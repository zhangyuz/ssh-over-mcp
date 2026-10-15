"""Gate A: caller-supplied provenance COHERENCE, never host attestation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "ops/live-e2e/interpreter_provenance_contract.py"
ROOT = "/test-only/uid502-immutable-python"
PKG = "a" * 64
DIR = "NOT_APPLICABLE"


@pytest.fixture(scope="module")
def c():
    spec = importlib.util.spec_from_file_location("_gate_a_provenance_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


# Stable, pairwise unique fictional inode values; never derived from path length.
_FIXTURE_INODES = {
    "root": 101,
    "exe": 102,
    "lib": 103,
    "os": 104,
    "dyld": 105,
    "ext": 106,
    "frameparent": 107,
    "bundle": 108,
    "frameworklib": 109,
}


def _node(c, node_id, rel, kind, *, mode=None, arch=None, abi=DIR, py=None):
    directory = kind in ("directory", "framework_bundle", "stdlib_dir")
    return c.ProvenanceNode(
        node_id,
        ROOT + ("/" + rel if rel else ""),
        kind,
        1,
        _FIXTURE_INODES[node_id],
        0,
        0,
        (0o40755 if directory else 0o100755) if mode is None else mode,
        "verified_safe",
        DIR if directory else "b" * 64,
        False,
        DIR if directory or kind == "stdlib_file" else ("x86_64" if arch is None else arch),
        abi,
        py,
    )


def fixture(c, *, framework=False):
    nodes = [
        _node(c, "root", "", "directory"),
        _node(c, "exe", "python3.13", "binary"),
        _node(c, "lib", "lib", "stdlib_dir"),
        _node(c, "os", "lib/os.py", "stdlib_file"),
        _node(c, "dyld", "lib/helper.dylib", "dylib"),
        _node(c, "ext", "lib/ext.so", "extension", abi="cpython-313-darwin", py=(3, 13)),
    ]
    if framework:
        nodes += [
            _node(c, "frameparent", "Frameworks", "directory"),
            _node(c, "bundle", "Frameworks/Python.framework", "framework_bundle"),
            _node(c, "frameworklib", "Frameworks/Python.framework/Python", "framework_dylib"),
        ]
    edges = [
        c.DependencyEdge("root", "exe", "contains"),
        c.DependencyEdge("root", "lib", "contains"),
        c.DependencyEdge("lib", "os", "contains"),
        c.DependencyEdge("lib", "dyld", "contains"),
        c.DependencyEdge("lib", "ext", "contains"),
        c.DependencyEdge("exe", "dyld", "macho_load"),
        c.DependencyEdge("exe", "os", "python_import"),
        c.DependencyEdge("exe", "ext", "python_import"),
    ]
    if framework:
        edges += [
            c.DependencyEdge("root", "frameparent", "contains"),
            c.DependencyEdge("frameparent", "bundle", "contains"),
            c.DependencyEdge("bundle", "frameworklib", "contains"),
            c.DependencyEdge("exe", "frameworklib", "macho_load"),
        ]
    entries = tuple(
        sorted(
            (
                c.ManifestEntry(n.node_id, n.path[len(ROOT) :].lstrip("/"), n.kind, n.digest_sha256)
                for n in nodes
            ),
            key=lambda entry: entry.relative_path,
        )
    )
    manifest = c.PackageManifest(PKG, entries)
    payload = {
        "schema_version": 1,
        "package_sha256": PKG,
        "entries": [
            {
                "node_id": e.node_id,
                "relative_path": e.relative_path,
                "kind": e.kind,
                "digest_sha256": e.digest_sha256,
            }
            for e in entries
        ],
    }
    manifest_sha = hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    artifact = c.ArtifactClaim(
        PKG,
        manifest_sha,
        ROOT,
        "framework" if framework else "standalone",
        (3, 13, 16),
        "Darwin",
        "x86_64",
        "REVIEW.TEST",
        True,
    )
    runtime = c.RuntimeClaim("exe", ROOT + "/python3.13", (ROOT + "/lib",), True, True, True)
    return c.ProvenanceEvidence(artifact, manifest, runtime, tuple(nodes), tuple(edges))


def _status(c, e):
    return c.assess_provenance(e)


def _refuses(c, evidence):
    r = _status(c, evidence)
    assert r.status == "PROVENANCE_REFUSED"
    assert r.violations
    assert len(r.violations) <= 32
    assert all(type(x) is str and x == x.upper() for x in r.violations)


def _replace_node(e, target_id, **values):
    return replace(
        e, nodes=tuple(replace(n, **values) if n.node_id == target_id else n for n in e.nodes)
    )


def _replace_entry(e, target_id, **values):
    # Deliberately do NOT recompute the manifest checksum: discordance must refuse.
    return replace(
        e,
        manifest=replace(
            e.manifest,
            entries=tuple(
                replace(n, **values) if n.node_id == target_id else n for n in e.manifest.entries
            ),
        ),
    )


def test_standalone_fictional_schema_unattested(c):
    r = _status(c, fixture(c))
    assert r.status == "PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED"
    assert r.violations == ()
    assert r.__dataclass_params__.frozen
    assert not any(hasattr(r, key) for key in ("approved", "dispatch", "token", "execute"))


def test_framework_fictional_nested_schema_unattested(c):
    assert _status(c, fixture(c, framework=True)).status == (
        "PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED"
    )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("package_sha256", "c" * 64),
        ("manifest_sha256", "c" * 64),
        ("package_sha256", "Z" * 64),
        ("python_version", (3, 12, 16)),
        ("platform", "Linux"),
        ("arch", "arm64"),
        ("layout", "other"),
        ("approval_ref", "x" * 65),
        ("approval_ref", "x" * 2_000_000),
        ("approval_ref", "a b"),
        ("complete", False),
        ("install_root", "../unsafe"),
    ],
)
def test_package_and_budget_mutation_refuses(c, field, bad):
    e = fixture(c)
    _refuses(c, replace(e, artifact=replace(e.artifact, **{field: bad})))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("package_sha256", "c" * 64),
        ("entries", ()),
    ],
)
def test_manifest_changes_refuse(c, field, bad):
    e = fixture(c)
    _refuses(c, replace(e, manifest=replace(e.manifest, **{field: bad})))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("digest_sha256", "c" * 64),
        ("kind", "directory"),
        ("relative_path", "../other"),
        ("node_id", "not_the_original_id"),
    ],
)
def test_manifest_member_changes_refuse(c, field, bad):
    _refuses(c, _replace_entry(fixture(c), "dyld", **{field: bad}))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("uid", 501),
        ("gid", 80),
        ("mode", 0o100775),
        ("mode", 0o40755),
        ("acl_state", "unknown"),
        ("writable_by_uid502", True),
        ("digest_sha256", "c" * 64),
        ("path", ROOT + "/different"),
        ("macho_arch", "arm64"),
        ("kind", "stdlib_file"),
        ("node_id", "X" * 65),
    ],
)
def test_node_malformed_or_mutable_refuses(c, field, bad):
    _refuses(c, _replace_node(fixture(c), "dyld", **{field: bad}))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("macho_arch", "arm64"),
        ("python_abi", "cpython-312-darwin"),
        ("python_major_minor", (3, 12)),
        ("python_major_minor", (True, 13)),
    ],
)
def test_extension_abi_refuses(c, field, bad):
    _refuses(c, _replace_node(fixture(c), "ext", **{field: bad}))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("binary_node_id", "missing"),
        ("sys_executable", "/different/python"),
        ("module_search_paths", ()),
        ("module_search_paths", (ROOT + "/lib",) * 2),
        ("module_search_paths", (ROOT + "/lib",) * 65),
        ("module_search_paths", (ROOT + "/lib",) * 200000),
        ("module_search_paths", ("/tmp",)),
        ("dyld_environment_clean", False),
        ("python_environment_clean", False),
        ("graph_complete", False),
    ],
)
def test_runtime_input_budget_and_environment_refuse(c, field, bad):
    e = fixture(c)
    _refuses(c, replace(e, runtime=replace(e.runtime, **{field: bad})))


@pytest.mark.parametrize(
    "parent,child,kind",
    [
        ("root", "missing", "contains"),
        ("root", "exe", "unknown"),
        ("exe", "os", "macho_load"),
        ("lib", "exe", "contains"),
        ("exe", "root", "contains"),
    ],
)
def test_bad_graph_edges_refuse(c, parent, child, kind):
    e = fixture(c)
    e = replace(e, edges=(*e.edges, c.DependencyEdge(parent, child, kind)))
    _refuses(c, e)


def test_duplicate_edge_refuses(c):
    e = fixture(c)
    _refuses(c, replace(e, edges=(*e.edges, e.edges[0])))


def test_over_budget_edges_refuse(c):
    e = fixture(c)
    _refuses(c, replace(e, edges=e.edges * 17))


def test_framework_dylib_outside_bundle_refuses(c):
    e = fixture(c, framework=True)
    # Move dylib to root sibling, keeping role count and a root contains edge.
    e = _replace_node(e, "frameworklib", path=ROOT + "/freefloating")
    _refuses(c, e)


def test_claimed_real_group_writable_homebrew_ancestor_refuses(c):
    e = fixture(c)
    e = _replace_node(e, "lib", uid=501, gid=80, mode=0o40775)
    _refuses(c, e)


class Trap:
    def __init__(self, calls):
        self.calls = calls

    def __eq__(self, other):
        self.calls.append("eq")
        raise AssertionError("must not call untrusted equality")

    def __repr__(self):
        self.calls.append("repr")
        raise AssertionError("must not stringify untrusted object")


@pytest.mark.parametrize(
    "part,field",
    [
        ("artifact", "approval_ref"),
        ("artifact", "package_sha256"),
        ("manifest", "package_sha256"),
        ("runtime", "sys_executable"),
        ("runtime", "module_search_paths"),
    ],
)
def test_untrusted_comparison_never_invoked(c, part, field):
    calls = []
    e = fixture(c)
    broken = replace(getattr(e, part), **{field: Trap(calls)})
    _refuses(c, replace(e, **{part: broken}))
    assert calls == []


def test_trap_nested_manifest_node_and_edge(c):
    calls = []
    e = fixture(c)
    for modified in (
        replace(e, nodes=(*e.nodes[:1], replace(e.nodes[1], path=Trap(calls)), *e.nodes[2:])),
        replace(
            e,
            manifest=replace(
                e.manifest,
                entries=(
                    replace(e.manifest.entries[0], node_id=Trap(calls)),
                    *e.manifest.entries[1:],
                ),
            ),
        ),
        replace(e, edges=(replace(e.edges[0], loader_kind=Trap(calls)), *e.edges[1:])),
    ):
        _refuses(c, modified)
    assert calls == []


def test_malformed_outer_shape_refuses(c):
    for bad in (None, {"data": "SECRET_SENTINEL"}, "secret"):
        r = _status(c, bad)
        assert r.status == "PROVENANCE_REFUSED"
        assert "SECRET_SENTINEL" not in repr(r)


def test_no_host_side_effect_or_authority_surface(c):
    import ast

    tree = ast.parse(SOURCE.read_text())
    blocked = {"os", "subprocess", "socket", "urllib", "requests", "pathlib", "ctypes", "shutil"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(name.name.split(".")[0] not in blocked for name in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module and node.module.split(".")[0] not in blocked
    for export in ("dispatch", "execute", "approve", "main", "run", "PASS_CLEAN"):
        assert not hasattr(c, export)
    assert _status(c, fixture(c)).status.endswith("UNATTESTED")


def _rebind_fictional_claim(c, evidence):
    """Test-only recomputation: all attacker-controlled claims remain fabricated."""
    entries = tuple(
        sorted(
            (
                c.ManifestEntry(n.node_id, n.path[len(ROOT) :].lstrip("/"), n.kind, n.digest_sha256)
                for n in evidence.nodes
            ),
            key=lambda entry: entry.relative_path,
        )
    )
    manifest = c.PackageManifest(PKG, entries)
    payload = {
        "schema_version": 1,
        "package_sha256": PKG,
        "entries": [
            {
                "node_id": v.node_id,
                "relative_path": v.relative_path,
                "kind": v.kind,
                "digest_sha256": v.digest_sha256,
            }
            for v in entries
        ],
    }
    new_digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return replace(
        evidence, artifact=replace(evidence.artifact, manifest_sha256=new_digest), manifest=manifest
    )


def test_floating_framework_dylib_even_with_coherent_manifest_refuses(c):
    e = fixture(c, framework=True)
    # Every self-report is made coherent and reachability preserved.
    e = _replace_node(e, "frameworklib", path=ROOT + "/Frameworks/stray.dylib")
    e = replace(
        e,
        edges=tuple(
            replace(link, parent_id="frameparent")
            if link.parent_id == "bundle" and link.child_id == "frameworklib"
            else link
            for link in e.edges
        ),
    )
    e = _rebind_fictional_claim(c, e)
    _refuses(c, e)


def test_framework_valid_only_when_contains_chain_reaches_bundle(c):
    e = fixture(c, framework=True)
    _refuses(
        c,
        replace(
            e,
            edges=tuple(
                link
                for link in e.edges
                if not (link.parent_id == "bundle" and link.child_id == "frameworklib")
            ),
        ),
    )


def test_standalone_rejects_extra_framework_roles_even_if_manifest_coherent(c):
    e = fixture(c, framework=True)
    e = replace(e, artifact=replace(e.artifact, layout="standalone"))
    _refuses(c, e)


def test_forged_coherent_manifest_remains_unattested(c):
    e = fixture(c)
    # A hypothetical malicious caller may fabricate new digests in all
    # synthetic declarations. This cannot prove actual source authenticity.
    replacement = "f" * 64
    nodes = tuple(
        replace(n, digest_sha256=replacement) if n.node_id == "exe" else n for n in e.nodes
    )
    e = _rebind_fictional_claim(c, replace(e, nodes=nodes))
    result = _status(c, e)
    assert result.status == "PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED"
    assert not hasattr(result, "approved")


def test_over_budget_manifest_tuple_and_nodes_refuse_early(c):
    e = fixture(c)
    for invalid in (
        replace(e, manifest=replace(e.manifest, entries=e.manifest.entries * 12)),
        replace(e, nodes=e.nodes * 12),
    ):
        _refuses(c, invalid)


def test_positive_fixtures_claim_unique_device_inode_identities(c):
    # Synthetic aliases of one object cannot represent separate nodes.
    for framework in (False, True):
        e = fixture(c, framework=framework)
        identities = [(n.dev, n.ino) for n in e.nodes]
        assert len(identities) == len(set(identities))


def test_distinct_paths_same_device_inode_refuse_with_coherent_manifest(c):
    e = fixture(c)
    original = next(n for n in e.nodes if n.node_id == "root")
    e = _replace_node(e, "ext", dev=original.dev, ino=original.ino)
    # Node names, paths, package manifest, digest, role and topology are
    # intentionally unchanged and coherent; only alleged inode identity aliases.
    _refuses(c, e)


@pytest.mark.parametrize(
    ("node_id", "invalid_mode"),
    [
        ("exe", 0o100755 | (1 << 64)),
        ("lib", 0o40755 | (1 << 64)),
        ("exe", 0o100755 | (1 << 128)),
        ("exe", 0o100755 | (1 << 1000)),
    ],
)
def test_out_of_range_st_mode_refuses(c, node_id, invalid_mode):
    _refuses(c, _replace_node(fixture(c), node_id, mode=invalid_mode))


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("dev", 1 << 64),
        ("ino", 1 << 64),
        ("dev", 1 << 1000),
        ("ino", 1 << 1000),
    ],
)
def test_out_of_range_synthetic_device_inode_refuses(c, field, invalid_value):
    _refuses(c, _replace_node(fixture(c), "ext", **{field: invalid_value}))
