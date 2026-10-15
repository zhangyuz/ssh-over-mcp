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


def _node(c, node_id, rel, kind, *, mode=None, arch=None, abi=DIR, py=None):
    directory = kind in ("directory", "framework_bundle", "stdlib_dir")
    return c.ProvenanceNode(
        node_id, ROOT + ("/" + rel if rel else ""), kind,
        1, 100 + len(rel), 0, 0,
        (0o40755 if directory else 0o100755) if mode is None else mode,
        "verified_safe", DIR if directory else "b" * 64, False,
        DIR if directory or kind == "stdlib_file" else ("x86_64" if arch is None else arch),
        abi, py,
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
    entries = tuple(sorted(
        (c.ManifestEntry(n.node_id, n.path[len(ROOT):].lstrip("/"),
                         n.kind, n.digest_sha256) for n in nodes),
        key=lambda entry: entry.relative_path,
    ))
    manifest = c.PackageManifest(PKG, entries)
    payload = {
        "schema_version": 1, "package_sha256": PKG,
        "entries": [
            {"node_id": e.node_id, "relative_path": e.relative_path,
             "kind": e.kind, "digest_sha256": e.digest_sha256}
            for e in entries
        ],
    }
    manifest_sha = hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    artifact = c.ArtifactClaim(PKG, manifest_sha, ROOT,
                               "framework" if framework else "standalone",
                               (3, 13, 16), "Darwin", "x86_64", "REVIEW.TEST", True)
    runtime = c.RuntimeClaim("exe", ROOT + "/python3.13", (ROOT + "/lib",),
                             True, True, True)
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
    return replace(e, nodes=tuple(
        replace(n, **values) if n.node_id == target_id else n for n in e.nodes
    ))


def _replace_entry(e, target_id, **values):
    # Deliberately do NOT recompute the manifest checksum: discordance must refuse.
    return replace(e, manifest=replace(e.manifest, entries=tuple(
        replace(n, **values) if n.node_id == target_id else n
        for n in e.manifest.entries
    )))


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


@pytest.mark.parametrize("field,bad", [
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
])
def test_package_and_budget_mutation_refuses(c, field, bad):
    e = fixture(c)
    _refuses(c, replace(e, artifact=replace(e.artifact, **{field: bad})))


@pytest.mark.parametrize("field,bad", [
    ("package_sha256", "c" * 64),
    ("entries", ()),
])
def test_manifest_changes_refuse(c, field, bad):
    e = fixture(c)
    _refuses(c, replace(e, manifest=replace(e.manifest, **{field: bad})))


@pytest.mark.parametrize("field,bad", [
    ("digest_sha256", "c" * 64),
    ("kind", "directory"),
    ("relative_path", "../other"),
    ("node_id", "not_the_original_id"),
])
def test_manifest_member_changes_refuse(c, field, bad):
    _refuses(c, _replace_entry(fixture(c), "dyld", **{field: bad}))


@pytest.mark.parametrize("field,bad", [
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
])
def test_node_malformed_or_mutable_refuses(c, field, bad):
    _refuses(c, _replace_node(fixture(c), "dyld", **{field: bad}))


@pytest.mark.parametrize("field,bad", [
    ("macho_arch", "arm64"),
    ("python_abi", "cpython-312-darwin"),
    ("python_major_minor", (3, 12)),
    ("python_major_minor", (True, 13)),
])
def test_extension_abi_refuses(c, field, bad):
    _refuses(c, _replace_node(fixture(c), "ext", **{field: bad}))


@pytest.mark.parametrize("field,bad", [
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
])
def test_runtime_input_budget_and_environment_refuse(c, field, bad):
    e = fixture(c)
    _refuses(c, replace(e, runtime=replace(e.runtime, **{field: bad})))


@pytest.mark.parametrize("parent,child,kind", [
    ("root", "missing", "contains"),
    ("root", "exe", "unknown"),
    ("exe", "os", "macho_load"),
    ("lib", "exe", "contains"),
    ("exe", "root", "contains"),
])
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


@pytest.mark.parametrize("part,field", [
    ("artifact", "approval_ref"),
    ("artifact", "package_sha256"),
    ("manifest", "package_sha256"),
    ("runtime", "sys_executable"),
    ("runtime", "module_search_paths"),
])
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
        replace(e, manifest=replace(e.manifest, entries=(
            replace(e.manifest.entries[0], node_id=Trap(calls)), *e.manifest.entries[1:]
        ))),
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
