"""Gate A: pure, bounded, unauthenticated synthetic provenance coherence.

An apparently consistent caller-created manifest NEVER establishes source
authenticity, binary trust, signer approval, a usable Python executable,
UID502 physical acceptance, or authorization to run on a host.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArtifactClaim:
    package_sha256: str
    manifest_sha256: str
    install_root: str
    layout: str
    python_version: tuple[int, int, int]
    platform: str
    arch: str
    approval_ref: str
    complete: bool


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    node_id: str
    relative_path: str
    kind: str
    digest_sha256: str


@dataclass(frozen=True, slots=True)
class PackageManifest:
    package_sha256: str
    entries: tuple[ManifestEntry, ...]


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    node_id: str
    path: str
    kind: str
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    acl_state: str
    digest_sha256: str
    writable_by_uid502: bool
    macho_arch: str
    python_abi: str
    python_major_minor: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    parent_id: str
    child_id: str
    loader_kind: str


@dataclass(frozen=True, slots=True)
class RuntimeClaim:
    binary_node_id: str
    sys_executable: str
    module_search_paths: tuple[str, ...]
    dyld_environment_clean: bool
    python_environment_clean: bool
    graph_complete: bool


@dataclass(frozen=True, slots=True)
class ProvenanceEvidence:
    artifact: ArtifactClaim
    manifest: PackageManifest
    runtime: RuntimeClaim
    nodes: tuple[ProvenanceNode, ...]
    edges: tuple[DependencyEdge, ...]


@dataclass(frozen=True, slots=True)
class ProvenanceResult:
    status: str
    violations: tuple[str, ...]


_DIRS = frozenset({"directory", "framework_bundle", "stdlib_dir"})
_MACHO = frozenset({"binary", "dylib", "framework_dylib", "extension"})
_FILES = _MACHO | {"stdlib_file"}
_KINDS = _DIRS | _FILES
_LOADS = frozenset({"contains", "macho_load", "python_import"})
_NA = "NOT_APPLICABLE"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_APPROVAL = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_REFUSAL = ProvenanceResult("PROVENANCE_REFUSED", ("EVIDENCE_INVALID",))


def _ascii(value: object, size: int, *, empty: bool = False) -> bool:
    return type(value) is str and (empty or 0 < len(value)) and len(value) <= size and value.isascii()


def _token(value: object, pattern: re.Pattern[str]) -> bool:
    # Never regex-match until exact built-in type and length are known.
    return _ascii(value, 64) and pattern.fullmatch(value) is not None


def _sha(value: object) -> bool:
    return _ascii(value, 64) and _DIGEST.fullmatch(value) is not None


def _absolute(value: object) -> bool:
    if not _ascii(value, 1024) or not value.startswith("/") or value == "/":
        return False
    return all(part not in ("", ".", "..") for part in value.split("/")[1:])


def _relative(value: object, *, root: bool) -> bool:
    if not _ascii(value, 1024, empty=root):
        return False
    if not value:
        return root
    return not value.startswith("/") and all(
        part not in ("", ".", "..") for part in value.split("/")
    )


def _version(values: object, expected: tuple[int, ...]) -> bool:
    return (
        type(values) is tuple
        and len(values) == len(expected)
        and all(type(x) is int for x in values)
        and values == expected
    )


def _outer_types(e: object) -> bool:
    if type(e) is not ProvenanceEvidence:
        return False
    if not (
        type(e.artifact) is ArtifactClaim
        and type(e.manifest) is PackageManifest
        and type(e.runtime) is RuntimeClaim
        and type(e.nodes) is tuple
        and type(e.edges) is tuple
        and type(e.manifest.entries) is tuple
        and type(e.runtime.module_search_paths) is tuple
    ):
        return False
    # Constant-time length gates BEFORE ANY traversal or serialization.
    if (
        not 1 <= len(e.nodes) <= 64
        or len(e.nodes) != len(e.manifest.entries)
        or not 1 <= len(e.manifest.entries) <= 64
        or len(e.edges) > 128
        or not 1 <= len(e.runtime.module_search_paths) <= 64
    ):
        return False
    return (
        all(type(n) is ProvenanceNode for n in e.nodes)
        and all(type(m) is ManifestEntry for m in e.manifest.entries)
        and all(type(edge) is DependencyEdge for edge in e.edges)
    )


def _typed(e: ProvenanceEvidence) -> bool:
    a, manifest, runtime = e.artifact, e.manifest, e.runtime
    if not (
        _sha(a.package_sha256)
        and _sha(a.manifest_sha256)
        and _sha(manifest.package_sha256)
        and _absolute(a.install_root)
        and _ascii(a.approval_ref, 64) and _APPROVAL.fullmatch(a.approval_ref) is not None
        and type(a.layout) is str and a.layout in ("standalone", "framework")
        and type(a.platform) is str and a.platform == "Darwin"
        and type(a.arch) is str and a.arch == "x86_64"
        and _version(a.python_version, (3, 13, 16))
        and type(a.complete) is bool and a.complete is True
        and _token(runtime.binary_node_id, _ID)
        and _absolute(runtime.sys_executable)
        and all(type(flag) is bool and flag is True for flag in (
            runtime.dyld_environment_clean, runtime.python_environment_clean,
            runtime.graph_complete,
        ))
    ):
        return False
    # Validate bounded strings/tuple arities before comparing, sorting or hashing.
    for path in runtime.module_search_paths:
        if not _absolute(path):
            return False
    for entry in manifest.entries:
        if not (
            _token(entry.node_id, _ID)
            and _relative(entry.relative_path, root=True)
            and type(entry.kind) is str and entry.kind in _KINDS
            and (_sha(entry.digest_sha256) or (
                entry.kind in _DIRS and type(entry.digest_sha256) is str
                and entry.digest_sha256 == _NA
            ))
        ):
            return False
    for n in e.nodes:
        if not (
            _token(n.node_id, _ID)
            and _absolute(n.path)
            and type(n.kind) is str and n.kind in _KINDS
            and all(type(x) is int and x >= 0 for x in (
                n.dev, n.ino, n.uid, n.gid, n.mode,
            ))
            and type(n.acl_state) is str and n.acl_state == "verified_safe"
            and (_sha(n.digest_sha256) or (
                n.kind in _DIRS and type(n.digest_sha256) is str
                and n.digest_sha256 == _NA
            ))
            and type(n.writable_by_uid502) is bool
            and type(n.macho_arch) is str
            and n.macho_arch in ("x86_64", _NA)
            and type(n.python_abi) is str
            and n.python_abi in ("cpython-313-darwin", _NA)
            and (
                n.python_major_minor is None
                or _version(n.python_major_minor, (3, 13))
            )
        ):
            return False
    for edge in e.edges:
        if not (
            _token(edge.parent_id, _ID)
            and _token(edge.child_id, _ID)
            and type(edge.loader_kind) is str and edge.loader_kind in _LOADS
        ):
            return False
    return True


def _valid_graph(e: ProvenanceEvidence) -> bool:
    a, manifest, runtime = e.artifact, e.manifest, e.runtime
    if manifest.package_sha256 != a.package_sha256:
        return False

    entries = manifest.entries
    # All strings are already primitive and bounded; sorting is now safe.
    if tuple(sorted(entries, key=lambda m: m.relative_path)) != entries:
        return False
    payload = {
        "schema_version": 1, "package_sha256": manifest.package_sha256,
        "entries": [
            {"node_id": m.node_id, "relative_path": m.relative_path,
             "kind": m.kind, "digest_sha256": m.digest_sha256}
            for m in entries
        ],
    }
    manifest_sha = hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if manifest_sha != a.manifest_sha256:
        return False

    members = {m.node_id: m for m in entries}
    nodes = {n.node_id: n for n in e.nodes}
    if len(members) != len(entries) or len(nodes) != len(e.nodes) or members.keys() != nodes.keys():
        return False
    paths = {n.path for n in e.nodes}
    if len(paths) != len(e.nodes):
        return False

    root = None
    role_counts = {kind: 0 for kind in _KINDS}
    bundle = None
    for node_id, n in nodes.items():
        m = members[node_id]
        if n.kind != m.kind or n.digest_sha256 != m.digest_sha256:
            return False
        if n.path != a.install_root + ("/" + m.relative_path if m.relative_path else ""):
            return False
        role_counts[n.kind] += 1
        if m.relative_path == "":
            if root is not None or n.kind != "directory":
                return False
            root = node_id
        if n.kind == "framework_bundle":
            bundle = n.path
        if (
            n.dev == 0 or n.ino == 0 or n.uid != 0 or n.gid != 0
            or n.mode & 0o022 or n.writable_by_uid502
            or n.mode & 0o170000 != (0o040000 if n.kind in _DIRS else 0o100000)
            or (n.kind in _DIRS and n.digest_sha256 != _NA)
            or (n.kind in _FILES and not _sha(n.digest_sha256))
            or (n.kind in _MACHO and n.macho_arch != "x86_64")
            or (n.kind not in _MACHO and n.macho_arch != _NA)
            or (n.kind == "extension" and (
                n.python_abi != "cpython-313-darwin"
                or not _version(n.python_major_minor, (3, 13))
            ))
            or (n.kind != "extension" and (
                n.python_abi != _NA or n.python_major_minor is not None
            ))
        ):
            return False
        if n.kind == "stdlib_file" and not n.path.endswith(".py"):
            return False
    if root is None or role_counts["binary"] != 1:
        return False
    if not role_counts["stdlib_dir"] or not role_counts["stdlib_file"]:
        return False
    if a.layout == "standalone":
        if role_counts["framework_bundle"] or role_counts["framework_dylib"]:
            return False
    elif role_counts["framework_bundle"] != 1 or not role_counts["framework_dylib"]:
        return False
    if (
        runtime.binary_node_id not in nodes
        or nodes[runtime.binary_node_id].kind != "binary"
        or nodes[runtime.binary_node_id].path != runtime.sys_executable
    ):
        return False
    stdlibs = {n.path for n in e.nodes if n.kind == "stdlib_dir"}
    search_paths = runtime.module_search_paths
    if len(search_paths) > len(stdlibs) or len(set(search_paths)) != len(search_paths):
        return False
    if not set(search_paths).issubset(stdlibs):
        return False
    for n in e.nodes:
        if n.kind == "stdlib_file" and not any(n.path.startswith(d + "/") for d in stdlibs):
            return False
        if n.kind == "framework_dylib" and (
            bundle is None or not n.path.startswith(bundle + "/")
        ):
            return False

    edge_keys = {(x.parent_id, x.child_id, x.loader_kind) for x in e.edges}
    if len(edge_keys) != len(e.edges):
        return False
    by_path = {n.path: n for n in e.nodes}
    links = {name: set() for name in nodes}
    for edge in e.edges:
        parent = nodes.get(edge.parent_id)
        child = nodes.get(edge.child_id)
        if parent is None or child is None or edge.parent_id == edge.child_id:
            return False
        if edge.loader_kind == "contains":
            if parent.kind not in _DIRS or child.path.rsplit("/", 1)[0] != parent.path:
                return False
        elif edge.loader_kind == "macho_load":
            if parent.kind not in _MACHO or child.kind not in {"dylib", "framework_dylib"}:
                return False
        elif edge.loader_kind == "python_import" and (
            parent.kind not in {"binary", "stdlib_file"}
            or child.kind not in {"stdlib_file", "extension"}
        ):
            return False
        links[edge.parent_id].add(edge.child_id)
    # Every non-root node must have an actual direct-parent contains edge.
    for n in e.nodes:
        if n.node_id == root:
            continue
        parent = by_path.get(n.path.rsplit("/", 1)[0])
        if parent is None or (parent.node_id, n.node_id, "contains") not in edge_keys:
            return False

    # DFS rejects cycles, disconnected roles and dangling dependency claims.
    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(item: str) -> bool:
        if item in visiting:
            return False
        if item in visited:
            return True
        visiting.add(item)
        for child in links[item]:
            if not walk(child):
                return False
        visiting.remove(item)
        visited.add(item)
        return True

    return walk(root) and len(visited) == len(nodes)


def assess_provenance(evidence: ProvenanceEvidence) -> ProvenanceResult:
    """Refuse by default. Positive means only coherent UNATTESTED claims."""
    if not _outer_types(evidence):
        return _REFUSAL
    if not _typed(evidence):
        return _REFUSAL
    if not _valid_graph(evidence):
        return _REFUSAL
    return ProvenanceResult("PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED", ())
