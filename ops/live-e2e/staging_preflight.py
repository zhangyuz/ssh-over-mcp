"""Dormant incident preflight building blocks; no CLI, capture, or workflow.

The private chain seam accepts disposable fixture components only in Slice A.
It is not an inspection entrypoint and confers no authority over incident roots.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType

_FAILURE = "staging preflight rejected"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class PreflightError(RuntimeError):
    """Sanitized preflight failure; no process ownership or retry authority."""

    def __init__(self, *, cleanup_uncertain: bool = False):
        if type(cleanup_uncertain) is not bool:
            raise TypeError(_FAILURE)
        super().__init__(_FAILURE)
        self._cleanup_uncertain = cleanup_uncertain

    @property
    def cleanup_uncertain(self) -> bool:
        return self._cleanup_uncertain


@dataclass(frozen=True, slots=True)
class _Incident:
    selector: str
    basename: str
    device: int
    inode: int
    expected_commit: str
    uid: int = 502
    mode: int = 0o700


_INCIDENTS = MappingProxyType(
    {
        "stale-target": _Incident(
            "stale-target",
            "ssh-over-mcp-e2e-i8ow1ni6",
            16777220,
            187176421,
            "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
        ),
        "older-target": _Incident(
            "older-target",
            "ssh-over-mcp-e2e-w_kn4rus",
            16777220,
            186877220,
            "bf84c7aafa5c79d629fc04488b5e0bda1cd98cef",
        ),
    }
)


def _select_incident(selector: str) -> _Incident:
    """Only the two approved incident bindings; no caller-selected path."""
    if type(selector) is not str or selector not in _INCIDENTS:
        raise PreflightError()
    return _INCIDENTS[selector]


@dataclass(frozen=True, slots=True)
class DirectoryMetadata:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int


def _metadata(info: os.stat_result) -> DirectoryMetadata:
    if not stat.S_ISDIR(info.st_mode):
        raise PreflightError()
    result = DirectoryMetadata(
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
    )
    if any(
        type(x) is not int
        for x in (result.device, result.inode, result.uid, result.gid, result.mode)
    ):
        raise PreflightError()
    return result


@dataclass(frozen=True, slots=True)
class _PinnedDirectoryChain:
    """Owns descriptors only from private fixture/pinned-parent composition."""

    _fds: tuple[int, ...]
    _parts: tuple[str, ...]
    _initial: tuple[DirectoryMetadata, ...]

    @property
    def metadata(self) -> tuple[DirectoryMetadata, ...]:
        return self._initial[1:]

    def revalidate(self) -> None:
        """Every original parent-to-child edge must still name the held object."""
        try:
            for fd, original in zip(self._fds, self._initial, strict=True):
                if _metadata(os.fstat(fd)) != original:
                    raise PreflightError()
            for index, name in enumerate(self._parts):
                now = os.stat(
                    name,
                    dir_fd=self._fds[index],
                    follow_symlinks=False,
                )
                if _metadata(now) != self._initial[index + 1]:
                    raise PreflightError()
        except (OSError, ValueError, TypeError, OverflowError, MemoryError):
            raise PreflightError() from None


def _verify_parts_and_policies(
    start_fd: int,
    parts: tuple[str, ...],
    rules: tuple[tuple[int, tuple[int, ...]], ...],
) -> None:
    if (
        type(start_fd) is not int
        or start_fd < 0
        or type(parts) is not tuple
        or type(rules) is not tuple
        or not parts
        or len(parts) != len(rules)
        or len(parts) > 16
    ):
        raise PreflightError()
    for name, rule in zip(parts, rules, strict=True):
        if (
            type(name) is not str
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or not name.isascii()
            or len(name) > 255
            or any(ord(char) < 33 or ord(char) > 126 for char in name)
            or type(rule) is not tuple
            or len(rule) != 2
        ):
            raise PreflightError()
        uid, modes = rule
        if (
            type(uid) is not int
            or uid < 0
            or (
                modes is not None
                and (
                    type(modes) is not tuple
                    or not modes
                    or any(
                        type(mode) is not int or mode < 0 or mode > 0o777 or mode & 0o022
                        for mode in modes
                    )
                )
            )
        ):
            raise PreflightError()


@contextmanager
def _pin_directory_chain(
    start_fd: int,
    parts: tuple[str, ...],
    rules: tuple[tuple[int, tuple[int, ...]], ...],
) -> Iterator[_PinnedDirectoryChain]:
    """Private, read-only fixture seam; never accepts user-selected incident paths.

    Duplicates the borrowed start FD; closes only descriptors opened by this
    helper. The caller must retain the context until final edge revalidation.
    """
    try:
        _verify_parts_and_policies(start_fd, parts, rules)
    except (OSError, ValueError, TypeError, OverflowError, MemoryError):
        raise PreflightError() from None
    owned: list[int] = []
    try:
        try:
            root = os.dup(start_fd)
            owned.append(root)
            snapshots = [_metadata(os.fstat(root))]
            for name, (uid, modes) in zip(parts, rules, strict=True):
                before = _metadata(os.stat(name, dir_fd=owned[-1], follow_symlinks=False))
                if before.uid != uid or (
                    before.mode & 0o022 if modes is None else before.mode not in modes
                ):
                    raise PreflightError()
                child = os.open(name, _DIR_FLAGS, dir_fd=owned[-1])
                owned.append(child)
                after = _metadata(os.fstat(child))
                if after != before:
                    raise PreflightError()
                snapshots.append(after)
            pinned = _PinnedDirectoryChain(tuple(owned), parts, tuple(snapshots))
        except (OSError, ValueError, TypeError, OverflowError, MemoryError):
            raise PreflightError() from None
        yield pinned
    finally:
        cleanup_uncertain = False
        for fd in reversed(owned):
            try:
                os.close(fd)
            except (OSError, ValueError, TypeError, OverflowError):
                cleanup_uncertain = True
        if cleanup_uncertain:
            raise PreflightError(cleanup_uncertain=True) from None


# These readers are private composition primitives. No caller-selected file path,
# process PID, checkout, workflow, or full-host inspection entrypoint is exposed.
import json
from typing import Any

_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_MARKER_TARGET = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"


@dataclass(frozen=True, slots=True)
class _RegularMetadata:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class _FileObservation:
    content: bytes
    metadata: _RegularMetadata


def _file_meta(
    info: os.stat_result, uid: int, mode: int | None, limit: int, device: int | None
) -> _RegularMetadata:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or (
            stat.S_IMODE(info.st_mode) != mode
            if mode is not None
            else bool(stat.S_IMODE(info.st_mode) & 0o022)
        )
        or info.st_nlink != 1
        or info.st_size < 0
        or info.st_size > limit
        or (device is not None and info.st_dev != device)
    ):
        raise PreflightError()
    values = (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    if any(type(value) is not int for value in values):
        raise PreflightError()
    return _RegularMetadata(*values)


def _read_named_regular(
    parent_fd: int, name: str, *, uid: int, mode: int | None, limit: int, device: int | None
) -> _FileObservation:
    """Read only a fixed, trusted literal leaf from a borrowed directory FD."""
    if (
        type(parent_fd) is not int
        or parent_fd < 0
        or type(name) is not str
        or name not in {"active-run.json", "expected_commit"}
        or type(uid) is not int
        or uid < 0
        or type(mode) not in (int, type(None))
        or type(limit) is not int
        or type(device) not in (int, type(None))
        or (name == "active-run.json" and (mode != 0o600 or limit != 4096 or device is not None))
        or (
            name == "expected_commit"
            and (mode is not None or limit != 41 or type(device) is not int)
        )
    ):
        raise PreflightError()
    fd = None
    uncertain = False
    try:
        before = _file_meta(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False), uid, mode, limit, device
        )
        fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
        after = _file_meta(os.fstat(fd), uid, mode, limit, device)
        if before != after:
            raise PreflightError()
        data = os.read(fd, limit + 1)
        last = _file_meta(os.fstat(fd), uid, mode, limit, device)
        if len(data) != before.size or len(data) > limit or last != before:
            raise PreflightError()
        result = _FileObservation(data, before)
    except (OSError, ValueError, TypeError, OverflowError, MemoryError):
        raise PreflightError() from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except (OSError, ValueError, TypeError, OverflowError):
                uncertain = True
        if uncertain:
            raise PreflightError(cleanup_uncertain=True) from None
    return result


def _parse_marker(raw: bytes) -> None:
    """No nested JSON and no duplicate or coerced keys, under 4096 bytes."""
    if type(raw) is not bytes or len(raw) > 4096:
        raise PreflightError()
    try:
        text = raw.decode("ascii")
        # Outside strings, the only brackets allowed are the single outer
        # object delimiters. Escapes and quotes are scanned before JSON decode.
        quoted = False
        escaped = False
        delimiters: list[tuple[str, int]] = []
        for position, char in enumerate(text):
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "{}[]":
                delimiters.append((char, position))
                if len(delimiters) > 2:
                    raise PreflightError()
        if quoted or escaped or delimiters != [("{", text.find("{")), ("}", text.rfind("}"))]:
            raise PreflightError()
        if text[: delimiters[0][1]].strip() or text[delimiters[1][1] + 1 :].strip():
            raise PreflightError()

        def pairs(value: list[tuple[str, Any]]) -> dict[str, Any]:
            if len(value) != 2 or len({key for key, _ in value}) != 2:
                raise PreflightError()
            return dict(value)

        def integer(value: str) -> int:
            if len(value) > 10:
                raise PreflightError()
            return int(value)

        def invalid(_value: str) -> None:
            raise PreflightError()

        obj = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=invalid,
            parse_constant=invalid,
        )
        if (
            type(obj) is not dict
            or set(obj) != {"target", "owner_pid"}
            or type(obj["target"]) is not str
            or obj["target"] != _MARKER_TARGET
            or type(obj["owner_pid"]) is not int
            or obj["owner_pid"] != 38013
        ):
            raise PreflightError()
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError, MemoryError):
        raise PreflightError() from None


def _read_marker(cache_fd: int, *, uid: int) -> _FileObservation:
    original = _read_named_regular(
        cache_fd, "active-run.json", uid=uid, mode=0o600, limit=4096, device=None
    )
    _parse_marker(original.content)
    return original


def _revalidate_marker(cache_fd: int, original: _FileObservation, *, uid: int) -> None:
    if type(original) is not _FileObservation:
        raise PreflightError()
    observed = _read_marker(cache_fd, uid=uid)
    if observed != original:
        raise PreflightError()


@dataclass(frozen=True, slots=True)
class _ExpectedCommitObservation:
    first: _FileObservation
    _payload_chain: _PinnedDirectoryChain

    def revalidate(self, expected_sha: str, *, uid: int) -> None:
        if (
            type(expected_sha) is not str
            or len(expected_sha) != 40
            or any(c not in "0123456789abcdef" for c in expected_sha)
            or type(uid) is not int
        ):
            raise PreflightError()
        original = self.first
        current = _read_named_regular(
            self._payload_chain._fds[-1],
            "expected_commit",
            uid=uid,
            mode=None,
            limit=41,
            device=original.metadata.device,
        )
        if current != original or current.content != (expected_sha + "\n").encode("ascii"):
            raise PreflightError()
        # Reading via the held FD cannot establish that its directory entry
        # still names the same object. Verify the leaf edge *after* the read.
        try:
            live_leaf = os.stat(
                "expected_commit",
                dir_fd=self._payload_chain._fds[-1],
                follow_symlinks=False,
            )
            if _file_meta(live_leaf, uid, None, 41, original.metadata.device) != original.metadata:
                raise PreflightError()
        except (OSError, ValueError, TypeError, OverflowError, MemoryError):
            raise PreflightError() from None
        # The root->payload edge may also have changed during the read.
        self._payload_chain.revalidate()


@contextmanager
def _pin_expected_commit(
    root_fd: int, expected_sha: str, *, uid: int, device: int
) -> Iterator[_ExpectedCommitObservation]:
    """Private disposable fixture seam; real catalog/UID supplied later internally."""
    if (
        type(expected_sha) is not str
        or len(expected_sha) != 40
        or any(c not in "0123456789abcdef" for c in expected_sha)
        or type(uid) is not int
        or type(device) is not int
    ):
        raise PreflightError()
    with _pin_directory_chain(
        root_fd, ("payload-content",), ((uid, (0o700, 0o750, 0o755)),)
    ) as chain:
        if chain.metadata[-1].device != device:
            raise PreflightError()
        first = _read_named_regular(
            chain._fds[-1], "expected_commit", uid=uid, mode=None, limit=41, device=device
        )
        if first.content != (expected_sha + "\n").encode("ascii"):
            raise PreflightError()
        yield _ExpectedCommitObservation(first, chain)


def _require_expected_inventory_entry(entry: object, observation: _FileObservation) -> None:
    """Validate the collector's detached leaf metadata against the content read."""
    if (
        getattr(entry, "path", None) != "payload-content/expected_commit"
        or getattr(entry, "kind", None) != "regular"
        or not isinstance(observation, _FileObservation)
    ):
        raise PreflightError()
    meta = observation.metadata
    fields = ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")
    if any(
        type(getattr(entry, key, None)) is not int or getattr(entry, key) != getattr(meta, key)
        for key in fields
    ):
        raise PreflightError()


def _collect_and_bind(root_fd: int, pinned: _ExpectedCommitObservation, *, uid: int) -> tuple:
    """Collect only actual detached inventory from held root and bind leaf.

    This private fixture seam is not a fixed-host inspection entrypoint:
    the final caller must prove the root's literal UID/device/inode first.
    """
    if (
        type(root_fd) is not int
        or root_fd < 0
        or type(uid) is not int
        or type(pinned) is not _ExpectedCommitObservation
    ):
        raise PreflightError()
    try:
        staging_inventory = _fixed_inventory_module()
        original = _metadata(os.fstat(root_fd))
        if original.uid != uid or original.mode != 0o700:
            raise PreflightError()
        entries = staging_inventory.collect_staging_inventory(root_fd, uid=uid)
        if _metadata(os.fstat(root_fd)) != original or type(entries) is not tuple:
            raise PreflightError()
        roots = [item for item in entries if item.path == "."]
        leaves = [item for item in entries if item.path == "payload-content/expected_commit"]
        if len(roots) != 1 or len(leaves) != 1:
            raise PreflightError()
        root = roots[0]
        if root.kind != "directory" or any(
            getattr(root, key) != getattr(original, key)
            for key in ("device", "inode", "uid", "gid", "mode")
        ):
            raise PreflightError()
        _require_expected_inventory_entry(leaves[0], pinned.first)
        pinned._payload_chain.revalidate()
        return entries
    except PreflightError:
        # Pre-sanitized failures carry the known child/FD cleanup state.
        # Never turn cleanup_uncertain=True into a default False here.
        raise
    except (
        ImportError,
        SyntaxError,
        OSError,
        ValueError,
        TypeError,
        OverflowError,
        AttributeError,
        RuntimeError,
        MemoryError,
        KeyError,
        IndexError,
    ):
        raise PreflightError() from None


# One deterministic trusted sibling module provides stable InventoryEntry
# identity for repeated detached observations. Never import via sys.path.
_FIXED_INVENTORY_MODULE = None


def _fixed_inventory_module():
    global _FIXED_INVENTORY_MODULE
    if _FIXED_INVENTORY_MODULE is not None:
        return _FIXED_INVENTORY_MODULE

    import importlib.util
    import sys

    sibling = os.path.join(os.path.dirname(__file__), "staging_inventory.py")
    module_name = "_ssh_over_mcp_fixed_staging_inventory"
    spec = importlib.util.spec_from_file_location(module_name, sibling)
    if spec is None or spec.loader is None:
        raise PreflightError()
    module = importlib.util.module_from_spec(spec)
    sentinel = object()
    former = sys.modules.get(module_name, sentinel)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if former is sentinel:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = former
    _FIXED_INVENTORY_MODULE = module
    return module


# Literal runner marker-cache path *relative to a separately pinned "/" FD*.
# A complete trusted root-FD provenance and UID-502 call path are deferred.
_CACHE_PARTS = (
    "Users",
    "gha-e2e-orchestrator",
    "Library",
    "Caches",
    "ssh-over-mcp-e2e",
)
_CACHE_SYSTEM_UID = 0
_CACHE_ACCOUNT_UID = 502


@contextmanager
def _pin_fixed_cache_chain(root_fd: int) -> Iterator[_PinnedDirectoryChain]:
    """Dormant fixed-name cache ancestry with no content reads.

    root_fd is a borrowed descriptor. This is not a complete production
    entrypoint or proof that an arbitrary supplied FD represents literal "/".
    Only disposable tests substitute the fixed owner globals.
    """
    if type(root_fd) is not int or root_fd < 0:
        raise PreflightError()
    try:
        root_meta = _metadata(os.fstat(root_fd))
        if root_meta.uid != _CACHE_SYSTEM_UID or root_meta.mode & 0o022:
            raise PreflightError()
    except (OSError, ValueError, TypeError, OverflowError, MemoryError):
        raise PreflightError() from None

    # None means every owner/group/world mode is allowed *except*
    # group/world writable bits. The final cache has exact 0700 policy.
    rules = (
        (_CACHE_SYSTEM_UID, None),
        (_CACHE_ACCOUNT_UID, None),
        (_CACHE_ACCOUNT_UID, None),
        (_CACHE_ACCOUNT_UID, None),
        (_CACHE_ACCOUNT_UID, (0o700,)),
    )
    with _pin_directory_chain(root_fd, _CACHE_PARTS, rules) as chain:
        chain.revalidate()
        yield chain
