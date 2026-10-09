"""Dormant incident preflight building blocks; no CLI or workflow.

The private chain seam accepts disposable fixture components only in Slice A.
The fixed one-snapshot adapter delegates to the separately reviewed diagnostic
capture and a literal signal-zero presence leaf. Neither is an operational
incident-inspection entrypoint nor grants cleanup authority.
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
    rules: tuple[tuple[int, tuple[int, ...] | None], ...],
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
    rules: tuple[tuple[int, tuple[int, ...] | None], ...],
    *,
    post_close_validate: bool = False,
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
        edge_invalid = False
        # Every owned FD receives one close attempt, even when another
        # close is ambiguous or interrupted. Never retry a possibly closed FD.
        for index in range(len(owned) - 1, -1, -1):
            fd = owned[index]
            try:
                os.close(fd)
            except (
                OSError,
                ValueError,
                TypeError,
                OverflowError,
                MemoryError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
                cleanup_uncertain = True
            if post_close_validate and index > 0:
                if index >= len(snapshots):
                    # A post-open metadata failure may leave an owned FD but
                    # no completed snapshot; never abort the remaining closes.
                    edge_invalid = True
                    continue
                # A no-follow SINGLE edge check after each child close,
                # anchored to its still-held parent (never a slash path).
                try:
                    if (
                        _metadata(
                            os.stat(
                                parts[index - 1],
                                dir_fd=owned[index - 1],
                                follow_symlinks=False,
                            )
                        )
                        != snapshots[index]
                    ):
                        edge_invalid = True
                except (
                    PreflightError,
                    OSError,
                    ValueError,
                    TypeError,
                    OverflowError,
                    MemoryError,
                    KeyboardInterrupt,
                    SystemExit,
                    GeneratorExit,
                ):
                    edge_invalid = True
        if cleanup_uncertain:
            raise PreflightError(cleanup_uncertain=True) from None
        if edge_invalid:
            raise PreflightError() from None


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
            except (
                OSError,
                ValueError,
                TypeError,
                OverflowError,
                MemoryError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
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
        try:
            entries = staging_inventory.collect_staging_inventory(root_fd, uid=uid)
        except staging_inventory.InventoryError as failure:
            # Preserve the collector's strictly typed owned-descriptor cleanup
            # status. Unknown/forged types cannot assert settled cleanup.
            try:
                uncertain = failure.cleanup_uncertain
            except (AttributeError, RuntimeError, TypeError, ValueError, OSError, MemoryError):
                # Even an unreadable internal status cannot prove cleanup.
                uncertain = True
            if type(uncertain) is not bool:
                uncertain = True
            raise PreflightError(cleanup_uncertain=uncertain) from None
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
def _pin_safe_directory_chain(
    root_fd: int,
    parts: tuple[str, ...],
    rules: tuple[tuple[int, tuple[int, ...] | None], ...],
    *,
    system_uid: int,
    root_mode: int | None = None,
    post_close_validate: bool = False,
) -> Iterator[_PinnedDirectoryChain]:
    """Private shared safe-baseline check for the fixed namespace wrappers."""
    if type(root_fd) is not int or root_fd < 0:
        raise PreflightError()
    try:
        root_meta = _metadata(os.fstat(root_fd))
        if (
            root_meta.uid != system_uid
            or root_meta.mode & 0o022
            or (root_mode is not None and root_meta.mode != root_mode)
        ):
            raise PreflightError()
    except (OSError, ValueError, TypeError, OverflowError, MemoryError):
        raise PreflightError() from None

    with _pin_directory_chain(
        root_fd, parts, rules, post_close_validate=post_close_validate
    ) as chain:
        # The caller's preliminary borrowed-FD check cannot authorize the
        # newly duplicated root: its metadata may change between fstat/dup.
        # Bind both the duplicated FD and its immutable baseline to the
        # *already safe* borrowed-root snapshot. Consequently, later
        # chain.revalidate() also checks the root against a safe baseline.
        try:
            pinned_root = _metadata(os.fstat(chain._fds[0]))
            if (
                pinned_root != root_meta
                or chain._initial[0] != root_meta
                or pinned_root.uid != system_uid
                or pinned_root.mode & 0o022
                or (root_mode is not None and pinned_root.mode != root_mode)
            ):
                raise PreflightError()
        except (OSError, ValueError, TypeError, OverflowError, MemoryError):
            raise PreflightError() from None
        chain.revalidate()
        yield chain


@contextmanager
def _pin_fixed_cache_chain(
    root_fd: int, *, post_close_validate: bool = False
) -> Iterator[_PinnedDirectoryChain]:
    """Dormant fixed-name cache ancestry; borrowed FD does not prove literal /."""
    # None permits safe permission modes; the cache leaf requires exact 0700.
    rules = (
        (_CACHE_SYSTEM_UID, None),
        (_CACHE_ACCOUNT_UID, None),
        (_CACHE_ACCOUNT_UID, None),
        (_CACHE_ACCOUNT_UID, None),
        (_CACHE_ACCOUNT_UID, (0o700,)),
    )
    with _pin_safe_directory_chain(
        root_fd,
        _CACHE_PARTS,
        rules,
        system_uid=_CACHE_SYSTEM_UID,
        post_close_validate=post_close_validate,
    ) as chain:
        yield chain


_TEMP_SYSTEM_UID = 0
_TEMP_ACCOUNT_UID = 502
_TEMP_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


@contextmanager
def _pin_fixed_temp_chain(
    root_fd: int, components: tuple[str, str], *, post_close_validate: bool = False
) -> Iterator[_PinnedDirectoryChain]:
    """Private component seam, not OS derivation or a production entrypoint.

    Slice B must derive shard/token from its fixed, completed getconf capture.
    Slice A uses only disposable fixtures and never accepts a full input path.
    """
    if type(components) is not tuple or len(components) != 2:
        raise PreflightError()
    shard, token = components
    if (
        type(shard) is not str
        or len(shard) != 2
        or any(char not in _TEMP_ALNUM for char in shard)
        or type(token) is not str
        or not 1 <= len(token) <= 255
        or any(char not in _TEMP_ALNUM + "_" for char in token)
    ):
        raise PreflightError()
    parts = ("private", "var", "folders", shard, token, "T")
    rules = (
        (_TEMP_SYSTEM_UID, None),
        (_TEMP_SYSTEM_UID, None),
        (_TEMP_SYSTEM_UID, None),
        (_TEMP_SYSTEM_UID, None),
        (_TEMP_ACCOUNT_UID, (0o700, 0o755)),
        (_TEMP_ACCOUNT_UID, (0o700,)),
    )
    with _pin_safe_directory_chain(
        root_fd,
        parts,
        rules,
        system_uid=_TEMP_SYSTEM_UID,
        post_close_validate=post_close_validate,
    ) as chain:
        yield chain


@contextmanager
def _pin_fixed_incident_root(temp_fd: int, selector: str) -> Iterator[_PinnedDirectoryChain]:
    """Private selected-root seam; borrowed T does not prove its OS ancestry.

    Later composition must retain the full temp chain and revalidate all its
    edges together with this selected edge after final observations.
    """
    incident = _select_incident(selector)
    with _pin_safe_directory_chain(
        temp_fd,
        (incident.basename,),
        ((incident.uid, (incident.mode,)),),
        system_uid=incident.uid,
        root_mode=0o700,
    ) as chain:
        selected = chain.metadata[0]
        if (selected.device, selected.inode, selected.uid, selected.mode) != (
            incident.device,
            incident.inode,
            incident.uid,
            incident.mode,
        ):
            raise PreflightError()
        yield chain


@dataclass(frozen=True, slots=True)
class _SelectedInventoryEvidence:
    """Detached staging-only fixture evidence, not an operational preflight."""

    selector: str
    basename: str
    device: int
    inode: int
    uid: int
    mode: int
    expected_commit: str
    expected_metadata: _RegularMetadata
    inventory: tuple


def _observe_selected_inventory(
    selected_chain: _PinnedDirectoryChain, selector: str
) -> _SelectedInventoryEvidence:
    """Private Slice A composition on an already-pinned selected-root chain.

    Neither the supplied chain nor this result authenticates the host's
    full temp ancestry, dedicated UID-502 context, or the fixed cache marker.
    This must never be used as a production preflight/receipt entrypoint.
    """
    incident = _select_incident(selector)
    if (
        type(selected_chain) is not _PinnedDirectoryChain
        or incident.selector != selector
        or selected_chain._parts != (incident.basename,)
        or len(selected_chain.metadata) != 1
        or len(selected_chain._fds) != 2
    ):
        raise PreflightError()
    observed_root = selected_chain.metadata[0]
    if (
        observed_root.device,
        observed_root.inode,
        observed_root.uid,
        observed_root.mode,
    ) != (incident.device, incident.inode, incident.uid, incident.mode):
        raise PreflightError()
    try:
        # Verify the T-to-root edge before observing the fixed payload leaf.
        selected_chain.revalidate()
        with _pin_expected_commit(
            selected_chain._fds[-1],
            incident.expected_commit,
            uid=incident.uid,
            device=incident.device,
        ) as expected:
            entries = _collect_and_bind(selected_chain._fds[-1], expected, uid=incident.uid)
            # An inventory from an actual fixed collector consists only of
            # frozen records. No borrowed descriptors or raw file bytes escape.
            inventory_type = _fixed_inventory_module().InventoryEntry
            if type(entries) is not tuple or any(
                type(entry) is not inventory_type for entry in entries
            ):
                raise PreflightError()
            expected.revalidate(incident.expected_commit, uid=incident.uid)
            # A valid held root FD alone cannot prove the live root name
            # still resolves to the same object after inventory/read.
            selected_chain.revalidate()
            evidence = _SelectedInventoryEvidence(
                selector=incident.selector,
                basename=incident.basename,
                device=incident.device,
                inode=incident.inode,
                uid=incident.uid,
                mode=incident.mode,
                expected_commit=incident.expected_commit,
                expected_metadata=expected.first.metadata,
                inventory=entries,
            )
        # Nested payload FD cleanup is itself a race boundary: the selected
        # name may change after the last content read but before return.
        selected_chain.revalidate()
        return evidence
    except PreflightError:
        # Keep the strictly typed cleanup_uncertain status if any owned
        # descriptor closure failed in a nested observer.
        raise
    except (
        ImportError,
        SyntaxError,
        OSError,
        TypeError,
        ValueError,
        OverflowError,
        AttributeError,
        MemoryError,
        RuntimeError,
        KeyError,
        IndexError,
    ):
        raise PreflightError() from None


@dataclass(frozen=True, slots=True)
class _MarkerStagingEvidence:
    """Detached fixture-only marker/staging pair; not a full preflight."""

    marker_target: str
    marker_owner_pid: int
    marker_metadata: _RegularMetadata
    selected: _SelectedInventoryEvidence


def _observe_marker_staging(
    cache_chain: _PinnedDirectoryChain,
    selected_chain: _PinnedDirectoryChain,
    selector: str,
) -> _MarkerStagingEvidence:
    """Observe fixed marker plus staging without OS provenance or process capture.

    The caller must hold and independently validate the complete original
    cache/temp ancestry. No arbitrary file name, PID, uid or captured data is
    accepted. This is a private disposable composition seam, not live UID-502
    preflight evidence and it does not authorize any recovery action.
    """
    try:
        incident = _select_incident(selector)
        if (
            type(cache_chain) is not _PinnedDirectoryChain
            or cache_chain._parts != _CACHE_PARTS
            or len(cache_chain.metadata) != len(_CACHE_PARTS)
            or type(selected_chain) is not _PinnedDirectoryChain
            or selected_chain._parts != (incident.basename,)
            or len(selected_chain.metadata) != 1
            or len(selected_chain._fds) != 2
        ):
            raise PreflightError()
        last = cache_chain.metadata[-1]
        if last.uid != _CACHE_ACCOUNT_UID or last.mode != 0o700:
            raise PreflightError()
        cache_chain.revalidate()
        selected_chain.revalidate()
        marker = _read_marker(cache_chain._fds[-1], uid=_CACHE_ACCOUNT_UID)
        staging = _observe_selected_inventory(selected_chain, selector)
        _revalidate_marker(cache_chain._fds[-1], marker, uid=_CACHE_ACCOUNT_UID)
        # Both name chains must still refer to their originally held objects
        # after the marker reread and nested selected-inventory FD cleanup.
        cache_chain.revalidate()
        selected_chain.revalidate()
        return _MarkerStagingEvidence(
            marker_target=_MARKER_TARGET,
            marker_owner_pid=38013,
            marker_metadata=marker.metadata,
            selected=staging,
        )
    except PreflightError:
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


# Dormant one-snapshot adapter. The complete incident inspection sequence,
# trusted-main caller, namespace provenance and receipt remain separate gates.
_FIXED_DIAGNOSTICS_MODULE = None
_FIXED_PROCESS_METADATA_MODULE = None
_FIXED_OWNER_PROBE_MODULE = None


def _load_fixed_process_sibling(filename: str, module_name: str):
    """Load only three fixed local components, never caller-selected paths."""
    if (filename, module_name) not in {
        ("staging_diagnostics.py", "_ssh_over_mcp_fixed_staging_diagnostics"),
        ("staging_process_metadata.py", "_ssh_over_mcp_fixed_process_metadata"),
        ("staging_owner_probe.py", "_ssh_over_mcp_fixed_staging_owner_probe"),
    }:
        raise PreflightError()
    import importlib.util
    import sys

    sibling = os.path.join(os.path.dirname(__file__), filename)
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
    return module


def _fixed_diagnostics_module():
    global _FIXED_DIAGNOSTICS_MODULE
    if _FIXED_DIAGNOSTICS_MODULE is None:
        _FIXED_DIAGNOSTICS_MODULE = _load_fixed_process_sibling(
            "staging_diagnostics.py", "_ssh_over_mcp_fixed_staging_diagnostics"
        )
    return _FIXED_DIAGNOSTICS_MODULE


def _fixed_process_metadata_module():
    global _FIXED_PROCESS_METADATA_MODULE
    if _FIXED_PROCESS_METADATA_MODULE is None:
        _FIXED_PROCESS_METADATA_MODULE = _load_fixed_process_sibling(
            "staging_process_metadata.py", "_ssh_over_mcp_fixed_process_metadata"
        )
    return _FIXED_PROCESS_METADATA_MODULE


def _fixed_owner_probe_module():
    global _FIXED_OWNER_PROBE_MODULE
    if _FIXED_OWNER_PROBE_MODULE is None:
        _FIXED_OWNER_PROBE_MODULE = _load_fixed_process_sibling(
            "staging_owner_probe.py", "_ssh_over_mcp_fixed_staging_owner_probe"
        )
    return _FIXED_OWNER_PROBE_MODULE


def _require_fixed_marker_owner_absent() -> None:
    """Delegate the strictly fixed signal-zero operation to its isolated leaf."""
    _fixed_owner_probe_module().require_owner_absent()


def _observe_fixed_process_snapshot() -> None:
    """Validate one fresh fixed ps capture, never return process or child data.

    The real capture performs its own UID-502, Darwin, authority-digest and
    exclusive-owned-child checks. A future full preflight must call this twice,
    independently, on opposite sides of inventory and alongside held paths.
    """
    try:
        diagnostics = _fixed_diagnostics_module()
        metadata = _fixed_process_metadata_module()
        try:
            capture = diagnostics.capture_ps()
        except diagnostics.DiagnosticError as failure:
            try:
                uncertain = failure.cleanup_uncertain
            except (
                AttributeError,
                RuntimeError,
                TypeError,
                ValueError,
                OSError,
                MemoryError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
                uncertain = True
            if type(uncertain) is not bool:
                uncertain = True
            raise PreflightError(cleanup_uncertain=uncertain) from None
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
            # A non-contract error after capture starts cannot prove that an
            # owned diagnostic child or descriptor cleanup was settled.
            raise PreflightError(cleanup_uncertain=True) from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            # Cancellation after an attempted diagnostic capture cannot
            # establish the disposition of its owned child or descriptors.
            raise PreflightError(cleanup_uncertain=True) from None
        if (
            type(capture) is not diagnostics.DiagnosticCapture
            or capture.kind != "ps"
            or type(capture.stdout) is not bytes
            or type(capture.child_pid) is not int
        ):
            # A malformed return is not proof of fully reaped/closed capture.
            raise PreflightError(cleanup_uncertain=True)
        rows = metadata._parse_process_rows(capture.stdout)
        metadata._require_snapshot(rows, inspection_pid=os.getpid(), own_ps_pid=capture.child_pid)
        # ps -U 502 alone cannot establish owner death. Reject that PID
        # independently of command classification, then signal-zero-probe it.
        if any(type(row) is not metadata.ProcessRow or row.pid == 38013 for row in rows):
            raise PreflightError()
        _require_fixed_marker_owner_absent()
    except PreflightError:
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


def _observe_fixed_temp_parent():
    """Get one native-derived temp parent without granting path or staging access.

    The strict trusted-checkout authority check occurs *before* any diagnostic
    capture invocation. The real fixed child implementation independently
    repeats its UID-502/authority checks before spawn, using its reviewed
    owned-child cleanup lifecycle. No environment or caller path is consulted.
    """
    try:
        diagnostics = _fixed_diagnostics_module()
        metadata = _fixed_process_metadata_module()
        diagnostics._require_identity()
        diagnostics._require_wait_context()
        try:
            diagnostics._verify_authority()
        except diagnostics.DiagnosticError as failure:
            # A failed trusted-checkout check happens before child capture,
            # but its owned document/ancestor descriptor closes can be unsure.
            try:
                uncertain = failure.cleanup_uncertain
            except (
                OSError,
                RuntimeError,
                ValueError,
                TypeError,
                AttributeError,
                OverflowError,
                MemoryError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
                uncertain = True
            if type(uncertain) is not bool:
                uncertain = True
            raise PreflightError(cleanup_uncertain=uncertain) from None
        try:
            capture = diagnostics.capture_getconf()
        except diagnostics.DiagnosticError as failure:
            try:
                uncertain = failure.cleanup_uncertain
            except (
                OSError,
                RuntimeError,
                ValueError,
                TypeError,
                AttributeError,
                OverflowError,
                MemoryError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
                uncertain = True
            if type(uncertain) is not bool:
                uncertain = True
            raise PreflightError(cleanup_uncertain=uncertain) from None
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
            MemoryError,
            ImportError,
            SyntaxError,
            KeyError,
            IndexError,
            KeyboardInterrupt,
            SystemExit,
            GeneratorExit,
        ):
            # An attempted capture without a contract result cannot prove
            # that an owned child and its descriptors have been settled.
            raise PreflightError(cleanup_uncertain=True) from None

        if (
            type(capture) is not diagnostics.DiagnosticCapture
            or capture.kind != "getconf"
            or type(capture.stdout) is not bytes
            or len(capture.stdout) > diagnostics.GETCONF_STREAM_BYTES
            or type(capture.child_pid) is not int
            or not 1 <= capture.child_pid <= 2147483647
        ):
            raise PreflightError(cleanup_uncertain=True)

        observed = metadata._parse_temp_parent(capture.stdout)
        if type(observed) is not metadata.TempParent:
            raise PreflightError()
        return observed
    except PreflightError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        AttributeError,
        OverflowError,
        MemoryError,
        ImportError,
        SyntaxError,
        KeyError,
        IndexError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None


def _open_fixed_native_root() -> int:
    """Open only literal /; caller never supplies a root path or descriptor."""
    return os.open("/", _DIR_FLAGS)


def _stat_fixed_native_root() -> DirectoryMetadata:
    """Re-observe literal root; no caller-selected pathname."""
    return _metadata(os.stat("/", follow_symlinks=False))


@contextmanager
def _pin_observed_native_temp_chain() -> Iterator[_PinnedDirectoryChain]:
    """Pin getconf-derived native T ancestry, with no incident-state access.

    Private dormant composition seam only. The yielded chain is valid solely
    inside this context. This is not a complete incident preflight or evidence
    receipt; it neither opens selected staging nor grants caller path authority.
    """
    try:
        native = _observe_fixed_temp_parent()
        process = _fixed_process_metadata_module()
        if type(native) is not process.TempParent:
            raise PreflightError()
        source = native.native_path
        canonical = native.canonical_path
        if (
            type(source) is not str
            or type(canonical) is not str
            or not source.startswith("/var/folders/")
            or canonical != "/private" + source
        ):
            raise PreflightError()
        pieces = source.split("/")
        if len(pieces) != 7 or pieces[:3] != ["", "var", "folders"] or pieces[5:] != ["T", ""]:
            raise PreflightError()
        shard, token = pieces[3], pieces[4]
        if (
            len(shard) != 2
            or any(c not in _TEMP_ALNUM for c in shard)
            or not 1 <= len(token) <= 255
            or any(c not in _TEMP_ALNUM + "_" for c in token)
        ):
            raise PreflightError()
    except PreflightError:
        raise
    except (
        OSError,
        RuntimeError,
        TypeError,
        AttributeError,
        ValueError,
        IndexError,
        OverflowError,
        MemoryError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None

    root_fd = None
    try:
        root_fd = _open_fixed_native_root()
        if type(root_fd) is not int or root_fd < 0:
            raise PreflightError(cleanup_uncertain=True)
        root_initial = _metadata(os.fstat(root_fd))
        if root_initial != _stat_fixed_native_root():
            raise PreflightError()
        with _pin_fixed_temp_chain(root_fd, (shard, token)) as chain:
            if chain._initial[0] != root_initial:
                raise PreflightError()
            baseline = chain._initial
            yield chain
            chain.revalidate()
            if _stat_fixed_native_root() != root_initial:
                raise PreflightError()

        # The previous revalidation happened before the owned descendant FDs
        # were closed. Never accept it as final evidence: re-open only the
        # fixed component-wise, no-follow ancestry and compare every immutable
        # metadata snapshot AFTER those closes. The nested context owns and
        # safely closes all its own descriptors, propagating close uncertainty.
        with _pin_fixed_temp_chain(root_fd, (shard, token), post_close_validate=True) as fresh:
            if fresh._initial != baseline:
                raise PreflightError()
            fresh.revalidate()

        # The second pass checks each literal single-component edge against
        # its held parent after the child closes. A later ancestor close may
        # still change an already-checked descendant. Supplement that
        # authoritative no-follow traversal with a *reject-only* reverse
        # metadata drift pass after all descendant closes. Joined stat paths
        # are NEVER used as proof of intermediate no-follow provenance.
        # Reverse order prevents a later shallow prefix from silently
        # authorizing a previously unchecked deeper edge.
        fixed_parts = ("private", "var", "folders", shard, token, "T")
        for index in range(len(baseline) - 1, 0, -1):
            prefix = "/".join(fixed_parts[:index])
            if _metadata(os.stat(prefix, dir_fd=root_fd, follow_symlinks=False)) != baseline[index]:
                raise PreflightError()
        if (
            _metadata(os.fstat(root_fd)) != root_initial
            or _stat_fixed_native_root() != root_initial
        ):
            raise PreflightError()
    except PreflightError:
        raise
    except (
        OSError,
        RuntimeError,
        TypeError,
        AttributeError,
        ValueError,
        IndexError,
        OverflowError,
        MemoryError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None
    finally:
        if type(root_fd) is int and root_fd >= 0:
            try:
                os.close(root_fd)
            except (
                OSError,
                RuntimeError,
                TypeError,
                OverflowError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
                raise PreflightError(cleanup_uncertain=True) from None


def _observe_paired_process_inventory(
    selected_chain: _PinnedDirectoryChain, selector: str
) -> _SelectedInventoryEvidence:
    """Fixture-only ps-A / selected inventory / ps-B composition.

    The caller must *already* hold and validate the original temp ancestry.
    This private intermediate neither derives native getconf provenance nor
    authenticates the cache marker; it is NOT a complete native preflight
    entrypoint and returns no process identities, capture bytes or receipt.
    """
    try:
        incident = _select_incident(selector)
        if (
            type(selected_chain) is not _PinnedDirectoryChain
            or selected_chain._parts != (incident.basename,)
            or len(selected_chain._fds) != 2
            or len(selected_chain._initial) != 2
            or (
                selected_chain.metadata[0].device,
                selected_chain.metadata[0].inode,
                selected_chain.metadata[0].uid,
                selected_chain.metadata[0].mode,
            )
            != (incident.device, incident.inode, incident.uid, incident.mode)
        ):
            raise PreflightError()
        selected_chain.revalidate()
        # Real child freshness is two invocations of the reviewed fixed
        # capture; equal stdout/rows or kernel-reused ps PIDs are permitted.
        _observe_fixed_process_snapshot()
        selected = _observe_selected_inventory(selected_chain, selector)
        _observe_fixed_process_snapshot()
        # The second child has now been reaped. Recheck the *content* and
        # immutable metadata of expected_commit, not just its held root FD.
        with _pin_expected_commit(
            selected_chain._fds[-1],
            incident.expected_commit,
            uid=incident.uid,
            device=incident.device,
        ) as expected:
            if expected.first.metadata != selected.expected_metadata:
                raise PreflightError()
            original_payload = expected._payload_chain.metadata[0]
            expected.revalidate(incident.expected_commit, uid=incident.uid)
        # Owned payload-close can itself change the live name after the
        # previous read. Reopen only the same fixed no-follow payload/leaf,
        # bind both directory and leaf identities to the earlier observation,
        # and close the new descendant FDs before the final stat-only pass.
        selected_chain.revalidate()
        with _pin_expected_commit(
            selected_chain._fds[-1],
            incident.expected_commit,
            uid=incident.uid,
            device=incident.device,
        ) as after_close:
            if (
                after_close._payload_chain.metadata[0] != original_payload
                or after_close.first.metadata != selected.expected_metadata
            ):
                raise PreflightError()
            after_close.revalidate(incident.expected_commit, uid=incident.uid)

        # Final no-content, no-new-FD observation runs AFTER both payload
        # contexts have closed. It checks the fixed parent edge on either
        # side of a metadata-only leaf stat and refuses a changed parent or
        # file even if a close induced a same-inode content rewrite.
        # The leaf path is fixed, anchored to the held selected root and
        # follow_symlinks=False; no new regular-file content is opened.
        root_fd = selected_chain._fds[-1]
        if (
            _metadata(os.stat("payload-content", dir_fd=root_fd, follow_symlinks=False))
            != original_payload
        ):
            raise PreflightError()
        leaf = os.stat(
            "payload-content/expected_commit",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if _file_meta(leaf, incident.uid, None, 41, incident.device) != selected.expected_metadata:
            raise PreflightError()
        if (
            _metadata(os.stat("payload-content", dir_fd=root_fd, follow_symlinks=False))
            != original_payload
        ):
            raise PreflightError()
        selected_chain.revalidate()
        return selected
    except PreflightError:
        raise
    except (
        ImportError,
        SyntaxError,
        OSError,
        TypeError,
        ValueError,
        OverflowError,
        AttributeError,
        RuntimeError,
        MemoryError,
        KeyError,
        IndexError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None


@contextmanager
def _pin_observed_fixed_cache_chain() -> Iterator[_PinnedDirectoryChain]:
    """Dormant literal / → fixed marker-cache ancestry, not incident inspection.

    Zero caller selectors, no marker file read, receipt or workflow. The
    yielded descriptor chain is owned only inside this context; its literal
    root FD and descendant FDs are not detached as evidence.
    """
    root_fd = None
    try:
        root_fd = _open_fixed_native_root()
        if type(root_fd) is not int or root_fd < 0:
            raise PreflightError(cleanup_uncertain=True)
        root_initial = _metadata(os.fstat(root_fd))
        if root_initial != _stat_fixed_native_root():
            raise PreflightError()
        with _pin_fixed_cache_chain(root_fd) as chain:
            if chain._initial[0] != root_initial or chain._parts != _CACHE_PARTS:
                raise PreflightError()
            baseline = chain._initial
            yield chain
            chain.revalidate()
            if _stat_fixed_native_root() != root_initial:
                raise PreflightError()

        # Closing a descendant after its last revalidation can be the point
        # of a namespace swap. A second fixed no-follow chain compares every
        # original edge AFTER the first descendant cleanup has completed.
        with _pin_fixed_cache_chain(root_fd, post_close_validate=True) as fresh:
            if fresh._initial != baseline:
                raise PreflightError()
            fresh.revalidate()

        # Every descendant close was followed by a single-component,
        # no-follow name check relative to its still-held original parent.
        # A multi-component stat cannot prove this invariant.
        if (
            _metadata(os.fstat(root_fd)) != root_initial
            or _stat_fixed_native_root() != root_initial
        ):
            raise PreflightError()
    except PreflightError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        RuntimeError,
        OverflowError,
        MemoryError,
        IndexError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None
    finally:
        if type(root_fd) is int and root_fd >= 0:
            try:
                os.close(root_fd)
            except (
                OSError,
                ValueError,
                TypeError,
                RuntimeError,
                OverflowError,
                MemoryError,
                KeyboardInterrupt,
                SystemExit,
                GeneratorExit,
            ):
                raise PreflightError(cleanup_uncertain=True) from None


@contextmanager
def _pin_observed_incident_ancestry(
    selector: str,
) -> Iterator[tuple[_PinnedDirectoryChain, _PinnedDirectoryChain, _PinnedDirectoryChain]]:
    """Borrow fixed cache, getconf-temp, and selected-root FDs together.

    Private fixture-only ownership context: no detached evidence, host-state
    content read, snapshot, receipt, activation, or recovery authority.
    Original fixed selectors alone choose the staging basename. The native
    getconf child completes before any namespace FD is pinned.
    """
    _select_incident(selector)
    try:
        with (
            _pin_observed_native_temp_chain() as temp,
            _pin_observed_fixed_cache_chain() as cache,
            _pin_fixed_incident_root(temp._fds[-1], selector) as selected,
        ):
            _require_shared_incident_ancestry(cache, temp, selected)
            temp.revalidate()
            cache.revalidate()
            selected.revalidate()
            yield (cache, temp, selected)
            # Rebind root and T provenance while every owner still holds
            # its FD, before the nested, fail-closed cleanup begins.
            selected.revalidate()
            temp.revalidate()
            cache.revalidate()
            _require_shared_incident_ancestry(cache, temp, selected)
    except PreflightError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        OverflowError,
        AttributeError,
        RuntimeError,
        MemoryError,
        IndexError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None


def _require_shared_incident_ancestry(
    cache: _PinnedDirectoryChain,
    temp: _PinnedDirectoryChain,
    selected: _PinnedDirectoryChain,
) -> None:
    """Bind two literal-root FD owners and the borrowed selected T parent.

    Compare the *full* device/inode/type/UID/GID/mode tuple at the common
    boundaries, twice while all three contexts still own live descriptors.
    """
    if (
        type(cache) is not _PinnedDirectoryChain
        or type(temp) is not _PinnedDirectoryChain
        or type(selected) is not _PinnedDirectoryChain
        or not cache._initial
        or not temp._initial
        or not selected._initial
        or not cache._fds
        or not temp._fds
        or not selected._fds
        or cache._initial[0] != temp._initial[0]
        or selected._initial[0] != temp._initial[-1]
    ):
        raise PreflightError()
    root = temp._initial[0]
    tail = temp._initial[-1]
    if (
        _metadata(os.fstat(temp._fds[0])) != root
        or _metadata(os.fstat(cache._fds[0])) != root
        or _metadata(os.fstat(temp._fds[-1])) != tail
        or _metadata(os.fstat(selected._fds[0])) != tail
    ):
        raise PreflightError()


def _observe_joint_marker_staging(selector: str) -> _MarkerStagingEvidence:
    """Private dormant marker/staging observation under jointly pinned roots.

    No ps, trusted-runner invocation, receipt, workflow or recovery action.
    This detached *partial* evidence does not prove complete native preflight.
    """
    incident = _select_incident(selector)
    try:
        with _pin_observed_incident_ancestry(selector) as (cache, temp, selected):
            _require_shared_incident_ancestry(cache, temp, selected)
            observed = _observe_marker_staging(cache, selected, selector)
            # The inventory can change after its inner helper returns.
            # Rebind only the catalog's fixed expected_commit through the
            # still-held selected FD, then confirm the marker's fixed schema
            # and immutable metadata once again after that bounded read.
            with _pin_expected_commit(
                selected._fds[-1],
                incident.expected_commit,
                uid=incident.uid,
                device=incident.device,
            ) as expected:
                if expected.first.metadata != observed.selected.expected_metadata:
                    raise PreflightError()
                original_payload = expected._payload_chain.metadata[0]
                expected.revalidate(incident.expected_commit, uid=incident.uid)
                late_marker = _read_marker(cache._fds[-1], uid=_CACHE_ACCOUNT_UID)
                if late_marker.metadata != observed.marker_metadata:
                    raise PreflightError()
                # Content is reread through the SAME pinned payload descriptor
                # after the marker read, while it is still held.
                expected.revalidate(incident.expected_commit, uid=incident.uid)
            # The owned payload close may itself mutate the marker. Bind the
            # fixed marker again *after* the payload descriptors are closed.
            settled_marker = _read_marker(cache._fds[-1], uid=_CACHE_ACCOUNT_UID)
            if settled_marker.metadata != observed.marker_metadata:
                raise PreflightError()
            # The final marker owned FD is now closed. Its successful
            # close can rename the *currently named* fixed leaf while
            # leaving the frozen returned metadata unchanged. Bind that
            # literal single-component live edge with NOFOLLOW relative
            # to the still-held cache directory FD, before releasing it.
            if (
                _file_meta(
                    os.stat(
                        "active-run.json",
                        dir_fd=cache._fds[-1],
                        follow_symlinks=False,
                    ),
                    _CACHE_ACCOUNT_UID,
                    0o600,
                    4096,
                    None,
                )
                != observed.marker_metadata
            ):
                raise PreflightError()
            # Descendant closure itself can mutate a name. After it completes,
            # perform only a reject-only metadata drift check of the original
            # fixed payload and expected-commit identities. The joined leaf
            # stat is NOT a no-follow proof for intermediate components; the
            # preceding descriptor-relative pin supplies that authority.
            selected_fd = selected._fds[-1]
            if (
                _metadata(os.stat("payload-content", dir_fd=selected_fd, follow_symlinks=False))
                != original_payload
            ):
                raise PreflightError()
            late_leaf = os.stat(
                "payload-content/expected_commit",
                dir_fd=selected_fd,
                follow_symlinks=False,
            )
            if (
                _file_meta(late_leaf, incident.uid, None, 41, incident.device)
                != observed.selected.expected_metadata
            ):
                raise PreflightError()
            if (
                _metadata(os.stat("payload-content", dir_fd=selected_fd, follow_symlinks=False))
                != original_payload
            ):
                raise PreflightError()
            # Both content readers completed before this final common-root,
            # pinned-name-edge and ownership gate.
            selected.revalidate()
            cache.revalidate()
            temp.revalidate()
            _require_shared_incident_ancestry(cache, temp, selected)
        return observed
    except PreflightError:
        raise
    except (
        ImportError,
        SyntaxError,
        OSError,
        TypeError,
        ValueError,
        AttributeError,
        RuntimeError,
        OverflowError,
        MemoryError,
        IndexError,
        KeyError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise PreflightError() from None
