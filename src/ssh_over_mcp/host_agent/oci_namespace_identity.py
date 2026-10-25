"""Read-only, pidfd-bound Linux OCI namespace/mapping verification.

This is a fail-closed observation layer, not authorization to move cgroups,
change user namespaces, run containers or grant elevated capabilities.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .oci_pidfd_handoff import (
    OciPidfdHandoffRefused,
    _pidfd_pid,
    _proc_identity,
)

_UINT32_MAX = (1 << 32) - 1


@dataclass(frozen=True, slots=True)
class IdMapEntry:
    inside: int
    outside: int
    length: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.inside, self.outside, self.length)
        ):
            raise ValueError("invalid user namespace id map entry")
        if (
            self.length == 0
            or self.inside + self.length > _UINT32_MAX
            or self.outside + self.length > _UINT32_MAX
        ):
            raise ValueError("user namespace id map exceeds valid kernel ids")


def parse_id_map(raw: bytes) -> tuple[IdMapEntry, ...]:
    """Parse canonical procfs map bytes, rejecting overlaps and overflow."""
    if not isinstance(raw, bytes) or not raw or len(raw) > 4096:
        raise OciPidfdHandoffRefused("missing or oversized namespace map")
    if not raw.endswith(b"\n") or any(byte not in b"0123456789 \t\n" for byte in raw):
        raise OciPidfdHandoffRefused("noncanonical namespace map record")
    entries: list[IdMapEntry] = []
    try:
        for line in raw[:-1].split(b"\n"):
            columns = line.split()
            if len(columns) != 3 or not all(
                value.isascii() and value.isdigit() for value in columns
            ):
                raise ValueError("invalid map syntax")
            entries.append(IdMapEntry(*(int(value) for value in columns)))
        if not 1 <= len(entries) <= 5:
            raise ValueError("invalid map entry count")
        for left_index, left in enumerate(entries):
            for right in entries[left_index + 1 :]:
                if (
                    left.inside < right.inside + right.length
                    and right.inside < left.inside + left.length
                ) or (
                    left.outside < right.outside + right.length
                    and right.outside < left.outside + left.length
                ):
                    raise ValueError("overlapping namespace map extents")
        return tuple(entries)
    except (ValueError, TypeError) as exc:
        raise OciPidfdHandoffRefused("unverifiable namespace id map") from exc


def _read_map(pid: int, map_name: str) -> tuple[IdMapEntry, ...]:
    if map_name not in ("uid_map", "gid_map"):
        raise ValueError("unsupported namespace map")
    try:
        with open(f"/proc/{pid}/{map_name}", "rb") as stream:
            raw = stream.read(4097)
        return parse_id_map(raw)
    except (OSError, ValueError) as exc:
        raise OciPidfdHandoffRefused("kernel namespace map unavailable") from exc


def _namespace_inode(pid: int, name: str) -> tuple[int, int]:
    if name not in ("pid", "user"):
        raise ValueError("unsupported namespace type")
    try:
        record = os.stat(f"/proc/{pid}/ns/{name}")
    except OSError as exc:
        raise OciPidfdHandoffRefused("kernel namespace link unavailable") from exc
    if record.st_dev <= 0 or record.st_ino <= 0:
        raise OciPidfdHandoffRefused("invalid namespace inode")
    return record.st_dev, record.st_ino


@dataclass(frozen=True, slots=True)
class PinnedNamespaceIdentity:
    pid: int
    parent_pid: int
    starttime: int
    pidns: tuple[int, int]
    userns: tuple[int, int]
    uid_map: tuple[IdMapEntry, ...]
    gid_map: tuple[IdMapEntry, ...]


def inspect_pinned_namespace_identity(fd: int) -> PinnedNamespaceIdentity:
    """Observe proc namespace identities with consistent pidfd and birth time."""
    pid = _pidfd_pid(fd)
    parent, birth = _proc_identity(pid)
    result = PinnedNamespaceIdentity(
        pid=pid,
        parent_pid=parent,
        starttime=birth,
        pidns=_namespace_inode(pid, "pid"),
        userns=_namespace_inode(pid, "user"),
        uid_map=_read_map(pid, "uid_map"),
        gid_map=_read_map(pid, "gid_map"),
    )
    if _pidfd_pid(fd) != pid or _proc_identity(pid) != (parent, birth):
        raise OciPidfdHandoffRefused("namespace process changed during inspection")
    if (
        _namespace_inode(pid, "pid") != result.pidns
        or _namespace_inode(pid, "user") != result.userns
        or _read_map(pid, "uid_map") != result.uid_map
        or _read_map(pid, "gid_map") != result.gid_map
    ):
        raise OciPidfdHandoffRefused("namespace mapping changed during inspection")
    return result


def require_separate_userns_shared_pidns(
    manager: PinnedNamespaceIdentity, target: PinnedNamespaceIdentity
) -> None:
    """Refuse proposed OCI split if expected namespace relationship is absent."""
    if not isinstance(manager, PinnedNamespaceIdentity) or not isinstance(
        target, PinnedNamespaceIdentity
    ):
        raise OciPidfdHandoffRefused("pinned namespace identities required")
    if manager.pidns != target.pidns:
        raise OciPidfdHandoffRefused("manager and target PID namespaces differ")
    if manager.userns == target.userns:
        raise OciPidfdHandoffRefused("manager and target share user namespace")
    if manager.pid == target.pid:
        raise OciPidfdHandoffRefused("manager cannot be its own OCI target")
