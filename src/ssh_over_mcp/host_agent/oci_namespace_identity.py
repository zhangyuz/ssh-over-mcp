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


def require_exact_namespace_maps(
    observed: PinnedNamespaceIdentity,
    *,
    expected_uid_map: tuple[IdMapEntry, ...],
    expected_gid_map: tuple[IdMapEntry, ...],
) -> None:
    """Compare to independently configured manager maps, never SSH-provided IDs.

    /proc/<pid>/uid_map's outside column is relative to the parent user
    namespace; this comparison does NOT claim global/host UID translation.
    """
    if not isinstance(observed, PinnedNamespaceIdentity):
        raise OciPidfdHandoffRefused("pinned identity required")
    if (
        not isinstance(expected_uid_map, tuple)
        or not expected_uid_map
        or any(not isinstance(entry, IdMapEntry) for entry in expected_uid_map)
    ):
        raise OciPidfdHandoffRefused("trusted UID mapping required")
    if (
        not isinstance(expected_gid_map, tuple)
        or not expected_gid_map
        or any(not isinstance(entry, IdMapEntry) for entry in expected_gid_map)
    ):
        raise OciPidfdHandoffRefused("trusted GID mapping required")
    if observed.uid_map != expected_uid_map:
        raise OciPidfdHandoffRefused("OCI UID mapping differs from trusted configuration")
    if observed.gid_map != expected_gid_map:
        raise OciPidfdHandoffRefused("OCI GID mapping differs from trusted configuration")


_CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
_REQUIRED_STATUS_FIELDS = ("Uid", "Gid", "NoNewPrivs", *_CAPABILITY_FIELDS)


@dataclass(frozen=True, slots=True)
class LinuxSecurityStatus:
    """Credentials as seen by the *reading manager's* procfs credentials view."""

    uid: tuple[int, int, int, int]
    gid: tuple[int, int, int, int]
    no_new_privs: int
    caps: tuple[int, int, int, int, int]


def parse_security_status(raw: bytes) -> LinuxSecurityStatus:
    """Parse only required, unique numeric Linux /proc/<pid>/status fields."""
    if not isinstance(raw, bytes) or not raw.endswith(b"\n") or len(raw) > 16384:
        raise OciPidfdHandoffRefused("incomplete or oversized process status")
    found: dict[str, bytes] = {}
    for line in raw[:-1].split(b"\n"):
        key, separator, value = line.partition(b":")
        if not separator or key not in {field.encode() for field in _REQUIRED_STATUS_FIELDS}:
            continue
        name = key.decode("ascii")
        if name in found:
            raise OciPidfdHandoffRefused("duplicate process security field")
        if b"\r" in value or b"\x00" in value:
            raise OciPidfdHandoffRefused("ambiguous process security field")
        found[name] = value.strip()
    if set(found) != set(_REQUIRED_STATUS_FIELDS):
        raise OciPidfdHandoffRefused("missing required process security field")
    try:
        ids: list[tuple[int, int, int, int]] = []
        for name in ("Uid", "Gid"):
            parts = found[name].split()
            if len(parts) != 4 or any(not part.isascii() or not part.isdigit() for part in parts):
                raise ValueError("invalid process ID quartet")
            values = tuple(int(part) for part in parts)
            if any(value >= _UINT32_MAX for value in values):
                raise ValueError("unmapped or overflow process identity")
            ids.append(values)
        if found["NoNewPrivs"] not in (b"0", b"1"):
            raise ValueError("invalid NoNewPrivs status")
        caps: list[int] = []
        for name in _CAPABILITY_FIELDS:
            value = found[name]
            if len(value) != 16 or any(byte not in b"0123456789abcdefABCDEF" for byte in value):
                raise ValueError("noncanonical capability mask")
            caps.append(int(value, 16))
        return LinuxSecurityStatus(
            uid=ids[0],
            gid=ids[1],
            no_new_privs=int(found["NoNewPrivs"]),
            caps=tuple(caps),
        )
    except (ValueError, TypeError) as exc:
        raise OciPidfdHandoffRefused("unverifiable process security status") from exc


def _read_security_status(pid: int) -> LinuxSecurityStatus:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise OciPidfdHandoffRefused("invalid status process PID")
    try:
        with open(f"/proc/{pid}/status", "rb") as stream:
            return parse_security_status(stream.read(16385))
    except OSError as exc:
        raise OciPidfdHandoffRefused("process security status unavailable") from exc


@dataclass(frozen=True, slots=True)
class PinnedExecutionSecurity:
    namespace: PinnedNamespaceIdentity
    status: LinuxSecurityStatus


def inspect_pinned_execution_security(fd: int) -> PinnedExecutionSecurity:
    """Take before/after pinned snapshots; return no privilege authority."""
    first = inspect_pinned_namespace_identity(fd)
    if _pidfd_pid(fd) != first.pid or _proc_identity(first.pid) != (
        first.parent_pid,
        first.starttime,
    ):
        raise OciPidfdHandoffRefused("pinned process changed before status read")
    initial_status = _read_security_status(first.pid)
    second = inspect_pinned_namespace_identity(fd)
    final_status = _read_security_status(first.pid)
    if first != second or initial_status != final_status:
        raise OciPidfdHandoffRefused("process namespace or credentials changed")
    if _pidfd_pid(fd) != first.pid or _proc_identity(first.pid) != (
        first.parent_pid,
        first.starttime,
    ):
        raise OciPidfdHandoffRefused("pinned process changed after status read")
    return PinnedExecutionSecurity(namespace=first, status=initial_status)


def require_workload_security_status(
    status: LinuxSecurityStatus,
    *,
    expected_observed_uid: int,
    expected_observed_gid: int,
) -> None:
    """Proof-check postdrop workload NNP=1 and **all** capability sets zero.

    Expected IDs must be separately determined in the manager's procfs
    namespace; never assume a container-internal UID equals a host UID.
    """
    if not isinstance(status, LinuxSecurityStatus):
        raise OciPidfdHandoffRefused("kernel status snapshot required")
    for name, expected in (("uid", expected_observed_uid), ("gid", expected_observed_gid)):
        if (
            isinstance(expected, bool)
            or not isinstance(expected, int)
            or not 0 < expected < _UINT32_MAX
        ):
            raise OciPidfdHandoffRefused(f"trusted observed {name} required")
        if getattr(status, name) != (expected,) * 4:
            raise OciPidfdHandoffRefused(f"workload {name} credentials differ")
    if status.no_new_privs != 1:
        raise OciPidfdHandoffRefused("workload NoNewPrivs not enabled")
    if any(status.caps):
        raise OciPidfdHandoffRefused("workload retains capabilities")
