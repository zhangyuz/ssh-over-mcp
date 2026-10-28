"""Node-bound OCI manager cgroup-v2 source writer (source-only, NOT admitted).

This is called only by the authenticated self-pidfd manager handler. Writing
a numeric PID to cgroup.procs is not an atomic pidfd operation, so kernel
PID-lifetime/namespace proof and separate guest runtime approval remain STOP.
"""

from __future__ import annotations

import ctypes
import os
import stat
import sys

from .oci_pidfd_handoff import OciPidfdHandoffRefused
from .oci_source_migration import OciSourceDomain, PinnedOciSource

_CGROUP2_SUPER_MAGIC = 0x63677270
_CGROUP2_ROOT = "/sys/fs/cgroup"
_DIRECTORY_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_WRITE_FLAGS = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class OciSourceOutcomeUnknown(OciPidfdHandoffRefused):
    """One cgroup.procs write was attempted; never retry blindly."""


def _require_cgroup2(fd: int) -> None:
    if sys.platform != "linux":
        raise OciPidfdHandoffRefused("source cgroup writer is Linux-only")

    class _Statfs(ctypes.Structure):
        _fields_ = [("f_type", ctypes.c_long), ("reserved", ctypes.c_byte * 248)]

    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_Statfs)]
    libc.fstatfs.restype = ctypes.c_int
    state = _Statfs()
    if libc.fstatfs(fd, ctypes.byref(state)) != 0 or state.f_type != _CGROUP2_SUPER_MAGIC:
        raise OciPidfdHandoffRefused("trusted manager cgroup2 mount unavailable")


def _mount_id(fd: int) -> int:
    """Kernel mount ID. Reject bind/submount substitution at every component."""
    if sys.platform != "linux":
        raise OciPidfdHandoffRefused("cgroup mount ID is Linux-only")
    try:
        with open(f"/proc/self/fdinfo/{fd}", "rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError("oversized fdinfo")
        values = [
            line.partition(b":")[2].strip()
            for line in raw.splitlines()
            if line.startswith(b"mnt_id:")
        ]
        if len(values) != 1 or not values[0].isdigit() or int(values[0]) <= 0:
            raise ValueError("missing mount ID")
        return int(values[0])
    except (OSError, ValueError) as exc:
        raise OciPidfdHandoffRefused("cannot verify trusted cgroup mount") from exc


def _require_fixed_domain(domain: OciSourceDomain, trusted_node: str) -> tuple[str, ...]:
    if trusted_node not in ("node01", "node02"):
        raise OciPidfdHandoffRefused("untrusted manager node")
    expected = OciSourceDomain(
        delegated_root=f"/som-mode-a/{trusted_node}",
        admission_cgroup=f"/som-mode-a/{trusted_node}/admission",
        agent_source_cgroup=f"/som-mode-a/{trusted_node}/host-agent-source",
    )
    if domain != expected:
        raise OciPidfdHandoffRefused("source destination not this manager's node")
    return ("som-mode-a", trusted_node, "host-agent-source")


def move_fixed_source(source: PinnedOciSource, *, trusted_node: str) -> None:
    """Write exactly once under the pre-authorized *manager-owned* node mount.

    A successful syscall alone is insufficient: original pidfd identity and
    fixed target membership are read back before ACK. Even these checks do
    NOT establish the numeric PID reuse window is safe without kernel proof.
    """
    if not isinstance(source, PinnedOciSource):
        raise OciPidfdHandoffRefused("pinned source receipt required")
    segments = _require_fixed_domain(source.domain, trusted_node)
    source.recheck_source()

    fds: list[int] = []
    write_attempted = False
    prior_error: Exception | None = None
    try:
        fds.append(os.open(_CGROUP2_ROOT, _DIRECTORY_FLAGS))
        _require_cgroup2(fds[0])
        root_mount_id = _mount_id(fds[0])
        for segment in segments:
            fds.append(os.open(segment, _DIRECTORY_FLAGS, dir_fd=fds[-1]))
            _require_cgroup2(fds[-1])
            if _mount_id(fds[-1]) != root_mount_id:
                raise OciPidfdHandoffRefused("cgroup submount substitution")
        fd = os.open("cgroup.procs", _WRITE_FLAGS, dir_fd=fds[-1])
        fds.append(fd)
        _require_cgroup2(fd)
        if _mount_id(fd) != root_mount_id or not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OciPidfdHandoffRefused("untrusted destination cgroup.procs")
        source.recheck_source()
        payload = str(source.pid).encode("ascii")
        write_attempted = True
        if os.write(fd, payload) != len(payload):
            raise OciSourceOutcomeUnknown("partial source migration; do not retry")
        source.check_target_membership()
    except Exception as exc:
        prior_error = exc
        if write_attempted:
            raise OciSourceOutcomeUnknown(
                "source cgroup write outcome unknown; do not retry"
            ) from exc
        if isinstance(exc, (OSError, ValueError)):
            raise OciPidfdHandoffRefused("fixed source migration refused before write") from exc
        raise
    finally:
        close_error: OSError | None = None
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None and prior_error is None:
            raise OciSourceOutcomeUnknown(
                "source cgroup FD close outcome uncertain; do not retry"
            ) from close_error


def serve_fixed_node_source_once(
    sock, *, trusted_node: str, domain: OciSourceDomain, peer_policy
) -> None:
    """Bind existing self-pidfd authenticated handler to one manager-owned node."""
    _require_fixed_domain(domain, trusted_node)
    from .oci_source_migration import handle_fixed_source_move

    handle_fixed_source_move(
        sock,
        peer_policy=peer_policy,
        domain=domain,
        trusted_move=lambda source: move_fixed_source(source, trusted_node=trusted_node),
    )
