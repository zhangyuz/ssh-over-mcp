"""Fixed one-slot OCI MVP child cgroup attach callback (inactive by default).

Caller MUST be the authenticated child-pidfd handler with a trusted
OciChildAttachPolicy. The no-NIC guest creates /workload/mvp beforehand,
proves the cgroup delegation, parent barrier, and PID reuse behavior.
No generic cgroup paths, Linux host root operations, or retries.
"""

from __future__ import annotations

import os
import stat

from .oci_pidfd_handoff import OciPidfdHandoffRefused, PinnedOciChild
from .oci_source_migration import _current_cgroup
from .oci_source_writer import (
    _CGROUP2_ROOT,
    _DIRECTORY_FLAGS,
    _WRITE_FLAGS,
    OciSourceOutcomeUnknown,
    _mount_id,
    _require_cgroup2,
)


def fixed_mvp_target(trusted_node: str) -> str:
    if trusted_node not in ("node01", "node02"):
        raise OciPidfdHandoffRefused("untrusted manager node")
    return f"/som-mode-a/{trusted_node}/workload/mvp"


def move_fixed_mvp_child(child: PinnedOciChild, *, trusted_node: str) -> None:
    """Single target-cgroup write, UNKNOWN on any post-write doubt.

    The manager owns the pre-created one-slot workload subtree; multiple
    simultaneous requests are NOT supported until request-scoped lifecycle
    and kernel attach proof are complete.
    """
    if not isinstance(child, PinnedOciChild):
        raise OciPidfdHandoffRefused("pinned direct child receipt required")
    target = fixed_mvp_target(trusted_node)
    child.recheck_identity()
    fds: list[int] = []
    attempted = False
    prior: Exception | None = None
    try:
        fds.append(os.open(_CGROUP2_ROOT, _DIRECTORY_FLAGS))
        _require_cgroup2(fds[0])
        root_mount = _mount_id(fds[0])
        for part in ("som-mode-a", trusted_node, "workload", "mvp"):
            fds.append(os.open(part, _DIRECTORY_FLAGS, dir_fd=fds[-1]))
            _require_cgroup2(fds[-1])
            if _mount_id(fds[-1]) != root_mount:
                raise OciPidfdHandoffRefused("untrusted workload submount")
        fd = os.open("cgroup.procs", _WRITE_FLAGS, dir_fd=fds[-1])
        fds.append(fd)
        _require_cgroup2(fd)
        if _mount_id(fd) != root_mount or not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OciPidfdHandoffRefused("untrusted workload target")
        child.recheck_identity()
        payload = str(child.pid).encode("ascii")
        attempted = True
        if os.write(fd, payload) != len(payload):
            raise OciSourceOutcomeUnknown("child attach uncertain; do not retry")
        child.recheck_identity()
        if _current_cgroup(child.pid) != target:
            raise OciSourceOutcomeUnknown("child target membership unknown; do not retry")
    except Exception as exc:
        prior = exc
        if attempted:
            raise OciSourceOutcomeUnknown("child attach effect unknown; do not retry") from exc
        if isinstance(exc, (OSError, ValueError)):
            raise OciPidfdHandoffRefused("child attach refused before write") from exc
        raise
    finally:
        close_error: OSError | None = None
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None and prior is None:
            raise OciSourceOutcomeUnknown(
                "child attach close unknown; do not retry"
            ) from close_error
