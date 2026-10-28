"""Fail-closed source-cgroup identity preflight for OCI manager move_source_self.

The root launcher presents ONLY its own SCM_RIGHTS pidfd on a fresh
authenticated Unix socket. The manager supplies both fixed paths, never the
client. This module does NOT move processes or write cgroup.procs: the
numeric-PID reuse and delegation proof remains a separate kernel gate.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import PurePosixPath

from .containment_manager_peer import LinuxPeerCredentialPolicy
from .oci_pidfd_handoff import (
    OciPidfdHandoffRefused,
    _pidfd_pid,
    _proc_identity,
    receive_peer_self_pidfd,
)


def _cgroup_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path == "/"
        or len(path) > 240
        or "//" in path
        or any(segment in ("", ".", "..") for segment in path[1:].split("/"))
        or str(PurePosixPath(path)) != path
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in path)
    ):
        raise ValueError("invalid fixed cgroup-v2 path")
    return path


@dataclass(frozen=True, slots=True)
class OciSourceDomain:
    """Fixed manager-owned, per-node cgroup membership expectation."""

    delegated_root: str
    admission_cgroup: str
    agent_source_cgroup: str

    def __post_init__(self) -> None:
        for field in ("delegated_root", "admission_cgroup", "agent_source_cgroup"):
            _cgroup_path(getattr(self, field))
        prefix = self.delegated_root + "/"
        if not self.admission_cgroup.startswith(prefix):
            raise ValueError("admission cgroup not under delegated node root")
        if not self.agent_source_cgroup.startswith(prefix):
            raise ValueError("host-agent source not under delegated node root")
        if self.admission_cgroup == self.agent_source_cgroup:
            raise ValueError("source and target must be distinct")


def _current_cgroup(pid: int) -> str:
    """Read exactly one unified cgroup-v2 membership from the manager's procfs."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise OciPidfdHandoffRefused("invalid process identity")
    try:
        # Binary read is critical: universal-newline decoding would silently
        # turn a real cgroup name ending in CR into our expected path.
        with open(f"/proc/{pid}/cgroup", "rb") as stream:
            raw = stream.read(4097)
        if (
            len(raw) > 4096
            or not raw.startswith(b"0::/")
            or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1
        ):
            raise ValueError("expected one canonical unified cgroup-v2 record")
        return _cgroup_path(raw[3:-1].decode("ascii"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise OciPidfdHandoffRefused("unverifiable unified cgroup membership") from exc


@dataclass(frozen=True, slots=True)
class PinnedOciSource:
    """Authenticated process identity and source cgroup, no migration authority."""

    fd: int
    pid: int
    parent_pid: int
    starttime: int
    domain: OciSourceDomain

    def recheck_source(self) -> None:
        if _pidfd_pid(self.fd) != self.pid:
            raise OciPidfdHandoffRefused("source pidfd identity changed")
        parent, birth = _proc_identity(self.pid)
        if (parent, birth) != (self.parent_pid, self.starttime):
            raise OciPidfdHandoffRefused("source process identity changed")
        if _current_cgroup(self.pid) != self.domain.admission_cgroup:
            raise OciPidfdHandoffRefused("source not in fixed admission cgroup")

    def check_target_membership(self) -> None:
        """Read-only postcondition after a *separately authorized* cgroup write."""
        if _pidfd_pid(self.fd) != self.pid:
            raise OciPidfdHandoffRefused("source pidfd identity changed")
        parent, birth = _proc_identity(self.pid)
        if (parent, birth) != (self.parent_pid, self.starttime):
            raise OciPidfdHandoffRefused("source process identity changed")
        if _current_cgroup(self.pid) != self.domain.agent_source_cgroup:
            raise OciPidfdHandoffRefused("source not in fixed host-agent cgroup")


def inspect_manager_source_self(
    sock, *, peer_policy: LinuxPeerCredentialPolicy, domain: OciSourceDomain
) -> PinnedOciSource:
    """Authenticate launcher self-pidfd and prove fixed node source membership.

    Socket must be closed by the caller before dropping the launcher UID.
    The caller owns and must close the returned pinned fd.
    """
    if not isinstance(domain, OciSourceDomain):
        raise TypeError("trusted manager source domain required")
    fd = receive_peer_self_pidfd(sock, peer_policy=peer_policy)
    try:
        pid = _pidfd_pid(fd)
        parent, birth = _proc_identity(pid)
        candidate = PinnedOciSource(fd, pid, parent, birth, domain)
        candidate.recheck_source()
        return candidate
    except BaseException:
        os.close(fd)
        raise


def handle_fixed_source_move(
    sock,
    *,
    peer_policy: LinuxPeerCredentialPolicy,
    domain: OciSourceDomain,
    trusted_move,
) -> None:
    """One OCI manager request, never a caller-selected PID or cgroup.

    trusted_move is injected **only by manager startup**, not sent by an SSH
    peer. It must implement the guest-reviewed cgroup-v2 writer and refuse on
    any delegation/namespace/lifetime doubt. This handler is not wired into
    the existing managed-host protocol or a Docker deployment.
    """
    source = None
    try:
        source = inspect_manager_source_self(sock, peer_policy=peer_policy, domain=domain)
        source.recheck_source()
        trusted_move(source)
        # ACK only after proving *the same* pinned process is in exactly the
        # node's fixed source destination. On unknown effects refuse.
        source.check_target_membership()
        sock.settimeout(2.0)
        sock.sendall(b"A")
    except (OciPidfdHandoffRefused, OSError, ValueError) as exc:
        # A failed or uncertain cgroup write is never reported as success.
        try:
            sock.sendall(b"N")
        except OSError:
            pass
        raise OciPidfdHandoffRefused("fixed source migration refused") from exc
    finally:
        if source is not None:
            os.close(source.fd)


def request_fixed_source_move(
    sock,
    *,
    manager_peer_policy: LinuxPeerCredentialPolicy,
    expected_source_cgroup: str,
) -> None:
    """Root-phase launcher request: self-only pidfd; no arbitrary path or PID.

    The launcher MUST close its socket before setresuid/setresgid and open a
    separate authenticated post-drop connection. No workload import here.
    """
    from .containment_manager_peer import authenticate_linux_unix_peer
    from .oci_pidfd_handoff import _require_connected_unix_stream, send_self_pidfd

    _require_connected_unix_stream(sock)
    authenticate_linux_unix_peer(sock, manager_peer_policy)
    fixed_target = _cgroup_path(expected_source_cgroup)
    sock.settimeout(2.0)
    try:
        send_self_pidfd(sock)
        reply = sock.recv(1)
    except OSError as exc:
        raise OciPidfdHandoffRefused("source manager unresponsive") from exc
    if reply != b"A":
        raise OciPidfdHandoffRefused("source manager denied move")
    if _current_cgroup(os.getpid()) != fixed_target:
        raise OciPidfdHandoffRefused("launcher source cgroup readback failed")
