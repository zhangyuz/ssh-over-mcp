"""Dormant OCI manager child-attach ACK, using existing supervisor barrier.

This module validates a pinned, unreaped child and delegates *only* to a
separately approved manager-owned cgroup operation. No cgroup writer, runner,
child-release, or production integer-PID fallback is supplied here.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass

from .containment_manager_identity import (
    ContainmentServiceIdentityPlan,
    require_linux_process_identity,
)
from .containment_manager_peer import (
    LinuxPeerCredentialPolicy,
    authenticate_linux_unix_peer,
)
from .oci_namespace_identity import (
    IdMapEntry,
    inspect_pinned_namespace_identity,
    require_exact_namespace_maps,
    require_separate_userns_shared_pidns,
)
from .oci_pidfd_handoff import (
    OciPidfdHandoffRefused,
    PinnedOciChild,
    _pidfd_pid,
    _require_connected_unix_stream,
    receive_direct_child_pidfd,
    send_pinned_child_pidfd,
)
from .oci_source_migration import OciSourceDomain, _cgroup_path, _current_cgroup

_TIMEOUT = 2.0


@dataclass(frozen=True, slots=True)
class OciChildAttachPolicy:
    """Trusted manager-side scope; never serialized from the SSH peer."""

    domain: OciSourceDomain
    target_cgroup: str
    expected_child_uid_map: tuple[IdMapEntry, ...]
    expected_child_gid_map: tuple[IdMapEntry, ...]

    def __post_init__(self) -> None:
        _cgroup_path(self.target_cgroup)
        root = self.domain.delegated_root + "/"
        if not self.target_cgroup.startswith(root) or any(
            self.target_cgroup == forbidden or self.target_cgroup.startswith(forbidden + "/")
            for forbidden in (
                self.domain.admission_cgroup,
                self.domain.agent_source_cgroup,
            )
        ):
            raise ValueError("untrusted or non-workload destination")
        if (
            not self.expected_child_uid_map
            or not self.expected_child_gid_map
            or not all(
                isinstance(entry, IdMapEntry)
                for entry in (*self.expected_child_uid_map, *self.expected_child_gid_map)
            )
        ):
            raise ValueError("trusted child UID/GID maps required")


def _check_child(child: PinnedOciChild, policy: OciChildAttachPolicy, *, dest: bool) -> None:
    child.recheck_identity()
    expected = policy.target_cgroup if dest else policy.domain.agent_source_cgroup
    if _current_cgroup(child.pid) != expected:
        raise OciPidfdHandoffRefused("child cgroup membership differs from fixed node scope")


def handle_fixed_child_attach(
    sock: socket.socket,
    *,
    peer_policy: LinuxPeerCredentialPolicy,
    policy: OciChildAttachPolicy,
    trusted_attach,
) -> None:
    """Manager-owned child attach transaction; one pinned child, one ACK.

    trusted_attach is supplied by reviewed manager startup, never the peer.
    It MUST be a kernel-proven, PID-lifetime-safe fixed-target operation.
    Without such an operation this handler must remain unwired.
    """
    if not isinstance(policy, OciChildAttachPolicy):
        raise TypeError("trusted manager child policy required")

    child = None
    try:
        child = receive_direct_child_pidfd(sock, peer_policy=peer_policy)
        _check_child(child, policy, dest=False)
        with _self_pidfd() as manager_fd:
            manager = inspect_pinned_namespace_identity(manager_fd.fd)
            target = inspect_pinned_namespace_identity(child.fd)
            require_separate_userns_shared_pidns(manager, target)
            require_exact_namespace_maps(
                target,
                expected_uid_map=policy.expected_child_uid_map,
                expected_gid_map=policy.expected_child_gid_map,
            )
        child.recheck_identity()
        trusted_attach(child)
        _check_child(child, policy, dest=True)
        if inspect_pinned_namespace_identity(child.fd) != target:
            raise OciPidfdHandoffRefused("child namespace changed during attach")
        sock.settimeout(_TIMEOUT)
        sock.sendall(b"A")
    except (OciPidfdHandoffRefused, OSError, ValueError) as exc:
        try:
            sock.sendall(b"N")
        except OSError:
            pass
        raise OciPidfdHandoffRefused("fixed child attach refused") from exc
    finally:
        if child is not None:
            os.close(child.fd)


class _self_pidfd:
    """Manager PID pin retained only during local namespace identity checks."""

    def __enter__(self):
        self.fd = os.pidfd_open(os.getpid(), 0)
        return self

    def __exit__(self, *_args):
        os.close(self.fd)


def request_fixed_child_attach(
    sock: socket.socket,
    *,
    pinned_child_fd: int,
    manager_peer_policy: LinuxPeerCredentialPolicy,
    expected_local_target_cgroup: str,
) -> None:
    """Parent-side attach while EXISTING supervisor start barrier stays closed.

    Caller must keep the direct child unreaped and retain the barrier until a
    successful return. It must abort/kill/reap on any error, not release it.
    The local cgroup view must match an independently trusted exact target.
    """
    _require_connected_unix_stream(sock)
    authenticate_linux_unix_peer(sock, manager_peer_policy)
    target = _cgroup_path(expected_local_target_cgroup)
    sock.settimeout(_TIMEOUT)
    try:
        send_pinned_child_pidfd(sock, pinned_child_fd)
        answer = sock.recv(1)
    except OSError as exc:
        raise OciPidfdHandoffRefused("child manager unresponsive") from exc
    if answer != b"A":
        raise OciPidfdHandoffRefused("child manager denied attach")
    child_pid = _pidfd_pid(pinned_child_fd)
    if _current_cgroup(child_pid) != target:
        raise OciPidfdHandoffRefused("local pinned child cgroup readback failed")


def request_fixed_child_attach_at_endpoint(
    path: str | os.PathLike[str],
    *,
    pinned_child_fd: int,
    identity_plan: ContainmentServiceIdentityPlan,
    expected_local_target_cgroup: str,
) -> None:
    """Connect once as the verified post-drop agent and attach a pinned child.

    Only trusted launch code supplies the endpoint and expected cgroup. No
    client-selected target PID, manager write access or legacy attach fallback.
    """
    if not isinstance(identity_plan, ContainmentServiceIdentityPlan):
        raise TypeError("trusted OCI identity plan required")
    target = _cgroup_path(expected_local_target_cgroup)
    endpoint = identity_plan.endpoint_policy(path).path
    # Check our own post-drop identity before making any manager connection.
    require_linux_process_identity(identity_plan.host_agent_process_policy())
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as exc:
        raise OciPidfdHandoffRefused("cannot open OCI manager socket") from exc
    try:
        sock.set_inheritable(False)
        sock.settimeout(_TIMEOUT)
        sock.connect(os.fspath(endpoint))
        request_fixed_child_attach(
            sock,
            pinned_child_fd=pinned_child_fd,
            manager_peer_policy=identity_plan.host_agent_connect_peer_policy(),
            expected_local_target_cgroup=target,
        )
    except (OSError, ValueError) as exc:
        raise OciPidfdHandoffRefused("OCI manager connection refused") from exc
    finally:
        sock.close()
