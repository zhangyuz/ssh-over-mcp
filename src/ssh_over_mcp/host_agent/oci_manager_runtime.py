"""Fixed-source OCI manager service; no Docker/OCI boot or host changes.

Runs only inside separately verified, delegated, no-NIC manager container.
The guest provisions the node identity, ownership/mounts and socket parent.
No client chooses a PID, cgroup, command, endpoint or node.
"""

from __future__ import annotations

import select
from collections.abc import Callable

from .containment_manager_endpoint import (
    UnixContainmentManagerListener,
    UnixManagerEndpointPolicy,
)
from .containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
    require_linux_process_identity,
)
from .containment_manager_peer import (
    LinuxPeerCredentialPolicy,
    read_linux_unix_peer_credentials,
)
from .oci_child_attach import OciChildAttachPolicy, handle_fixed_child_attach
from .oci_child_writer import fixed_mvp_target, move_fixed_mvp_child
from .oci_namespace_identity import IdMapEntry
from .oci_pidfd_handoff import OciPidfdHandoffRefused
from .oci_source_migration import OciSourceDomain
from .oci_source_writer import serve_fixed_node_source_once

MANAGER_SOCKET = "/run/som/manager.sock"
MANAGER_UID = 2204
MANAGER_GID = 3204
MANAGER_CLIENT_GID = 3299
# Only valid after a guest proves the SSH root-phase peer's UID/GID mapping
# inside the manager container's user namespace. Fail closed otherwise.
ROOT_PHASE_PEER_UID = 0
ROOT_PHASE_PEER_GID = 0


class OciManagerRuntimeRefused(RuntimeError):
    """OCI manager trust boundary or service operation was not admitted."""


def _trusted_domain(node: str) -> OciSourceDomain:
    if node not in ("node01", "node02"):
        raise OciManagerRuntimeRefused("untrusted manager node")
    return OciSourceDomain(
        delegated_root=f"/som-mode-a/{node}",
        admission_cgroup=f"/som-mode-a/{node}/admission",
        agent_source_cgroup=f"/som-mode-a/{node}/host-agent-source",
    )


def serve_oci_source_manager(
    *,
    trusted_node: str,
    stop_requested: Callable[[], bool],
    identity_check: Callable[[LinuxProcessIdentityPolicy], object] = require_linux_process_identity,
    listener_factory: Callable[
        [UnixManagerEndpointPolicy], UnixContainmentManagerListener
    ] = UnixContainmentManagerListener.create,
    ready_to_accept: Callable[[int], bool] | None = None,
    peer_reader: Callable = read_linux_unix_peer_credentials,
    expected_child_uid_map: tuple[IdMapEntry, ...] | None = None,
    expected_child_gid_map: tuple[IdMapEntry, ...] | None = None,
) -> int:
    """Bind fixed ACL socket and serve sequential self-pidfd move requests.

    A denied/unknown operation terminates the manager (no retry). The guest
    must independently prove manager UID/GID maps, no-new-privileges, no caps,
    cgroup subtree delegation and PID lifetime before starting this process.
    """

    domain = _trusted_domain(trusted_node)
    if (expected_child_uid_map is None) != (expected_child_gid_map is None):
        raise OciManagerRuntimeRefused("both trusted child namespace maps are required")
    child_policy = None
    if expected_child_uid_map is not None:
        child_policy = OciChildAttachPolicy(
            domain=domain,
            target_cgroup=fixed_mvp_target(trusted_node),
            expected_child_uid_map=expected_child_uid_map,
            expected_child_gid_map=expected_child_gid_map,
        )
    identity_check(
        LinuxProcessIdentityPolicy(
            LinuxProcessIdentity(MANAGER_UID, MANAGER_GID),
            frozenset({MANAGER_CLIENT_GID}),
        )
    )
    endpoint = UnixManagerEndpointPolicy(
        path=MANAGER_SOCKET,
        directory_uid=MANAGER_UID,
        directory_gid=MANAGER_CLIENT_GID,
        socket_uid=MANAGER_UID,
        socket_gid=MANAGER_CLIENT_GID,
        socket_mode=0o660,
        backlog=4,
    )
    root_peer = LinuxPeerCredentialPolicy(
        expected_uid=ROOT_PHASE_PEER_UID,
        expected_gid=ROOT_PHASE_PEER_GID,
    )
    agent_peer = LinuxPeerCredentialPolicy(expected_uid=2202, expected_gid=3202)

    if ready_to_accept is None:

        def ready_to_accept(fd: int) -> bool:
            readable, _, _ = select.select([fd], [], [], 0.1)
            return bool(readable)

    served = 0
    child_slot_used = False  # one pre-provisioned MVP workload scope
    with listener_factory(endpoint) as listener:
        while not stop_requested():
            if not ready_to_accept(listener.fileno):
                continue
            if stop_requested():
                break
            with listener.accept() as sock:
                try:
                    credential = peer_reader(sock)
                    if (credential.uid, credential.gid) == (
                        ROOT_PHASE_PEER_UID,
                        ROOT_PHASE_PEER_GID,
                    ):
                        serve_fixed_node_source_once(
                            sock,
                            trusted_node=trusted_node,
                            domain=domain,
                            peer_policy=root_peer,
                        )
                    elif (credential.uid, credential.gid) == (
                        2202,
                        3202,
                    ) and child_policy is not None:
                        if child_slot_used:
                            raise OciPidfdHandoffRefused("one-slot OCI MVP scope already used")
                        child_slot_used = True  # reserve before uncertain write
                        handle_fixed_child_attach(
                            sock,
                            peer_policy=agent_peer,
                            policy=child_policy,
                            trusted_attach=lambda child: move_fixed_mvp_child(
                                child, trusted_node=trusted_node
                            ),
                        )
                    else:
                        raise OciPidfdHandoffRefused(
                            "untrusted OCI manager peer or child attach disabled"
                        )
                except (OciPidfdHandoffRefused, OSError, ValueError) as exc:
                    # Treat even prewrite client denial as fatal for initial
                    # isolated MVP; never accidentally replay uncertain write.
                    raise OciManagerRuntimeRefused(
                        "source manager operation denied; inspect before restart"
                    ) from exc
            served += 1
    return served
