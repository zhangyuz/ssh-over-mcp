"""OCI-only fixed SSH admission handoff, never the managed-host launcher.

This trusted root-phase orchestration checks the OCI login identity, asks a
separate manager to move ONLY the launcher's own pidfd, closes that root
socket, and verifies an exact two-capability nonroot UID/GID drop BEFORE
application import. No cgroupfs writes, shell, secret reads or container
start. The executable OCI entrypoint and kernel delegation remain gated.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .containment_manager_peer import LinuxPeerCredentialPolicy
from .oci_pidfd_handoff import OciPidfdHandoffRefused
from .oci_source_migration import request_fixed_source_move

SSH_ACCOUNT_UID = 2201
SSH_ACCOUNT_GID = 3201
AGENT_UID = 2202
AGENT_GID = 3202
MANAGER_UID = 2204
MANAGER_GID = 3204
MANAGER_CLIENT_GID = 3299
TRUSTED_AGENT_CAP_MASK = (1 << 6) | (1 << 7)
MANAGER_SOCKET = "/run/som/manager.sock"


class OciAdmissionRefused(RuntimeError):
    """The fixed container identity/source transition did not verify."""


@dataclass(frozen=True, slots=True)
class OciLauncherDomain:
    """Trusted guest-provisioned node identity, never client-supplied input."""

    node: str
    expected_source_cgroup: str

    @classmethod
    def for_node(cls, node: str) -> OciLauncherDomain:
        if not isinstance(node, str) or node not in ("node01", "node02"):
            raise ValueError("invalid trusted OCI node identity")
        return cls(node, f"/som-mode-a/{node}/host-agent-source")


@dataclass(frozen=True, slots=True)
class OciAdmissionSnapshot:
    uid: int
    euid: int
    suid: int
    gid: int
    egid: int
    sgid: int
    supplementary_gids: tuple[int, ...]
    cap_inheritable: int
    cap_permitted: int
    cap_effective: int
    cap_ambient: int


class OciAdmissionOps(Protocol):
    def effective_uid(self) -> int: ...
    def set_keepcaps(self, flag: bool) -> None: ...
    def set_groups(self, groups: tuple[int, ...]) -> None: ...
    def set_res_gid(self, gid: int) -> None: ...
    def set_res_uid(self, uid: int) -> None: ...
    def set_capabilities(self, mask: int) -> None: ...
    def clear_ambient_capabilities(self) -> None: ...
    def snapshot(self) -> OciAdmissionSnapshot: ...


class RootManagerStream(Protocol):
    def close(self) -> None: ...


def sanitized_oci_environment(env: Mapping[str, str]) -> dict[str, str]:
    """Refuse wrong sudo/SSH origin and discard all SSH-controlled extras."""

    required = {
        "SSH_ORIGINAL_COMMAND": "mcp-v1",
        "SUDO_USER": "ssh-over-mcp-e2e-host",
        "SUDO_UID": str(SSH_ACCOUNT_UID),
        "SUDO_GID": str(SSH_ACCOUNT_GID),
    }
    if any(env.get(key) != value for key, value in required.items()):
        raise OciAdmissionRefused("invalid fixed OCI ForceCommand identity")
    if env.get("SSH_TTY", ""):
        raise OciAdmissionRefused("OCI TTY is not permitted")
    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": required["SUDO_USER"],
        "PATH": "/usr/bin:/bin",
        "SSH_ORIGINAL_COMMAND": required["SSH_ORIGINAL_COMMAND"],
        "USER": required["SUDO_USER"],
    }


def admit_oci_source_before_application(
    *,
    argv: Sequence[str],
    env: Mapping[str, str],
    domain: OciLauncherDomain,
    ops: OciAdmissionOps,
    connect_manager: Callable[[str], RootManagerStream],
) -> dict[str, str]:
    """Execute the fixed pre-import gate; no application import or cgroup write.

    The trusted guest boot supplies the domain and a *fresh*, node-local,
    root-phase manager connector. Client-controlled env never selects nodes
    or cgroup paths. Runtime peer UID mappings and PID/cgroup attach must be
    independently verified before wiring this into a live launcher.
    """

    if tuple(argv):
        raise OciAdmissionRefused("OCI launcher does not accept arguments")
    if not isinstance(domain, OciLauncherDomain) or domain != OciLauncherDomain.for_node(
        domain.node
    ):
        raise OciAdmissionRefused("untrusted OCI source domain")
    clean_env = sanitized_oci_environment(env)
    if ops.effective_uid() != 0:
        raise OciAdmissionRefused("OCI launcher is not root at admission")

    stream = None
    try:
        stream = connect_manager(MANAGER_SOCKET)
        request_fixed_source_move(
            stream,
            manager_peer_policy=LinuxPeerCredentialPolicy(
                expected_uid=MANAGER_UID, expected_gid=MANAGER_GID
            ),
            expected_source_cgroup=domain.expected_source_cgroup,
        )
    except (OciPidfdHandoffRefused, OSError, ValueError, RuntimeError) as exc:
        raise OciAdmissionRefused("OCI source manager handoff refused") from exc
    finally:
        if stream is not None:
            # A root-authenticated SO_PEERCRED socket must NEVER survive the
            # UID drop. A failed close aborts prior to privilege transition.
            try:
                stream.close()
            except OSError as exc:
                raise OciAdmissionRefused("cannot close root-phase manager FD") from exc

    try:
        ops.set_keepcaps(True)
        ops.set_groups((MANAGER_CLIENT_GID,))
        ops.set_res_gid(AGENT_GID)
        ops.set_res_uid(AGENT_UID)
        ops.set_capabilities(TRUSTED_AGENT_CAP_MASK)
        ops.clear_ambient_capabilities()
        ops.set_keepcaps(False)
        state = ops.snapshot()
    except (OSError, ValueError, RuntimeError) as exc:
        raise OciAdmissionRefused("OCI trusted-agent privilege transition refused") from exc

    if (
        not isinstance(state, OciAdmissionSnapshot)
        or (state.uid, state.euid, state.suid, state.gid, state.egid, state.sgid)
        != (AGENT_UID, AGENT_UID, AGENT_UID, AGENT_GID, AGENT_GID, AGENT_GID)
        or (
            state.supplementary_gids != (MANAGER_CLIENT_GID,)
            or state.cap_inheritable != 0
            or state.cap_permitted != TRUSTED_AGENT_CAP_MASK
            or state.cap_effective != TRUSTED_AGENT_CAP_MASK
            or state.cap_ambient != 0
        )
    ):
        raise OciAdmissionRefused("OCI trusted-agent post-drop state is invalid")
    return clean_env
