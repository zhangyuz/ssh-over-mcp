from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .containment import ContainmentError, ContainmentUnavailableError
from .containment_manager_endpoint import UnixManagerEndpointPolicy
from .containment_manager_peer import LinuxPeerCredentialPolicy

_MAX_KERNEL_ID = (1 << 32) - 1


class LinuxProcessIdentityError(ContainmentError):
    """The current process does not match its configured Linux identity."""


@dataclass(frozen=True, slots=True)
class LinuxProcessIdentity:
    uid: int
    gid: int

    def __post_init__(self) -> None:
        _validate_kernel_id(self.uid, "uid")
        _validate_kernel_id(self.gid, "gid")


@dataclass(frozen=True, slots=True)
class LinuxProcessIdentitySnapshot:
    real_uid: int
    effective_uid: int
    saved_uid: int
    real_gid: int
    effective_gid: int
    saved_gid: int
    supplementary_gids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LinuxProcessIdentityPolicy:
    identity: LinuxProcessIdentity
    supplementary_gids: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        values = frozenset(self.supplementary_gids)
        for value in values:
            _validate_kernel_id(value, "supplementary_gid")
        object.__setattr__(self, "supplementary_gids", values)


@dataclass(frozen=True, slots=True)
class ContainmentServiceIdentityPlan:
    """Production identity contract for manager, host agent, and workload."""

    manager: LinuxProcessIdentity
    host_agent: LinuxProcessIdentity
    workload: LinuxProcessIdentity
    manager_client_gid: int

    def __post_init__(self) -> None:
        _validate_kernel_id(self.manager_client_gid, "manager_client_gid")

        if self.host_agent.uid == 0 or self.host_agent.gid == 0:
            raise ValueError("host-agent identity must be non-root")
        if self.workload.uid == 0 or self.workload.gid == 0:
            raise ValueError("workload identity must be non-root")
        if self.manager_client_gid == 0:
            raise ValueError("manager client GID must be non-root")

        uids = {
            self.manager.uid,
            self.host_agent.uid,
            self.workload.uid,
        }
        if len(uids) != 3:
            raise ValueError(
                "manager, host-agent, and workload UIDs must be distinct"
            )

        if self.manager_client_gid == self.workload.gid:
            raise ValueError(
                "workload primary GID must not equal manager client GID"
            )

    def manager_process_policy(self) -> LinuxProcessIdentityPolicy:
        supplementary = set()
        if self.manager_client_gid != self.manager.gid:
            supplementary.add(self.manager_client_gid)
        return LinuxProcessIdentityPolicy(
            identity=self.manager,
            supplementary_gids=frozenset(supplementary),
        )

    def host_agent_process_policy(self) -> LinuxProcessIdentityPolicy:
        supplementary = set()
        if self.manager_client_gid != self.host_agent.gid:
            supplementary.add(self.manager_client_gid)
        return LinuxProcessIdentityPolicy(
            identity=self.host_agent,
            supplementary_gids=frozenset(supplementary),
        )

    def workload_process_policy(self) -> LinuxProcessIdentityPolicy:
        return LinuxProcessIdentityPolicy(
            identity=self.workload,
            supplementary_gids=frozenset(),
        )

    def manager_accept_peer_policy(self) -> LinuxPeerCredentialPolicy:
        return LinuxPeerCredentialPolicy(
            expected_uid=self.host_agent.uid,
            expected_gid=self.host_agent.gid,
        )

    def host_agent_connect_peer_policy(self) -> LinuxPeerCredentialPolicy:
        return LinuxPeerCredentialPolicy(
            expected_uid=self.manager.uid,
            expected_gid=self.manager.gid,
        )

    def endpoint_policy(
        self,
        path: str | Path,
        *,
        socket_mode: int = 0o660,
        backlog: int = 16,
    ) -> UnixManagerEndpointPolicy:
        return UnixManagerEndpointPolicy(
            path=Path(path),
            directory_uid=self.manager.uid,
            directory_gid=self.manager_client_gid,
            socket_uid=self.manager.uid,
            socket_gid=self.manager_client_gid,
            socket_mode=socket_mode,
            backlog=backlog,
        )


def _validate_kernel_id(value: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_KERNEL_ID
    ):
        raise ValueError(f"{label} must be a valid Linux uid/gid value")


def read_linux_process_identity() -> LinuxProcessIdentitySnapshot:
    """Read real/effective/saved IDs plus supplementary groups."""

    for name in ("getresuid", "getresgid", "getgroups"):
        if not hasattr(os, name):
            raise ContainmentUnavailableError(
                "required Linux process identity API is unavailable"
            )

    try:
        real_uid, effective_uid, saved_uid = os.getresuid()
        real_gid, effective_gid, saved_gid = os.getresgid()
        supplementary = tuple(sorted(set(os.getgroups())))
    except OSError as exc:
        raise ContainmentUnavailableError(
            "cannot read Linux process identity"
        ) from exc

    return LinuxProcessIdentitySnapshot(
        real_uid=real_uid,
        effective_uid=effective_uid,
        saved_uid=saved_uid,
        real_gid=real_gid,
        effective_gid=effective_gid,
        saved_gid=saved_gid,
        supplementary_gids=supplementary,
    )


def require_linux_process_identity(
    policy: LinuxProcessIdentityPolicy,
) -> LinuxProcessIdentitySnapshot:
    """Fail closed unless all Linux process credentials match exactly."""

    snapshot = read_linux_process_identity()
    expected = policy.identity

    if (
        snapshot.real_uid != expected.uid
        or snapshot.effective_uid != expected.uid
        or snapshot.saved_uid != expected.uid
        or snapshot.real_gid != expected.gid
        or snapshot.effective_gid != expected.gid
        or snapshot.saved_gid != expected.gid
    ):
        raise LinuxProcessIdentityError(
            "process identity does not match policy"
        )

    observed_supplementary = (
        set(snapshot.supplementary_gids) - {expected.gid}
    )
    if observed_supplementary != set(policy.supplementary_gids):
        raise LinuxProcessIdentityError(
            "process supplementary groups do not match policy"
        )

    return snapshot
