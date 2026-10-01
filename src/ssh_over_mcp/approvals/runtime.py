from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    UnixManagerEndpointPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_peer import (
    LinuxPeerCredentialPolicy,
)

from .storage import LedgerStorageSettings

_PREFIX = "SSH_OVER_MCP_LEDGER_"


def _required(env: Mapping[str, str], name: str) -> str:
    key = _PREFIX + name
    value = env.get(key)
    if value is None or value == "":
        raise ValueError(f"missing Security Ledger environment value: {key}")
    return value


def _decimal(env: Mapping[str, str], name: str) -> int:
    raw = _required(env, name)
    try:
        value = int(raw, 10)
    except ValueError:
        raise ValueError(
            f"invalid Security Ledger integer environment value: {_PREFIX + name}"
        ) from None
    return value


def _mode(env: Mapping[str, str], name: str) -> int:
    raw = _required(env, name)
    if len(raw) != 4 or raw[0] != "0" or any(ch not in "01234567" for ch in raw):
        raise ValueError(
            f"invalid Security Ledger mode environment value: {_PREFIX + name}"
        )
    return int(raw, 8)


@dataclass(frozen=True, slots=True)
class SecurityLedgerRuntimeSettings:
    db_path: Path
    hmac_key_path: Path
    service_uid: int
    service_gid: int
    execution_socket_path: Path
    execution_socket_gid: int
    execution_socket_mode: int
    execution_peer_uid: int
    execution_peer_gid: int
    admin_socket_path: Path
    admin_socket_gid: int
    admin_socket_mode: int
    admin_peer_uid: int
    admin_peer_gid: int
    busy_timeout_ms: int = 2000

    def __post_init__(self) -> None:
        object.__setattr__(self, "db_path", Path(self.db_path))
        object.__setattr__(self, "hmac_key_path", Path(self.hmac_key_path))
        object.__setattr__(
            self,
            "execution_socket_path",
            Path(self.execution_socket_path),
        )
        object.__setattr__(
            self,
            "admin_socket_path",
            Path(self.admin_socket_path),
        )
        if self.execution_socket_path == self.admin_socket_path:
            raise ValueError("Security Ledger socket paths must be distinct")
        # Construct every derived policy once to fail settings validation
        # before the service touches storage or creates a listener.
        self.storage_settings()
        self.process_identity_policy()
        self.execution_endpoint_policy()
        self.admin_endpoint_policy()
        self.execution_peer_policy()
        self.admin_peer_policy()

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> SecurityLedgerRuntimeSettings:
        source = os.environ if env is None else env
        return cls(
            db_path=Path(_required(source, "DB_PATH")),
            hmac_key_path=Path(_required(source, "HMAC_KEY_PATH")),
            service_uid=_decimal(source, "SERVICE_UID"),
            service_gid=_decimal(source, "SERVICE_GID"),
            execution_socket_path=Path(
                _required(source, "EXEC_SOCKET_PATH")
            ),
            execution_socket_gid=_decimal(source, "EXEC_SOCKET_GID"),
            execution_socket_mode=_mode(source, "EXEC_SOCKET_MODE"),
            execution_peer_uid=_decimal(source, "EXEC_PEER_UID"),
            execution_peer_gid=_decimal(source, "EXEC_PEER_GID"),
            admin_socket_path=Path(
                _required(source, "ADMIN_SOCKET_PATH")
            ),
            admin_socket_gid=_decimal(source, "ADMIN_SOCKET_GID"),
            admin_socket_mode=_mode(source, "ADMIN_SOCKET_MODE"),
            admin_peer_uid=_decimal(source, "ADMIN_PEER_UID"),
            admin_peer_gid=_decimal(source, "ADMIN_PEER_GID"),
            busy_timeout_ms=int(
                source.get(_PREFIX + "BUSY_TIMEOUT_MS", "2000"),
                10,
            ),
        )

    def storage_settings(self) -> LedgerStorageSettings:
        return LedgerStorageSettings(
            db_path=self.db_path,
            hmac_key_path=self.hmac_key_path,
            service_uid=self.service_uid,
            service_gid=self.service_gid,
            busy_timeout_ms=self.busy_timeout_ms,
        )

    def process_identity_policy(self) -> LinuxProcessIdentityPolicy:
        supplementary = {
            self.execution_socket_gid,
            self.admin_socket_gid,
        } - {self.service_gid}
        return LinuxProcessIdentityPolicy(
            identity=LinuxProcessIdentity(
                uid=self.service_uid,
                gid=self.service_gid,
            ),
            supplementary_gids=frozenset(supplementary),
        )

    def execution_endpoint_policy(self) -> UnixManagerEndpointPolicy:
        return UnixManagerEndpointPolicy(
            path=self.execution_socket_path,
            directory_uid=self.service_uid,
            directory_gid=self.execution_socket_gid,
            socket_uid=self.service_uid,
            socket_gid=self.execution_socket_gid,
            socket_mode=self.execution_socket_mode,
        )

    def admin_endpoint_policy(self) -> UnixManagerEndpointPolicy:
        return UnixManagerEndpointPolicy(
            path=self.admin_socket_path,
            directory_uid=self.service_uid,
            directory_gid=self.admin_socket_gid,
            socket_uid=self.service_uid,
            socket_gid=self.admin_socket_gid,
            socket_mode=self.admin_socket_mode,
        )

    def execution_peer_policy(self) -> LinuxPeerCredentialPolicy:
        return LinuxPeerCredentialPolicy(
            expected_uid=self.execution_peer_uid,
            expected_gid=self.execution_peer_gid,
        )

    def admin_peer_policy(self) -> LinuxPeerCredentialPolicy:
        return LinuxPeerCredentialPolicy(
            expected_uid=self.admin_peer_uid,
            expected_gid=self.admin_peer_gid,
        )

    def ledger_server_peer_policy(self) -> LinuxPeerCredentialPolicy:
        return LinuxPeerCredentialPolicy(
            expected_uid=self.service_uid,
            expected_gid=self.service_gid,
        )
