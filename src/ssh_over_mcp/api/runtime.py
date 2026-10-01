from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import RuntimeConfigurationError

_MAX_KERNEL_ID = (1 << 32) - 1


class MCPRuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_path: Path
    credential_map_path: Path
    profile: str = Field(min_length=1)
    ledger_socket_path: Path
    ledger_server_uid: int = Field(strict=True, ge=0, le=_MAX_KERNEL_ID)
    ledger_server_gid: int = Field(strict=True, ge=0, le=_MAX_KERNEL_ID)
    port: int = Field(default=8000, ge=1, le=65535)

    @field_validator("ledger_socket_path")
    @classmethod
    def validate_ledger_socket_path(cls, value: Path) -> Path:
        path = Path(value)
        raw = os.fspath(path)
        if (
            "\x00" in raw
            or not path.is_absolute()
            or raw.startswith("//")
            or os.path.normpath(raw) != raw
        ):
            raise ValueError("ledger socket path must be absolute and canonical")
        return path


def load_runtime_settings(
    env: Mapping[str, str],
) -> MCPRuntimeSettings:
    config_value = env.get("SSH_OVER_MCP_CONFIG", "")
    credential_map_value = env.get("SSH_OVER_MCP_CREDENTIAL_MAP", "")
    profile_value = env.get("SSH_OVER_MCP_PROFILE", "")
    ledger_socket_value = env.get(
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH",
        "",
    )
    ledger_uid_value = env.get("SSH_OVER_MCP_LEDGER_SERVICE_UID", "")
    ledger_gid_value = env.get("SSH_OVER_MCP_LEDGER_SERVICE_GID", "")
    port_value = env.get("SSH_OVER_MCP_PORT", "8000")

    if (
        not config_value.strip()
        or not credential_map_value.strip()
        or not profile_value.strip()
        or not ledger_socket_value.strip()
        or not ledger_uid_value.strip()
        or not ledger_gid_value.strip()
    ):
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        )

    try:
        port = int(port_value, 10)
        ledger_uid = int(ledger_uid_value, 10)
        ledger_gid = int(ledger_gid_value, 10)
    except (TypeError, ValueError) as exc:
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from exc

    try:
        return MCPRuntimeSettings(
            config_path=Path(config_value),
            credential_map_path=Path(credential_map_value),
            profile=profile_value.strip(),
            ledger_socket_path=Path(ledger_socket_value),
            ledger_server_uid=ledger_uid,
            ledger_server_gid=ledger_gid,
            port=port,
        )
    except ValueError as exc:
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from exc
