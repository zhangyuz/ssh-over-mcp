from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
    bind_host: Literal["127.0.0.1", "0.0.0.0"] = "127.0.0.1"
    origin_bearer_token_file: Path | None = None
    port: int = Field(default=8000, ge=1, le=65535)

    @field_validator("ledger_socket_path")
    @classmethod
    def validate_ledger_socket_path(cls, value: Path) -> Path:
        return _validate_absolute_canonical_path(value, "ledger socket")

    @field_validator("origin_bearer_token_file")
    @classmethod
    def validate_origin_bearer_token_file(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        return _validate_absolute_canonical_path(value, "origin bearer token file")

    @model_validator(mode="after")
    def require_origin_auth_for_private_bind(self) -> Self:
        if self.bind_host == "0.0.0.0" and self.origin_bearer_token_file is None:
            raise ValueError("origin bearer token file is required for private bind")
        return self


def _validate_absolute_canonical_path(value: Path, label: str) -> Path:
    path = Path(value)
    raw = os.fspath(path)
    if (
        "\x00" in raw
        or not path.is_absolute()
        or raw.startswith("//")
        or os.path.normpath(raw) != raw
    ):
        raise ValueError(f"{label} path must be absolute and canonical")
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
    bind_host_value = env.get("SSH_OVER_MCP_BIND_HOST", "127.0.0.1")
    origin_token_file_value = env.get("SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE")
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

    origin_token_file = (
        None
        if origin_token_file_value is None or not origin_token_file_value.strip()
        else Path(origin_token_file_value)
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
            bind_host=bind_host_value,
            origin_bearer_token_file=origin_token_file,
            port=port,
        )
    except ValueError as exc:
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from exc
