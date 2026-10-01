from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .errors import RuntimeConfigurationError


class MCPRuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_path: Path
    credential_map_path: Path
    profile: str = Field(min_length=1)
    port: int = Field(default=8000, ge=1, le=65535)


def load_runtime_settings(
    env: Mapping[str, str],
) -> MCPRuntimeSettings:
    config_value = env.get("SSH_OVER_MCP_CONFIG", "")
    credential_map_value = env.get("SSH_OVER_MCP_CREDENTIAL_MAP", "")
    profile_value = env.get("SSH_OVER_MCP_PROFILE", "")
    port_value = env.get("SSH_OVER_MCP_PORT", "8000")

    if (
        not config_value.strip()
        or not credential_map_value.strip()
        or not profile_value.strip()
    ):
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        )

    try:
        port = int(port_value, 10)
    except (TypeError, ValueError) as exc:
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from exc

    try:
        return MCPRuntimeSettings(
            config_path=Path(config_value),
            credential_map_path=Path(credential_map_value),
            profile=profile_value.strip(),
            port=port,
        )
    except ValueError as exc:
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from exc
