from __future__ import annotations

from pathlib import Path

import pytest

from ssh_over_mcp.api.errors import RuntimeConfigurationError
from ssh_over_mcp.api.runtime import MCPRuntimeSettings, load_runtime_settings


def test_runtime_settings_load_required_values_and_default_port() -> None:
    settings = load_runtime_settings(
        {
            "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
            "SSH_OVER_MCP_PROFILE": "developer",
        }
    )

    assert settings == MCPRuntimeSettings(
        config_path=Path("/etc/ssh-over-mcp/config.yaml"),
        profile="developer",
        port=8000,
    )


def test_runtime_settings_accept_explicit_valid_port() -> None:
    settings = load_runtime_settings(
        {
            "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
            "SSH_OVER_MCP_PROFILE": "developer",
            "SSH_OVER_MCP_PORT": "9123",
        }
    )

    assert settings.port == 9123


@pytest.mark.parametrize(
    "env",
    [
        {
            "SSH_OVER_MCP_PROFILE": "developer",
        },
        {
            "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
        },
        {
            "SSH_OVER_MCP_CONFIG": "",
            "SSH_OVER_MCP_PROFILE": "developer",
        },
        {
            "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
            "SSH_OVER_MCP_PROFILE": " ",
        },
    ],
)
def test_runtime_settings_reject_missing_or_blank_required_values(
    env: dict[str, str],
) -> None:
    with pytest.raises(
        RuntimeConfigurationError,
        match="runtime configuration is invalid",
    ):
        load_runtime_settings(env)


@pytest.mark.parametrize("port", ["0", "65536", "-1", "abc", "1.5", ""])
def test_runtime_settings_reject_invalid_port(port: str) -> None:
    with pytest.raises(
        RuntimeConfigurationError,
        match="runtime configuration is invalid",
    ):
        load_runtime_settings(
            {
                "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
                "SSH_OVER_MCP_PROFILE": "developer",
                "SSH_OVER_MCP_PORT": port,
                "UNRELATED_SECRET": "must-not-appear",
            }
        )


def test_runtime_configuration_error_does_not_echo_environment() -> None:
    with pytest.raises(RuntimeConfigurationError) as exc_info:
        load_runtime_settings(
            {
                "SSH_OVER_MCP_CONFIG": "",
                "SSH_OVER_MCP_PROFILE": "developer",
                "UNRELATED_SECRET": "super-secret-value",
            }
        )

    assert "super-secret-value" not in str(exc_info.value)
    assert "UNRELATED_SECRET" not in str(exc_info.value)
