from __future__ import annotations

from pathlib import Path

import pytest


def _env(root: Path) -> dict[str, str]:
    return {
        "SSH_OVER_MCP_LEDGER_DB_PATH": str(root / "data" / "ledger.db"),
        "SSH_OVER_MCP_LEDGER_HMAC_KEY_PATH": str(root / "data" / "ledger.key"),
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": "1001",
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": "1002",
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": str(root / "exec" / "ledger.sock"),
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_GID": "2001",
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_MODE": "0660",
        "SSH_OVER_MCP_LEDGER_EXEC_PEER_UID": "3001",
        "SSH_OVER_MCP_LEDGER_EXEC_PEER_GID": "3002",
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": str(root / "admin" / "ledger.sock"),
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_GID": "4001",
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_MODE": "0660",
        "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID": "5001",
        "SSH_OVER_MCP_LEDGER_ADMIN_PEER_GID": "5002",
        "SSH_OVER_MCP_LEDGER_BUSY_TIMEOUT_MS": "2500",
    }


def test_runtime_settings_parse_exact_policies(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings

    settings = SecurityLedgerRuntimeSettings.from_env(_env(tmp_path))

    assert settings.service_uid == 1001
    assert settings.service_gid == 1002
    assert settings.storage_settings().busy_timeout_ms == 2500
    assert settings.process_identity_policy().identity.uid == 1001
    assert settings.process_identity_policy().identity.gid == 1002
    assert settings.process_identity_policy().supplementary_gids == frozenset(
        {2001, 4001}
    )

    execution = settings.execution_endpoint_policy()
    assert execution.path == tmp_path / "exec" / "ledger.sock"
    assert execution.directory_uid == 1001
    assert execution.directory_gid == 2001
    assert execution.socket_uid == 1001
    assert execution.socket_gid == 2001
    assert execution.socket_mode == 0o660

    admin = settings.admin_endpoint_policy()
    assert admin.directory_gid == 4001
    assert admin.socket_gid == 4001
    assert settings.execution_peer_policy().expected_uid == 3001
    assert settings.execution_peer_policy().expected_gid == 3002
    assert settings.admin_peer_policy().expected_uid == 5001
    assert settings.admin_peer_policy().expected_gid == 5002


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SSH_OVER_MCP_LEDGER_SERVICE_UID", "-1"),
        ("SSH_OVER_MCP_LEDGER_EXEC_SOCKET_MODE", "0777"),
        ("SSH_OVER_MCP_LEDGER_BUSY_TIMEOUT_MS", "0"),
    ],
)
def test_runtime_settings_reject_invalid_environment(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings

    env = _env(tmp_path)
    env[key] = value
    with pytest.raises(ValueError):
        SecurityLedgerRuntimeSettings.from_env(env)


def test_runtime_settings_require_all_security_fields(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings

    env = _env(tmp_path)
    del env["SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID"]
    with pytest.raises(ValueError, match="missing"):
        SecurityLedgerRuntimeSettings.from_env(env)
