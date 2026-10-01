from __future__ import annotations

from pathlib import Path

from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.approvals.client import SecurityLedgerClient
from ssh_over_mcp.host_agent.containment_manager_peer import (
    LinuxPeerCredentialPolicy,
)


def _settings() -> MCPRuntimeSettings:
    return MCPRuntimeSettings(
        config_path=Path("/etc/ssh-over-mcp/config.yaml"),
        credential_map_path=Path("/etc/ssh-over-mcp/credentials.yaml"),
        profile="developer",
        ledger_socket_path=Path("/run/ssh-over-mcp/ledger-exec.sock"),
        ledger_server_uid=2104,
        ledger_server_gid=3104,
        port=8000,
    )


def test_build_ledger_client_uses_server_owned_socket_and_peer_identity(
    monkeypatch,
) -> None:
    from ssh_over_mcp.api import ledger_runtime

    captured = {}

    class RecordingTransport:
        def __init__(
            self,
            socket_path,
            expected_server,
            *,
            timeout_seconds=2.0,
        ):
            captured["socket_path"] = socket_path
            captured["expected_server"] = expected_server
            captured["timeout_seconds"] = timeout_seconds

        def round_trip(self, frame):
            raise AssertionError("client construction must not contact ledger")

    monkeypatch.setattr(
        ledger_runtime,
        "UnixLedgerTransport",
        RecordingTransport,
    )

    client = ledger_runtime.build_ledger_client(_settings())

    assert isinstance(client, SecurityLedgerClient)
    assert captured == {
        "socket_path": Path("/run/ssh-over-mcp/ledger-exec.sock"),
        "expected_server": LinuxPeerCredentialPolicy(
            expected_uid=2104,
            expected_gid=3104,
        ),
        "timeout_seconds": 2.0,
    }
