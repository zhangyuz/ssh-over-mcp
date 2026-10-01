from __future__ import annotations

from ssh_over_mcp.approvals.client import SecurityLedgerClient
from ssh_over_mcp.approvals.transport import UnixLedgerTransport
from ssh_over_mcp.host_agent.containment_manager_peer import (
    LinuxPeerCredentialPolicy,
)

from .runtime import MCPRuntimeSettings


def build_ledger_client(
    settings: MCPRuntimeSettings,
) -> SecurityLedgerClient:
    transport = UnixLedgerTransport(
        settings.ledger_socket_path,
        LinuxPeerCredentialPolicy(
            expected_uid=settings.ledger_server_uid,
            expected_gid=settings.ledger_server_gid,
        ),
        timeout_seconds=2.0,
    )
    return SecurityLedgerClient(transport)
