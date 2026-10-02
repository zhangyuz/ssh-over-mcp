from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.approvals.binding import fingerprint_argv
from ssh_over_mcp.approvals.dispatcher import (
    AdminLedgerDispatcher,
    ExecutionLedgerDispatcher,
)
from ssh_over_mcp.approvals.ledger import SecurityLedgerStore
from ssh_over_mcp.approvals.models import ApprovalBindingInput
from ssh_over_mcp.approvals.protocol import (
    AppendAuditRequest,
    ConsumeApprovalRequest,
    DenyApprovalRequest,
    EnsureApprovalRequest,
    ErrorResponse,
    GrantApprovalRequest,
    ListApprovalsRequest,
)
from ssh_over_mcp.approvals.storage import LedgerDatabase, LedgerStorageSettings
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentials
from ssh_over_mcp.policy.models import RiskLevel


def _store(tmp_path: Path) -> tuple[LedgerDatabase, SecurityLedgerStore]:
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    key = root / "ledger.key"
    key.write_bytes(b"K" * 32)
    os.chmod(key, 0o600)
    info = root.stat()
    database = LedgerDatabase.open(
        LedgerStorageSettings(
            db_path=root / "ledger.db",
            hmac_key_path=key,
            service_uid=info.st_uid,
            service_gid=info.st_gid,
        )
    )
    return database, SecurityLedgerStore(
        database,
        b"K" * 32,
        clock=lambda: datetime(2026, 10, 2, 11, 0, tzinfo=UTC),
    )


def _binding() -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        privilege="user",
        policy_version="sha256:phase5",
        normalized_path="/srv/app/new",
        argv_count=0,
        argv_fingerprint=fingerprint_argv(()),
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
    )


def _peer() -> LinuxPeerCredentials:
    return LinuxPeerCredentials(pid=1234, uid=2001, gid=3001)


def _event() -> AuditEventInput:
    return AuditEventInput(
        event_type=AuditEventType.REQUEST_RECEIVED,
        request_id="req_" + ("1" * 32),
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
    )


def test_execution_and_admin_dispatchers_enforce_disjoint_authority(
    tmp_path: Path,
) -> None:
    database, store = _store(tmp_path)
    execution = ExecutionLedgerDispatcher(store)
    admin = AdminLedgerDispatcher(store)
    binding = _binding()
    try:
        execution_forbidden = (
            GrantApprovalRequest(
                message_id="msg_" + ("1" * 32),
                approval_id="apr_" + ("2" * 32),
            ),
            DenyApprovalRequest(
                message_id="msg_" + ("3" * 32),
                approval_id="apr_" + ("4" * 32),
            ),
            ListApprovalsRequest(
                message_id="msg_" + ("5" * 32),
                limit=10,
            ),
        )
        for request in execution_forbidden:
            response = execution.dispatch(request, peer=_peer())
            assert isinstance(response, ErrorResponse)
            assert response.code == "not_authorized"

        admin_forbidden = (
            AppendAuditRequest(
                message_id="msg_" + ("6" * 32),
                event=_event(),
            ),
            EnsureApprovalRequest(
                message_id="msg_" + ("7" * 32),
                request_id="req_" + ("8" * 32),
                binding=binding,
                risk=RiskLevel.HIGH,
            ),
            ConsumeApprovalRequest(
                message_id="msg_" + ("9" * 32),
                request_id="req_" + ("a" * 32),
                approval_id="apr_" + ("b" * 32),
                binding=binding,
            ),
        )
        for request in admin_forbidden:
            response = admin.dispatch(request, peer=_peer())
            assert isinstance(response, ErrorResponse)
            assert response.code == "not_authorized"
    finally:
        database.close()


class _AuditLedger:
    async def append_audit(self, event) -> str:
        return "evt_" + ("0" * 32)


class _PrincipalProvider:
    def get_principal(self) -> PrincipalContext:
        return PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        )


@pytest.mark.asyncio
async def test_mcp_registry_has_only_phase5_public_authority() -> None:
    server = build_mcp_server(
        service=object(),
        principal_provider=_PrincipalProvider(),
        audit=AuditRecorder(_AuditLedger()),
    )
    async with Client(server) as client:
        listed = await client.list_tools()

    tools = {tool.name: tool for tool in listed.tools}
    assert set(tools) == {
        "hosts_list",
        "host_info",
        "policy_explain",
        "approval_status",
        "ssh_exec",
        "fs_stat",
        "fs_read",
        "fs_mkdir",
        "fs_write",
    }
    for forbidden in (
        "grant",
        "deny",
        "approval_grant",
        "approval_deny",
        "audit_query",
        "ssh_shell",
        "fs_move",
        "fs_delete",
    ):
        assert forbidden not in tools

    assert set(tools["approval_status"].input_schema["properties"]) == {
        "approval_id"
    }
    for name in ("ssh_exec", "fs_stat", "fs_read", "fs_mkdir", "fs_write"):
        properties = tools[name].input_schema["properties"]
        assert "approval_id" in properties
        schema_text = repr(tools[name].input_schema)
        for forbidden in (
            "grant",
            "deny",
            "ttl",
            "binding_hmac",
            "operator_identity",
            "profile",
            "credential_ref",
            "host_key",
        ):
            assert forbidden not in schema_text


def test_mcp_runtime_has_socket_identity_only_not_ledger_storage_authority() -> None:
    assert set(MCPRuntimeSettings.model_fields) == {
        "config_path",
        "credential_map_path",
        "profile",
        "ledger_socket_path",
        "ledger_server_uid",
        "ledger_server_gid",
        "port",
    }

    base = {
        "config_path": Path("/etc/ssh-over-mcp/config.yaml"),
        "credential_map_path": Path("/etc/ssh-over-mcp/credentials.yaml"),
        "profile": "developer",
        "ledger_socket_path": Path("/run/ssh-over-mcp/execution.sock"),
        "ledger_server_uid": 1001,
        "ledger_server_gid": 1001,
    }
    for forbidden_field in ("ledger_db_path", "hmac_key_path"):
        with pytest.raises(ValidationError):
            MCPRuntimeSettings(
                **base,
                **{forbidden_field: Path("/run/secret")},
            )
