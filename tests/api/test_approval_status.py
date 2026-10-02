from __future__ import annotations

from datetime import UTC, datetime

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api import models
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.approvals.client import LedgerRemoteError
from ssh_over_mcp.approvals.models import (
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.models import RiskLevel

APR_ID = "apr_" + ("a" * 32)


def _status(
    *,
    state: ApprovalState = ApprovalState.PENDING,
    approval_id: str = APR_ID,
) -> ApprovalStatus:
    return ApprovalStatus(
        approval_id=approval_id,
        state=state,
        expires_at=datetime(2026, 10, 1, 18, 10, tzinfo=UTC),
        host="visible",
        tool="ssh_exec",
        risk=RiskLevel.HIGH,
        safe_summary=ApprovalSafeSummary(
            principal_id="static:developer",
            profile="developer",
            host="visible",
            tool="ssh_exec",
            privilege="user",
            policy_version="sha256:public",
            risk=RiskLevel.HIGH,
            normalized_executable="/usr/bin/git",
            normalized_cwd="/srv/app",
            normalized_path=None,
            argv_count=1,
            argv_fingerprint="sha256:" + ("1" * 64),
            env_names=("LANG",),
            stdin_length=5,
            stdin_fingerprint="sha256:" + ("2" * 64),
            content_length=None,
            content_fingerprint=None,
            effective_timeout_seconds=30.0,
            effective_max_output_bytes=1024 * 1024,
            effective_max_stdin_bytes=1024 * 1024,
            effective_tool_bytes=None,
        ),
        binding_fingerprint="hmac-sha256:v1:" + ("3" * 16),
    )


def _context() -> OperationContext:
    return OperationContext(
        request_id="req_" + ("1" * 32),
        principal=models.PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


class RecordingApprovalClient:
    def __init__(
        self,
        *,
        status: ApprovalStatus | None = None,
        error: Exception | None = None,
    ) -> None:
        self.status = status or _status()
        self.error = error
        self.calls = []

    async def approval_status(
        self,
        *,
        approval_id: str,
        principal_id: str,
        profile: str,
    ) -> ApprovalStatus:
        self.calls.append((approval_id, principal_id, profile))
        if self.error is not None:
            raise self.error
        return self.status


def _service(client: RecordingApprovalClient) -> MCPService:
    inventory = Inventory(
        hosts={
            "visible": Host(
                address="10.0.0.1",
                port=22,
                ssh_user="user",
                credential_ref="secret://visible",
                host_key="test-host-key",
            )
        }
    )
    return MCPService(
        inventory=inventory,
        policy=object(),
        approval_client=client,
    )


def test_approval_status_models_are_strict_and_bounded() -> None:
    request = models.ApprovalStatusRequest(approval_id=APR_ID)
    assert request.approval_id == APR_ID

    with pytest.raises(ValidationError):
        models.ApprovalStatusRequest(approval_id="apr_SUPERSECRET")
    with pytest.raises(ValidationError):
        models.ApprovalStatusRequest(
            approval_id=APR_ID,
            grant=True,
        )

    result = models.ApprovalStatusResult(**_status().model_dump())
    assert result.state is ApprovalState.PENDING
    assert result.expires_at.tzinfo is UTC
    assert result.binding_fingerprint == "hmac-sha256:v1:" + ("3" * 16)


@pytest.mark.asyncio
async def test_approval_status_uses_trusted_principal_scope() -> None:
    client = RecordingApprovalClient()
    service = _service(client)

    result = await service.approval_status(
        _context(),
        models.ApprovalStatusRequest(approval_id=APR_ID),
    )

    assert client.calls == [
        (APR_ID, "static:developer", "developer"),
    ]
    assert result.approval_id == APR_ID
    assert result.safe_summary.profile == "developer"


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["not_found", "not_authorized"])
async def test_approval_status_hidden_and_unknown_are_indistinguishable(
    code: str,
) -> None:
    service = _service(
        RecordingApprovalClient(error=LedgerRemoteError(code))
    )

    with pytest.raises(
        api_errors.ApprovalNotVisibleError,
        match="approval is not visible",
    ) as exc_info:
        await service.approval_status(
            _context(),
            models.ApprovalStatusRequest(approval_id=APR_ID),
        )

    assert str(exc_info.value) == "approval is not visible"
    assert code not in str(exc_info.value)


@pytest.mark.asyncio
async def test_approval_status_returns_visible_expired_state() -> None:
    service = _service(
        RecordingApprovalClient(status=_status(state=ApprovalState.EXPIRED))
    )

    result = await service.approval_status(
        _context(),
        models.ApprovalStatusRequest(approval_id=APR_ID),
    )

    assert result.state is ApprovalState.EXPIRED


class _AuditLedger:
    async def append_audit(self, event) -> str:
        return "evt_" + ("0" * 32)


def _audit() -> AuditRecorder:
    return AuditRecorder(_AuditLedger())


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        )


class RecordingStatusService:
    def __init__(self) -> None:
        self.calls = []

    async def approval_status(
        self,
        context: OperationContext,
        request,
    ):
        self.calls.append((context, request))
        return models.ApprovalStatusResult(**_status().model_dump())


def _tool_error_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


@pytest.mark.asyncio
async def test_server_registers_read_only_approval_status_without_mutators() -> None:
    server = build_mcp_server(
        service=RecordingStatusService(),
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    names = {tool.name for tool in listed.tools}
    assert "approval_status" in names
    assert "approval_grant" not in names
    assert "approval_deny" not in names
    assert "grant" not in names
    assert "deny" not in names

    tool = next(item for item in listed.tools if item.name == "approval_status")
    assert set(tool.input_schema["properties"]) == {"approval_id"}
    assert tool.input_schema["additionalProperties"] is False
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is None
    assert tool.annotations.open_world_hint is False


@pytest.mark.asyncio
async def test_server_approval_status_injects_principal_and_serializes() -> None:
    service = RecordingStatusService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "approval_status",
            {"approval_id": APR_ID},
        )

    assert result.is_error is False
    assert result.structured_content["approval_id"] == APR_ID
    assert result.structured_content["state"] == "pending"
    assert (
        result.structured_content["binding_fingerprint"]
        == "hmac-sha256:v1:" + ("3" * 16)
    )
    assert len(service.calls) == 1
    context, request = service.calls[0]
    assert context.principal.profile == "developer"
    assert request.approval_id == APR_ID


@pytest.mark.asyncio
async def test_server_malformed_approval_id_is_sanitized() -> None:
    service = RecordingStatusService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "approval_status",
            {"approval_id": "apr_SUPERSECRET-not-valid"},
        )

    assert result.is_error is True
    text = _tool_error_text(result)
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []
