from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api import models
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.approvals.models import (
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.models import Decision, PolicyDecision, RiskLevel


class _AuditLedger:
    async def append_audit(self, event) -> str:
        return "evt_" + ("0" * 32)


def _audit() -> AuditRecorder:
    return AuditRecorder(_AuditLedger())
from ssh_over_mcp.ssh import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHAuditPersistenceOutcomeUncertain,
    SSHConnectionError,
    SSHFilesystemWriteCommittedUncertain,
    SSHFilesystemWriteResult,
    SSHRequestOutcomeUncertain,
)

APR_ID = "apr_" + ("d" * 32)


def _operation_context(approval_id: str | None = None) -> OperationContext:
    return OperationContext(
        request_id="req_" + "1" * 32,
        principal=models.PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
        approval_id=approval_id,
    )


def _write_approval_status() -> ApprovalStatus:
    return ApprovalStatus(
        approval_id=APR_ID,
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 18, 10, tzinfo=UTC),
        host="visible",
        tool="fs_write",
        risk=RiskLevel.HIGH,
        safe_summary=ApprovalSafeSummary(
            principal_id="static:developer",
            profile="developer",
            host="visible",
            tool="fs_write",
            privilege="user",
            policy_version="sha256:test",
            risk=RiskLevel.HIGH,
            normalized_executable=None,
            normalized_cwd=None,
            normalized_path="/srv/app/new.bin",
            argv_count=0,
            argv_fingerprint="sha256:" + ("1" * 64),
            env_names=(),
            stdin_length=None,
            stdin_fingerprint=None,
            content_length=4,
            content_fingerprint="sha256:" + ("2" * 64),
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=4096,
            effective_max_stdin_bytes=None,
            effective_tool_bytes=None,
        ),
        binding_fingerprint="hmac-sha256:v1:" + ("3" * 16),
    )


def _inventory() -> Inventory:
    return Inventory(
        hosts={
            "visible": Host(
                address="10.0.0.1",
                ssh_user="secret-user",
                credential_ref="secret://visible",
                host_key="secret-host-key",
                allowed_roles=frozenset({"developer"}),
            ),
            "hidden": Host(
                address="10.0.0.2",
                ssh_user="hidden-user",
                credential_ref="secret://hidden",
                host_key="hidden-host-key",
                allowed_roles=frozenset({"ops"}),
            ),
        }
    )


class RecordingFilesystem:
    def __init__(self) -> None:
        self.calls = []
        self.error: Exception | None = None

    async def write(self, request, data, *, context):
        self.calls.append((context, request, data))
        if self.error is not None:
            raise self.error
        return SSHFilesystemWriteResult(
            request_id="req_write_1234",
            host=request.host,
            path="/srv/app/new.bin",
            content_length=len(data),
        )


def _service(filesystem: RecordingFilesystem) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_filesystem=filesystem,
    )


def test_fs_write_request_accepts_binary_and_empty_content() -> None:
    request_type = models.FsWriteRequest

    binary = request_type(
        host="visible",
        path="/srv/app/new.bin",
        data_base64=base64.b64encode(b"\x00\xffAB").decode("ascii"),
        approval_id=APR_ID,
    )
    assert binary.decoded_data() == b"\x00\xffAB"
    assert binary.approval_id == APR_ID

    empty = request_type(
        host="visible",
        path="/srv/app/empty.bin",
        data_base64="",
    )
    assert empty.decoded_data() == b""


@pytest.mark.parametrize(
    "data_base64",
    [
        "%%%",
        "A",
        "====",
        "éA==",
    ],
)
def test_fs_write_request_rejects_invalid_base64(data_base64: str) -> None:
    with pytest.raises(ValidationError):
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/new.bin",
            data_base64=data_base64,
        )


def test_fs_write_request_enforces_64_kib_decoded_cap() -> None:
    accepted = base64.b64encode(b"x" * (64 * 1024)).decode("ascii")
    models.FsWriteRequest(
        host="visible",
        path="/srv/app/max.bin",
        data_base64=accepted,
    )

    oversized = base64.b64encode(
        b"x" * ((64 * 1024) + 1)
    ).decode("ascii")
    with pytest.raises(ValidationError):
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/too-large.bin",
            data_base64=oversized,
        )


def test_fs_write_request_is_closed_world() -> None:
    request_type = models.FsWriteRequest
    for extra in (
        {"content_length": 4},
        {"overwrite": True},
        {"append": True},
        {"mode": 0o644},
        {"owner": "root"},
        {"profile": "ops"},
        {"request_id": "attacker"},
        {"credential_ref": "secret://attacker"},
        {"grant": True},
        {"deny": True},
        {"approval_ttl_seconds": 600},
        {"binding_hmac": "SUPERSECRET"},
    ):
        with pytest.raises(ValidationError):
            request_type(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
                **extra,
            )

    with pytest.raises(ValidationError):
        request_type(
            host="visible",
            path="/srv/app/new.bin",
            data_base64="ZGF0YQ==",
            approval_id="apr_SUPERSECRET",
        )


@pytest.mark.asyncio
async def test_fs_write_hides_host_before_filesystem_client() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.fs_write(
            _operation_context(),
            models.FsWriteRequest(
                host="hidden",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert filesystem.calls == []


@pytest.mark.asyncio
async def test_fs_write_injects_principal_and_derives_content_length() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_write(
        _operation_context(),
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/./new.bin",
            data_base64="AP9BQg==",
        ),
    )

    assert len(filesystem.calls) == 1
    seen_context, evaluation, data = filesystem.calls[0]
    assert seen_context == _operation_context()
    assert evaluation.profile == "developer"
    assert evaluation.host == "visible"
    assert evaluation.tool == "fs_write"
    assert evaluation.path == "/srv/app/./new.bin"
    assert evaluation.privilege == "user"
    assert data == b"\x00\xffAB"
    assert result == models.FsWriteResult(
        request_id="req_write_1234",
        host="visible",
        path="/srv/app/new.bin",
        content_length=4,
    )


@pytest.mark.asyncio
async def test_fs_write_threads_approval_only_through_context() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)
    context = _operation_context(approval_id=APR_ID)

    await service.fs_write(
        context,
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/new.bin",
            data_base64="ZGF0YQ==",
            approval_id=APR_ID,
        ),
    )

    seen_context, evaluation, data = filesystem.calls[0]
    assert seen_context.approval_id == APR_ID
    assert data == b"data"
    assert "approval_id" not in type(evaluation).model_fields


@pytest.mark.asyncio
async def test_fs_write_approval_required_returns_safe_retry_handle() -> None:
    filesystem = RecordingFilesystem()
    decision = PolicyDecision(
        decision=Decision.APPROVAL_REQUIRED,
        reason="SUPERSECRET policy detail",
        risk=RiskLevel.HIGH,
        normalized_path="/srv/app/new.bin",
        approval_required=True,
        policy_version="sha256:test",
    )
    filesystem.error = SSHApprovalRequired(
        decision,
        approval_status=_write_approval_status(),
    )
    service = _service(filesystem)

    with pytest.raises(api_errors.ApprovalRequiredError) as exc_info:
        await service.fs_write(
            _operation_context(),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    rendered = str(exc_info.value)
    assert f"approval_id={APR_ID}" in rendered
    assert "state=pending" in rendered
    assert "expires_at=2026-10-01T18:10:00+00:00" in rendered
    assert "retry the exact operation with this approval_id only after approval" in rendered
    for forbidden in ("SUPERSECRET", "ZGF0YQ==", "/srv/app/new.bin", "sha256:"):
        assert forbidden not in rendered


@pytest.mark.asyncio
async def test_fs_write_committed_uncertain_outcome_is_preserved() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHFilesystemWriteCommittedUncertain(
        "SUPERSECRET committed detail"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.FilesystemWriteCommittedUncertainError,
        match="filesystem write committed; durability uncertain; do not retry blindly",
    ) as exc_info:
        await service.fs_write(
            _operation_context(),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_generic_uncertainty_remains_non_retryable() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHRequestOutcomeUncertain(
        "SUPERSECRET transport uncertainty"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.FilesystemMutationOutcomeUncertainError,
        match="do not retry blindly",
    ) as exc_info:
        await service.fs_write(
            _operation_context(),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_pre_request_connection_failure_is_definite() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHConnectionError(
        "SUPERSECRET channel open detail"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.SSHTransportError,
        match="SSH transport failed",
    ) as exc_info:
        await service.fs_write(
            _operation_context(),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(principal_id="static:developer", profile="developer")


class ToolService:
    def __init__(self) -> None:
        self.calls = []

    async def fs_write(self, principal, request):
        self.calls.append((principal, request))
        return models.FsWriteResult(
            request_id="req_tool_write_1234",
            host=request.host,
            path="/srv/app/new.bin",
            content_length=len(request.decoded_data()),
        )


def _tool_error_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


@pytest.mark.asyncio
async def test_server_registers_strict_create_only_fs_write_tool() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tool = next(item for item in listed.tools if item.name == "fs_write")
    assert set(tool.input_schema["properties"]) == {
        "host",
        "path",
        "data_base64",
        "approval_id",
    }
    assert tool.input_schema["additionalProperties"] is False
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.destructive_hint is False
    assert tool.annotations.idempotent_hint is False
    assert tool.annotations.open_world_hint is False

    schema_text = repr(tool.input_schema)
    for forbidden in (
        "content_length",
        "overwrite",
        "append",
        "mode",
        "owner",
        "profile",
        "request_id",
        "address",
        "ssh_user",
        "credential_ref",
        "host_key",
        "grant",
        "deny",
        "approval_ttl_seconds",
        "binding_hmac",
    ):
        assert forbidden not in schema_text


@pytest.mark.asyncio
async def test_server_fs_write_injects_principal_and_rejects_bad_input() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        ok = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "AP9BQg==",
                "approval_id": APR_ID,
            },
        )
        invalid = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "SUPERSECRET%%%",
            },
        )
        extra = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "ZGF0YQ==",
                "overwrite": True,
            },
        )

    assert ok.is_error is False
    assert ok.structured_content["content_length"] == 4
    assert len(service.calls) == 1
    context, request = service.calls[0]
    assert isinstance(context, OperationContext)
    assert context.principal == models.PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )
    assert request.decoded_data() == b"\x00\xffAB"
    assert request.approval_id == APR_ID
    assert context.approval_id == APR_ID

    assert invalid.is_error is True
    assert "SUPERSECRET" not in _tool_error_text(invalid)
    assert extra.is_error is True

    async with Client(server) as client:
        malformed_approval = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "ZGF0YQ==",
                "approval_id": "apr_SUPERSECRET-invalid",
            },
        )
    assert malformed_approval.is_error is True
    assert "SUPERSECRET" not in _tool_error_text(malformed_approval)
    assert len(service.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "public_error", "message"),
    [
        (
            SSHAuditPersistenceError("SUPERSECRET audit detail"),
            api_errors.AuditPersistenceError,
            "audit persistence failed",
        ),
        (
            SSHAuditPersistenceOutcomeUncertain(
                "SUPERSECRET audit uncertainty"
            ),
            api_errors.AuditPersistenceOutcomeUncertainError,
            "audit persistence outcome is uncertain; do not retry blindly",
        ),
    ],
)
async def test_fs_write_preserves_audit_persistence_failures(
    error: Exception,
    public_error,
    message: str,
) -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = error
    service = _service(filesystem)

    with pytest.raises(public_error, match=message) as exc_info:
        await service.fs_write(
            _operation_context(),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
