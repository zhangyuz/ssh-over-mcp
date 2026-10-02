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


class _AuditLedger:
    async def append_audit(self, event) -> str:
        return "evt_" + ("0" * 32)


def _audit() -> AuditRecorder:
    return AuditRecorder(_AuditLedger())
from ssh_over_mcp.policy.models import Decision, PolicyDecision, RiskLevel
from ssh_over_mcp.ssh import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHAuditPersistenceOutcomeUncertain,
    SSHConnectionError,
    SSHCredentialError,
    SSHFilesystemReadResult,
    SSHFilesystemStatResult,
    SSHHostKeyVerificationError,
    SSHOutputLimitExceeded,
    SSHPolicyDenied,
    SSHRemoteOperationError,
    SSHRemotePolicyDenied,
    SSHRemoteResponseError,
    SSHRequestTimeout,
)

APR_ID = "apr_" + ("a" * 32)


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


def _approval_status(tool: str = "fs_stat") -> ApprovalStatus:
    return ApprovalStatus(
        approval_id=APR_ID,
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 18, 10, tzinfo=UTC),
        host="visible",
        tool=tool,
        risk=RiskLevel.HIGH,
        safe_summary=ApprovalSafeSummary(
            principal_id="static:developer",
            profile="developer",
            host="visible",
            tool=tool,
            privilege="user",
            policy_version="sha256:test",
            risk=RiskLevel.HIGH,
            normalized_executable=None,
            normalized_cwd=None,
            normalized_path="/srv/app/file",
            argv_count=0,
            argv_fingerprint="sha256:" + ("1" * 64),
            env_names=(),
            stdin_length=None,
            stdin_fingerprint=None,
            content_length=None,
            content_fingerprint=None,
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=64 * 1024 if tool == "fs_stat" else 4096,
            effective_max_stdin_bytes=None,
            effective_tool_bytes=None if tool == "fs_stat" else 4096,
        ),
        binding_fingerprint="hmac-sha256:v1:" + ("2" * 16),
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

    async def stat(self, request, *, context):
        self.calls.append(("stat", context, request))
        if self.error is not None:
            raise self.error
        return SSHFilesystemStatResult(
            request_id="req_stat_1234",
            host=request.host,
            path="/srv/app/file",
            kind="regular",
            size=7,
            mode=0o640,
            uid=2103,
            gid=3103,
            mtime_ns=123456,
        )

    async def read(self, request, *, context, max_bytes):
        self.calls.append(("read", context, request, max_bytes))
        if self.error is not None:
            raise self.error
        return SSHFilesystemReadResult(
            request_id="req_read_1234",
            host=request.host,
            path="/srv/app/file",
            data=b"\x00\xffAB",
        )


def _service(filesystem: RecordingFilesystem) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_filesystem=filesystem,
    )


def test_read_only_filesystem_requests_accept_only_opaque_approval_id() -> None:
    stat = models.FsStatRequest(
        host="visible",
        path="/srv/app/file",
        approval_id=APR_ID,
    )
    read = models.FsReadRequest(
        host="visible",
        path="/srv/app/file",
        max_bytes=4096,
        approval_id=APR_ID,
    )
    assert stat.approval_id == APR_ID
    assert read.approval_id == APR_ID

    for request_type, kwargs in (
        (models.FsStatRequest, {"host": "visible", "path": "/srv/app/file"}),
        (
            models.FsReadRequest,
            {"host": "visible", "path": "/srv/app/file", "max_bytes": 4096},
        ),
    ):
        with pytest.raises(ValidationError):
            request_type(**kwargs, approval_id="apr_SUPERSECRET")
        for field, value in (
            ("grant", True),
            ("deny", True),
            ("approval_ttl_seconds", 600),
            ("binding_hmac", "SUPERSECRET"),
        ):
            with pytest.raises(ValidationError):
                request_type(**kwargs, **{field: value})


@pytest.mark.asyncio
async def test_fs_stat_hides_host_before_filesystem_client() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.fs_stat(
            _operation_context(),
            models.FsStatRequest(host="hidden", path="/srv/app/file"),
        )

    assert filesystem.calls == []


@pytest.mark.asyncio
async def test_fs_stat_injects_principal_and_returns_metadata() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_stat(
        _operation_context(),
        models.FsStatRequest(host="visible", path="/srv/app/file"),
    )

    operation, seen_context, evaluation = filesystem.calls[0]
    assert operation == "stat"
    assert seen_context == _operation_context()
    assert evaluation.profile == "developer"
    assert evaluation.host == "visible"
    assert evaluation.tool == "fs_stat"
    assert evaluation.path == "/srv/app/file"
    assert evaluation.privilege == "user"
    assert result.request_id == "req_stat_1234"
    assert result.path == "/srv/app/file"
    assert result.kind == "regular"
    assert result.mode == 0o640
    assert result.uid == 2103
    assert result.gid == 3103


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["fs_stat", "fs_read"])
async def test_read_only_filesystem_threads_approval_only_through_context(
    operation: str,
) -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)
    context = _operation_context(approval_id=APR_ID)

    if operation == "fs_stat":
        await service.fs_stat(
            context,
            models.FsStatRequest(
                host="visible",
                path="/srv/app/file",
                approval_id=APR_ID,
            ),
        )
        _, seen_context, evaluation = filesystem.calls[0]
    else:
        await service.fs_read(
            context,
            models.FsReadRequest(
                host="visible",
                path="/srv/app/file",
                max_bytes=4096,
                approval_id=APR_ID,
            ),
        )
        _, seen_context, evaluation, _ = filesystem.calls[0]

    assert seen_context.approval_id == APR_ID
    assert "approval_id" not in type(evaluation).model_fields


@pytest.mark.asyncio
async def test_fs_read_is_bounded_and_returns_lossless_base64() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_read(
        _operation_context(),
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=4096,
        ),
    )

    operation, seen_context, evaluation, max_bytes = filesystem.calls[0]
    assert operation == "read"
    assert seen_context == _operation_context()
    assert evaluation.profile == "developer"
    assert evaluation.tool == "fs_read"
    assert evaluation.path == "/srv/app/file"
    assert max_bytes == 4096
    assert result.request_id == "req_read_1234"
    assert result.data_base64 == base64.b64encode(b"\x00\xffAB").decode("ascii")


def test_fs_read_request_has_one_mib_hard_cap() -> None:
    request = models.FsReadRequest(
        host="visible",
        path="/srv/app/file",
        max_bytes=1024 * 1024,
    )
    assert request.max_bytes == 1024 * 1024
    with pytest.raises(ValidationError):
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=(1024 * 1024) + 1,
        )
    with pytest.raises(ValidationError):
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=True,
        )


def _policy_failure(
    decision: Decision,
    *,
    approval_required: bool = False,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="SUPERSECRET policy detail",
        risk=RiskLevel.HIGH,
        approval_required=approval_required,
        policy_version="sha256:test",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["fs_stat", "fs_read"])
async def test_filesystem_approval_required_returns_safe_retry_handle(
    operation: str,
) -> None:
    filesystem = RecordingFilesystem()
    decision = _policy_failure(
        Decision.APPROVAL_REQUIRED,
        approval_required=True,
    )
    filesystem.error = SSHApprovalRequired(
        decision,
        approval_status=_approval_status(operation),
    )
    service = _service(filesystem)

    with pytest.raises(api_errors.ApprovalRequiredError) as exc_info:
        if operation == "fs_stat":
            await service.fs_stat(
                _operation_context(),
                models.FsStatRequest(host="visible", path="/srv/app/file"),
            )
        else:
            await service.fs_read(
                _operation_context(),
                models.FsReadRequest(
                    host="visible",
                    path="/srv/app/file",
                    max_bytes=4096,
                ),
            )

    rendered = str(exc_info.value)
    assert f"approval_id={APR_ID}" in rendered
    assert "state=pending" in rendered
    assert "expires_at=2026-10-01T18:10:00+00:00" in rendered
    assert "retry the exact operation with this approval_id only after approval" in rendered
    for forbidden in ("SUPERSECRET", "/srv/app/file", "sha256:", "hmac-sha256:"):
        assert forbidden not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "public_error", "message"),
    [
        (
            SSHPolicyDenied(_policy_failure(Decision.DENY)),
            "PolicyDeniedError",
            "request denied by central policy",
        ),
        (
            SSHApprovalRequired(
                _policy_failure(
                    Decision.APPROVAL_REQUIRED,
                    approval_required=True,
                )
            ),
            "ApprovalRequiredError",
            "approval required by central policy",
        ),
        (
            SSHCredentialError("SUPERSECRET credential"),
            "SSHCredentialUnavailableError",
            "SSH credential is unavailable",
        ),
        (
            SSHHostKeyVerificationError("SUPERSECRET host key"),
            "SSHHostKeyError",
            "SSH host key verification failed",
        ),
        (
            SSHConnectionError("SUPERSECRET transport"),
            "SSHTransportError",
            "SSH transport failed",
        ),
        (
            SSHRemotePolicyDenied("SUPERSECRET remote denial"),
            "RemotePolicyDeniedError",
            "remote filesystem policy denied request",
        ),
        (
            SSHRequestTimeout("SUPERSECRET timeout"),
            "RemoteTimeoutError",
            "remote filesystem request timed out",
        ),
        (
            SSHOutputLimitExceeded("SUPERSECRET overflow"),
            "RemoteOutputLimitError",
            "remote filesystem response exceeded output limit",
        ),
        (
            SSHRemoteOperationError("SUPERSECRET remote failure"),
            "FilesystemOperationError",
            "remote filesystem operation failed",
        ),
        (
            SSHRemoteResponseError("SUPERSECRET malformed response"),
            "FilesystemOperationError",
            "remote filesystem operation failed",
        ),
        (
            SSHAuditPersistenceError("SUPERSECRET audit detail"),
            "AuditPersistenceError",
            "audit persistence failed",
        ),
        (
            SSHAuditPersistenceOutcomeUncertain("SUPERSECRET audit uncertainty"),
            "AuditPersistenceOutcomeUncertainError",
            "audit persistence outcome is uncertain; do not retry blindly",
        ),
    ],
)
async def test_filesystem_service_sanitizes_remote_failures(
    error: Exception,
    public_error: str,
    message: str,
) -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = error
    service = _service(filesystem)

    with pytest.raises(
        getattr(api_errors, public_error),
        match=message,
    ) as exc_info:
        await service.fs_stat(
            _operation_context(),
            models.FsStatRequest(host="visible", path="/srv/app/file"),
        )
    assert "SUPERSECRET" not in str(exc_info.value)


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(principal_id="static:developer", profile="developer")


class ToolService:
    def __init__(self) -> None:
        self.calls = []

    async def fs_stat(self, principal, request):
        self.calls.append(("fs_stat", principal, request))
        return models.FsStatResult(
            request_id="req_stat_1234",
            host=request.host,
            path=request.path,
            kind="regular",
            size=7,
            mode=0o640,
            uid=2103,
            gid=3103,
            mtime_ns=123456,
        )

    async def fs_read(self, principal, request):
        self.calls.append(("fs_read", principal, request))
        return models.FsReadResult(
            request_id="req_read_1234",
            host=request.host,
            path=request.path,
            data_base64="AP9BQg==",
        )


@pytest.mark.asyncio
async def test_server_registers_strict_read_only_filesystem_tools() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tools = {tool.name: tool for tool in listed.tools}
    assert {"fs_stat", "fs_read"}.issubset(tools)
    assert set(tools["fs_stat"].input_schema["properties"]) == {
        "host", "path", "approval_id"
    }
    assert set(tools["fs_read"].input_schema["properties"]) == {
        "host",
        "path",
        "max_bytes",
        "approval_id",
    }
    for name in ("fs_stat", "fs_read"):
        tool = tools[name]
        assert tool.input_schema["additionalProperties"] is False
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is not True
        assert tool.annotations.open_world_hint is False
        schema = repr(tool.input_schema)
        for forbidden in (
            "profile",
            "address",
            "ssh_user",
            "credential_ref",
            "host_key",
            "request_id",
            "grant",
            "deny",
            "approval_ttl_seconds",
            "binding_hmac",
        ):
            assert forbidden not in schema


@pytest.mark.asyncio
async def test_server_fs_read_injects_principal_and_rejects_extra_fields() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )
    async with Client(server) as client:
        ok = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
                "approval_id": APR_ID,
            },
        )
        rejected = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
                "profile": "ops",
            },
        )

    assert ok.is_error is False
    assert ok.structured_content["data_base64"] == "AP9BQg=="
    _, context, request = service.calls[0]
    assert isinstance(context, OperationContext)
    assert context.principal == models.PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )
    assert request.max_bytes == 4096
    assert request.approval_id == APR_ID
    assert context.approval_id == APR_ID
    assert rejected.is_error is True
    assert len(service.calls) == 1

@pytest.mark.asyncio
async def test_server_invalid_fs_read_input_is_sanitized() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": "SUPERSECRET",
            },
        )

    assert result.is_error is True
    text = "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []

    async with Client(server) as client:
        malformed = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
                "approval_id": "apr_SUPERSECRET-invalid",
            },
        )
    assert malformed.is_error is True
    text = "\n".join(getattr(block, "text", "") for block in malformed.content)
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []
