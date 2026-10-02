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

APR_ID = "apr_" + ("a" * 32)


class _AuditLedger:
    async def append_audit(self, event) -> str:
        return "evt_" + ("0" * 32)


def _audit() -> AuditRecorder:
    return AuditRecorder(_AuditLedger())
from ssh_over_mcp.policy.models import Decision, PolicyDecision, RiskLevel
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHAuditPersistenceOutcomeUncertain,
    SSHConnectionError,
    SSHCredentialError,
    SSHHostKeyVerificationError,
    SSHPolicyDenied,
)
from ssh_over_mcp.ssh.executor import SSHExecutionResult


def test_ssh_exec_request_is_closed_world_and_bounded() -> None:
    request_type = models.SSHExecRequest

    request = request_type(
        host="dev01",
        executable="/usr/bin/git",
        args=("status", "--short"),
        cwd="/srv/app",
        env={"LANG": "C"},
        stdin="hello",
        timeout_seconds=30,
        approval_id=APR_ID,
    )

    assert request.stdin == "hello"
    assert request.timeout_seconds == 30
    assert request.approval_id == APR_ID

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            profile="ops",
        )

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            stdin="x" * ((64 * 1024) + 1),
        )

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            timeout_seconds=60.001,
        )

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            approval_id="apr_SUPERSECRET",
        )

    for forbidden_field, forbidden_value in (
        ("grant", True),
        ("deny", True),
        ("approval_ttl_seconds", 3600),
        ("binding_hmac", "SUPERSECRET"),
    ):
        with pytest.raises(ValidationError):
            request_type(
                host="dev01",
                executable="/bin/echo",
                **{forbidden_field: forbidden_value},
            )


def test_ssh_exec_result_uses_explicit_lossless_base64_fields() -> None:
    result_type = models.SSHExecResult

    result = result_type(
        request_id="req_12345678",
        host="dev01",
        exit_status=0,
        stdout_base64="/wA=",
        stderr_base64="/g==",
        duration_ms=12,
        timed_out=False,
        truncated=False,
    )

    assert result.stdout_base64 == "/wA="
    assert result.stderr_base64 == "/g=="
    assert set(result_type.model_fields) == {
        "request_id",
        "host",
        "exit_status",
        "exit_signal",
        "stdout_base64",
        "stderr_base64",
        "duration_ms",
        "timed_out",
        "truncated",
    }


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


def _inventory() -> Inventory:
    return Inventory(
        hosts={
            "visible": Host(
                address="10.0.0.1",
                port=22,
                ssh_user="secret-user",
                credential_ref="secret://visible",
                host_key="secret-host-key",
                allowed_roles=frozenset({"developer"}),
            ),
            "hidden": Host(
                address="10.0.0.2",
                port=22,
                ssh_user="hidden-user",
                credential_ref="secret://hidden",
                host_key="hidden-host-key",
                allowed_roles=frozenset({"ops"}),
            ),
        }
    )


class RecordingExecutor:
    default_timeout_seconds = 60.0
    default_max_output_bytes = 1024 * 1024
    default_max_stdin_bytes = 1024 * 1024

    def __init__(self) -> None:
        self.calls = []

        self.result = SSHExecutionResult(
            request_id="req_12345678",
            host="visible",
            exit_status=0,
            stdout=b"\xff\x00",
            stderr=b"\xfe",
            duration_ms=7,
            timed_out=False,
            truncated=False,
        )

    async def execute(self, request, **kwargs):
        self.calls.append((request, kwargs))
        return self.result


def _service(executor: RecordingExecutor) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_executor=executor,
    )


def _request(host: str = "visible", **overrides) -> models.SSHExecRequest:
    values = {
        "host": host,
        "executable": "/usr/bin/git",
        "args": ("status",),
        "cwd": "/srv/app",
        "env": {"LANG": "C"},
        "stdin": "hello",
        "timeout_seconds": 30,
    }
    values.update(overrides)
    return models.SSHExecRequest(**values)


@pytest.mark.asyncio
async def test_ssh_exec_hides_host_before_executor() -> None:
    executor = RecordingExecutor()
    service = _service(executor)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.ssh_exec(
            _operation_context(),
            _request("hidden"),
        )

    assert executor.calls == []


@pytest.mark.asyncio
async def test_ssh_exec_injects_principal_and_returns_lossless_output() -> None:
    executor = RecordingExecutor()
    service = _service(executor)

    result = await service.ssh_exec(
        _operation_context(),
        _request(),
    )

    assert len(executor.calls) == 1
    evaluation, kwargs = executor.calls[0]
    assert evaluation.profile == "developer"
    assert evaluation.host == "visible"
    assert evaluation.tool == "ssh_exec"
    assert evaluation.executable == "/usr/bin/git"
    assert evaluation.args == ("status",)
    assert evaluation.cwd == "/srv/app"
    assert evaluation.env == {"LANG": "C"}
    assert evaluation.privilege == "user"

    assert kwargs == {
        "context": _operation_context(),
        "stdin": b"hello",
        "timeout_seconds": 30,
    }
    assert result.request_id == "req_12345678"
    assert result.host == "visible"
    assert result.stdout_base64 == base64.b64encode(b"\xff\x00").decode("ascii")
    assert result.stderr_base64 == base64.b64encode(b"\xfe").decode("ascii")
    assert result.exit_status == 0
    assert result.duration_ms == 7
    assert result.timed_out is False
    assert result.truncated is False


@pytest.mark.asyncio
async def test_ssh_exec_threads_approval_only_through_operation_context() -> None:
    executor = RecordingExecutor()
    service = _service(executor)

    context = _operation_context(approval_id=APR_ID)
    await service.ssh_exec(
        context,
        _request(approval_id=APR_ID),
    )

    assert len(executor.calls) == 1
    evaluation, kwargs = executor.calls[0]
    assert kwargs["context"].approval_id == APR_ID
    assert "approval_id" not in type(evaluation).model_fields


@pytest.mark.asyncio
async def test_ssh_exec_cannot_expand_runtime_limits() -> None:
    executor = RecordingExecutor()
    executor.default_timeout_seconds = 10.0
    executor.default_max_stdin_bytes = 4
    service = _service(executor)

    with pytest.raises(
        api_errors.InvalidExecutionLimitError,
        match="execution limits are invalid",
    ):
        await service.ssh_exec(
            _operation_context(),
            _request(timeout_seconds=30),
        )

    with pytest.raises(
        api_errors.InvalidExecutionLimitError,
        match="execution limits are invalid",
    ):
        await service.ssh_exec(
            _operation_context(),
            _request(timeout_seconds=5, stdin="hello"),
        )

    assert executor.calls == []


def _policy_failure(
    decision: Decision,
    *,
    approval_required: bool = False,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="SUPERSECRET internal rule detail",
        risk=RiskLevel.HIGH,
        approval_required=approval_required,
        policy_version="sha256:public",
    )


def _approval_status() -> ApprovalStatus:
    return ApprovalStatus(
        approval_id=APR_ID,
        state=ApprovalState.PENDING,
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
            env_names=(),
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


class RaisingExecutor(RecordingExecutor):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    async def execute(self, request, **kwargs):
        self.calls.append((request, kwargs))
        raise self.error


_ERROR_CASES = (
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
        SSHCredentialError("SUPERSECRET credential ref"),
        "SSHCredentialUnavailableError",
        "SSH credential is unavailable",
    ),
    (
        SSHHostKeyVerificationError("SUPERSECRET host key"),
        "SSHHostKeyError",
        "SSH host key verification failed",
    ),
    (
        SSHConnectionError("SUPERSECRET transport detail"),
        "SSHTransportError",
        "SSH transport failed",
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
    (
        RuntimeError("SUPERSECRET raw library exception"),
        "SSHExecutionError",
        "SSH execution failed",
    ),
)


@pytest.mark.asyncio
async def test_ssh_exec_approval_required_error_has_safe_exact_retry_contract() -> None:
    decision = _policy_failure(
        Decision.APPROVAL_REQUIRED,
        approval_required=True,
    )
    executor = RaisingExecutor(
        SSHApprovalRequired(
            decision,
            approval_status=_approval_status(),
        )
    )
    service = _service(executor)

    with pytest.raises(api_errors.ApprovalRequiredError) as exc_info:
        await service.ssh_exec(
            _operation_context(),
            _request(),
        )

    rendered = str(exc_info.value)
    assert rendered == (
        "approval required: "
        f"request_id={'req_' + '1' * 32} "
        f"approval_id={APR_ID} "
        "state=pending "
        "expires_at=2026-10-01T18:10:00+00:00; "
        "retry the exact operation with this approval_id only after approval"
    )
    for forbidden in (
        "SUPERSECRET",
        "secret://",
        "/usr/bin/git",
        "/srv/app",
        "static:developer",
        "sha256:",
        "hmac-sha256:",
    ):
        assert forbidden not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "public_error_name", "public_message"),
    _ERROR_CASES,
)
async def test_ssh_exec_normalizes_internal_failures(
    error: Exception,
    public_error_name: str,
    public_message: str,
) -> None:
    executor = RaisingExecutor(error)
    service = _service(executor)

    with pytest.raises(
        getattr(api_errors, public_error_name),
        match=public_message,
    ) as exc_info:
        await service.ssh_exec(
            _operation_context(),
            _request(),
        )

    rendered = str(exc_info.value)
    assert "SUPERSECRET" not in rendered
    assert "secret://" not in rendered


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(principal_id="static:developer", profile="developer")


class RecordingToolService:
    def __init__(self) -> None:
        self.calls = []

    async def ssh_exec(
        self,
        principal: models.PrincipalContext,
        request: models.SSHExecRequest,
    ) -> models.SSHExecResult:
        self.calls.append((principal, request))
        return models.SSHExecResult(
            request_id="req_server_1234",
            host=request.host,
            exit_status=0,
            stdout_base64="b2s=",
            stderr_base64="",
            duration_ms=5,
            timed_out=False,
            truncated=False,
        )


def _tool_error_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


@pytest.mark.asyncio
async def test_server_registers_strict_ssh_exec_tool() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tool = next(
        item for item in listed.tools
        if item.name == "ssh_exec"
    )
    assert set(tool.input_schema["properties"]) == {
        "host",
        "executable",
        "args",
        "cwd",
        "env",
        "stdin",
        "timeout_seconds",
        "approval_id",
    }
    assert tool.input_schema["additionalProperties"] is False
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.destructive_hint is True
    assert tool.annotations.idempotent_hint is False
    assert tool.annotations.open_world_hint is False

    schema_text = repr(tool.input_schema)
    for forbidden in (
        "profile",
        "address",
        "ssh_user",
        "credential_ref",
        "host_key",
        "request_id",
        "max_output_bytes",
        "max_stdin_bytes",
        "privilege",
        "grant",
        "deny",
        "approval_ttl_seconds",
        "binding_hmac",
    ):
        assert forbidden not in schema_text


@pytest.mark.asyncio
async def test_server_ssh_exec_injects_principal_and_returns_result() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "ssh_exec",
            {
                "host": "visible",
                "executable": "/usr/bin/git",
                "args": ["status"],
                "cwd": "/srv/app",
                "env": {"LANG": "C"},
                "stdin": "hello",
                "timeout_seconds": 30,
                "approval_id": APR_ID,
            },
        )

    assert result.is_error is False
    assert result.structured_content["request_id"] == "req_server_1234"
    assert result.structured_content["stdout_base64"] == "b2s="
    assert len(service.calls) == 1
    context, request = service.calls[0]
    assert isinstance(context, OperationContext)
    assert context.principal == models.PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )
    assert request.host == "visible"
    assert request.executable == "/usr/bin/git"
    assert request.stdin == "hello"
    assert request.approval_id == APR_ID
    assert context.approval_id == APR_ID


@pytest.mark.asyncio
async def test_server_rejects_client_owned_execution_identity_fields() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "ssh_exec",
            {
                "host": "visible",
                "executable": "/usr/bin/id",
                "profile": "ops",
                "credential_ref": "secret://attacker",
            },
        )

    assert result.is_error is True
    assert service.calls == []
    text = _tool_error_text(result)
    assert "secret://attacker" not in text


@pytest.mark.asyncio
async def test_server_invalid_ssh_exec_input_is_sanitized() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )
    secret_stdin = "SUPERSECRET-" + ("x" * (64 * 1024))

    async with Client(server) as client:
        result = await client.call_tool(
            "ssh_exec",
            {
                "host": "visible",
                "executable": "/usr/bin/id",
                "stdin": secret_stdin,
            },
        )

    assert result.is_error is True
    text = _tool_error_text(result)
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []

    async with Client(server) as client:
        result = await client.call_tool(
            "ssh_exec",
            {
                "host": "visible",
                "executable": "/usr/bin/id",
                "approval_id": "apr_SUPERSECRET-not-a-valid-id",
            },
        )

    assert result.is_error is True
    text = _tool_error_text(result)
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []


@pytest.mark.asyncio
async def test_ssh_exec_without_executor_fails_closed() -> None:
    service = MCPService(
        inventory=_inventory(),
        policy=object(),
    )

    with pytest.raises(
        api_errors.SSHExecutionError,
        match="SSH execution is unavailable",
    ):
        await service.ssh_exec(
            _operation_context(),
            _request(),
        )


@pytest.mark.asyncio
async def test_server_sdk_type_validation_is_sanitized() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "ssh_exec",
            {
                "host": "visible",
                "executable": "/usr/bin/id",
                "timeout_seconds": "SUPERSECRET",
            },
        )

    assert result.is_error is True
    text = _tool_error_text(result)
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []
