from __future__ import annotations

import base64

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api import models
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.models import Decision, PolicyDecision, RiskLevel
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
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
    )

    assert request.stdin == "hello"
    assert request.timeout_seconds == 30

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
            models.PrincipalContext(profile="developer"),
            _request("hidden"),
        )

    assert executor.calls == []


@pytest.mark.asyncio
async def test_ssh_exec_injects_principal_and_returns_lossless_output() -> None:
    executor = RecordingExecutor()
    service = _service(executor)

    result = await service.ssh_exec(
        models.PrincipalContext(profile="developer"),
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
            models.PrincipalContext(profile="developer"),
            _request(timeout_seconds=30),
        )

    with pytest.raises(
        api_errors.InvalidExecutionLimitError,
        match="execution limits are invalid",
    ):
        await service.ssh_exec(
            models.PrincipalContext(profile="developer"),
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
        RuntimeError("SUPERSECRET raw library exception"),
        "SSHExecutionError",
        "SSH execution failed",
    ),
)


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
            models.PrincipalContext(profile="developer"),
            _request(),
        )

    rendered = str(exc_info.value)
    assert "SUPERSECRET" not in rendered
    assert "secret://" not in rendered


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(profile="developer")


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
    ):
        assert forbidden not in schema_text


@pytest.mark.asyncio
async def test_server_ssh_exec_injects_principal_and_returns_result() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
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
            },
        )

    assert result.is_error is False
    assert result.structured_content["request_id"] == "req_server_1234"
    assert result.structured_content["stdout_base64"] == "b2s="
    assert len(service.calls) == 1
    principal, request = service.calls[0]
    assert principal == models.PrincipalContext(profile="developer")
    assert request.host == "visible"
    assert request.executable == "/usr/bin/git"
    assert request.stdin == "hello"


@pytest.mark.asyncio
async def test_server_rejects_client_owned_execution_identity_fields() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
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
            models.PrincipalContext(profile="developer"),
            _request(),
        )


@pytest.mark.asyncio
async def test_server_sdk_type_validation_is_sanitized() -> None:
    service = RecordingToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
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
