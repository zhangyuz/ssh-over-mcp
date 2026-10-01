from __future__ import annotations

import base64
import importlib

import pytest

from ssh_over_mcp.api.errors import ApiError, HostNotVisibleError
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh import SSHExecutionResult
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHConnectionError,
    SSHCredentialError,
    SSHHostKeyVerificationError,
    SSHPolicyDenied,
)
from ssh_over_mcp.ssh.protocol import ProtocolError


def _ssh_exec_types():
    models = importlib.import_module("ssh_over_mcp.api.models")
    assert hasattr(models, "SSHExecRequest")
    assert hasattr(models, "SSHExecResult")
    return models.SSHExecRequest, models.SSHExecResult


def _inventory() -> Inventory:
    return Inventory(
        hosts={
            "developer-host": Host(
                address="10.0.0.1",
                port=22,
                ssh_user="secret-user",
                credential_ref="secret://developer-host",
                host_key="secret-host-key",
                allowed_roles=frozenset({"developer"}),
            ),
            "ops-only-host": Host(
                address="10.0.0.2",
                port=22,
                ssh_user="secret-ops-user",
                credential_ref="secret://ops-only-host",
                host_key="secret-ops-host-key",
                allowed_roles=frozenset({"ops"}),
            ),
        }
    )


def _decision(
    decision: Decision,
    *,
    reason: str,
    approval_required: bool = False,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason=reason,
        risk=RiskLevel.HIGH if approval_required else RiskLevel.LOW,
        normalized_executable="/bin/echo",
        normalized_cwd="/srv/app",
        approval_required=approval_required,
        policy_version="sha256:test",
    )


class RecordingExecutor:
    default_timeout_seconds = 60.0
    default_max_output_bytes = 1024
    default_max_stdin_bytes = 8

    def __init__(
        self,
        *,
        result: SSHExecutionResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result or SSHExecutionResult(
            request_id="req_12345678",
            host="developer-host",
            exit_status=0,
            stdout=b"\x00\xff",
            stderr=b"warn\x80",
            duration_ms=7,
        )
        self.error = error
        self.calls: list[tuple[EvaluationRequest, dict[str, object]]] = []

    async def execute(self, request: EvaluationRequest, **kwargs):
        self.calls.append((request, kwargs))
        if self.error is not None:
            raise self.error
        return self.result


def _service(executor: RecordingExecutor) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_executor=executor,
    )


def test_ssh_exec_request_accepts_any_alias_valid_in_inventory() -> None:
    SSHExecRequest, _ = _ssh_exec_types()
    alias = "a" * 300
    inventory = Inventory(
        hosts={
            alias: Host(
                address="10.0.0.9",
                port=22,
                ssh_user="mcp",
                credential_ref="secret://long-alias",
                host_key="ssh-ed25519 AAAATEST",
                allowed_roles=frozenset({"developer"}),
            )
        }
    )

    request = SSHExecRequest(
        host=alias,
        executable="/bin/echo",
    )

    assert alias in inventory.hosts
    assert request.host == alias


def test_ssh_exec_request_enforces_declared_field_bounds() -> None:
    SSHExecRequest, _ = _ssh_exec_types()

    with pytest.raises(ValueError):
        SSHExecRequest(
            host="developer-host",
            executable="/" + ("x" * 4097),
        )

    with pytest.raises(ValueError):
        SSHExecRequest(
            host="developer-host",
            executable="/bin/echo",
            env={"": "value"},
        )

    with pytest.raises(ValueError):
        SSHExecRequest(
            host="developer-host",
            executable="/bin/echo",
            timeout_seconds=0,
        )


def test_ssh_exec_models_expose_only_public_bounded_fields() -> None:
    SSHExecRequest, SSHExecResult = _ssh_exec_types()

    assert set(SSHExecRequest.model_fields) == {
        "host",
        "executable",
        "args",
        "cwd",
        "env",
        "stdin",
        "timeout_seconds",
    }
    assert set(SSHExecResult.model_fields) == {
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

    for forbidden in (
        "profile",
        "address",
        "port",
        "ssh_user",
        "credential_ref",
        "host_key",
        "request_id",
        "max_output_bytes",
        "max_stdin_bytes",
    ):
        assert forbidden not in SSHExecRequest.model_fields


@pytest.mark.asyncio
async def test_ssh_exec_injects_principal_and_preserves_structured_request() -> None:
    SSHExecRequest, _ = _ssh_exec_types()
    assert hasattr(MCPService, "ssh_exec")
    executor = RecordingExecutor()
    service = _service(executor)

    result = await service.ssh_exec(
        PrincipalContext(profile="developer"),
        SSHExecRequest(
            host="developer-host",
            executable="/bin/echo",
            args=("hello",),
            cwd="/srv/app",
            env={"SAFE": "1"},
            stdin="payload",
            timeout_seconds=5,
        ),
    )

    assert len(executor.calls) == 1
    request, kwargs = executor.calls[0]
    assert request == EvaluationRequest(
        profile="developer",
        host="developer-host",
        tool="ssh_exec",
        executable="/bin/echo",
        args=("hello",),
        cwd="/srv/app",
        env={"SAFE": "1"},
        privilege="user",
    )
    assert kwargs["stdin"] == b"payload"
    assert kwargs["timeout_seconds"] == 5.0
    assert "max_output_bytes" not in kwargs
    assert "max_stdin_bytes" not in kwargs

    assert base64.b64decode(result.stdout_base64) == b"\x00\xff"
    assert base64.b64decode(result.stderr_base64) == b"warn\x80"
    assert result.request_id == "req_12345678"
    assert result.host == "developer-host"
    assert result.exit_status == 0
    assert result.duration_ms == 7


@pytest.mark.asyncio
async def test_ssh_exec_hides_nonvisible_host_before_executor() -> None:
    SSHExecRequest, _ = _ssh_exec_types()
    assert hasattr(MCPService, "ssh_exec")
    executor = RecordingExecutor()
    service = _service(executor)

    with pytest.raises(HostNotVisibleError, match="host is not visible"):
        await service.ssh_exec(
            PrincipalContext(profile="developer"),
            SSHExecRequest(
                host="ops-only-host",
                executable="/bin/echo",
            ),
        )

    assert executor.calls == []


@pytest.mark.asyncio
async def test_ssh_exec_rejects_timeout_larger_than_server_default() -> None:
    SSHExecRequest, _ = _ssh_exec_types()
    assert hasattr(MCPService, "ssh_exec")
    executor = RecordingExecutor()
    service = _service(executor)

    with pytest.raises(ApiError, match="execution request is invalid"):
        await service.ssh_exec(
            PrincipalContext(profile="developer"),
            SSHExecRequest(
                host="developer-host",
                executable="/bin/echo",
                timeout_seconds=61,
            ),
        )

    assert executor.calls == []


@pytest.mark.asyncio
async def test_ssh_exec_bounds_stdin_by_encoded_bytes() -> None:
    SSHExecRequest, _ = _ssh_exec_types()
    assert hasattr(MCPService, "ssh_exec")
    executor = RecordingExecutor()
    executor.default_max_stdin_bytes = 5
    service = _service(executor)

    with pytest.raises(ApiError, match="execution request is invalid"):
        await service.ssh_exec(
            PrincipalContext(profile="developer"),
            SSHExecRequest(
                host="developer-host",
                executable="/bin/echo",
                stdin="ééé",
            ),
        )

    assert executor.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_public_message"),
    [
        (
            SSHPolicyDenied(
                _decision(
                    Decision.DENY,
                    reason="secret-policy-rule-id",
                )
            ),
            "execution denied by central policy",
        ),
        (
            SSHApprovalRequired(
                _decision(
                    Decision.APPROVAL_REQUIRED,
                    reason="secret-approval-rule-id",
                    approval_required=True,
                )
            ),
            "execution requires approval",
        ),
        (
            SSHCredentialError("secret://developer-host"),
            "SSH credential unavailable",
        ),
        (
            SSHHostKeyVerificationError("secret-host-key-value"),
            "SSH host key verification failed",
        ),
        (
            SSHConnectionError("10.0.0.1 secret transport detail"),
            "SSH transport failed",
        ),
        (
            ProtocolError("secret envelope detail"),
            "execution request is invalid",
        ),
        (
            RuntimeError("secret library exception"),
            "SSH execution failed",
        ),
    ],
)
async def test_ssh_exec_normalizes_ssh_errors_without_secret_details(
    error: Exception,
    expected_public_message: str,
) -> None:
    SSHExecRequest, _ = _ssh_exec_types()
    assert hasattr(MCPService, "ssh_exec")
    service = _service(RecordingExecutor(error=error))

    with pytest.raises(ApiError) as exc_info:
        await service.ssh_exec(
            PrincipalContext(profile="developer"),
            SSHExecRequest(
                host="developer-host",
                executable="/bin/echo",
            ),
        )

    assert str(exc_info.value) == expected_public_message
    rendered = str(exc_info.value)
    for secret in (
        "secret-policy-rule-id",
        "secret-approval-rule-id",
        "secret://developer-host",
        "secret-host-key-value",
        "10.0.0.1",
        "secret envelope detail",
        "secret library exception",
    ):
        assert secret not in rendered
