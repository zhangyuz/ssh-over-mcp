from __future__ import annotations

import uuid
from typing import Protocol

from ssh_over_mcp.policy.models import Decision, EvaluationRequest

from .connection import SSHConnectionManager
from .errors import SSHApprovalRequired, SSHPolicyDenied
from .protocol import ExecEnvelope, ExecutionLimits, encode_request
from .transport import SSHExecutionResult, StructuredSSHTransport


class PolicyEvaluator(Protocol):
    def evaluate(self, request: EvaluationRequest): ...


class SSHExecutor:
    """Policy-gated structured execution over a pooled SSH connection."""

    def __init__(
        self,
        *,
        policy: PolicyEvaluator,
        connections: SSHConnectionManager,
        default_timeout_seconds: float = 60.0,
        default_max_output_bytes: int = 1024 * 1024,
        default_max_stdin_bytes: int = 1024 * 1024,
        cleanup_timeout_seconds: float = 2.0,
        transport: StructuredSSHTransport | None = None,
    ) -> None:
        self.policy = policy
        self.connections = connections
        self.default_timeout_seconds = default_timeout_seconds
        self.default_max_output_bytes = default_max_output_bytes
        self.default_max_stdin_bytes = default_max_stdin_bytes
        self.cleanup_timeout_seconds = cleanup_timeout_seconds
        self.transport = transport or StructuredSSHTransport(
            connections=connections,
            cleanup_timeout_seconds=cleanup_timeout_seconds,
        )

    async def execute(
        self,
        request: EvaluationRequest,
        *,
        stdin: bytes = b"",
        request_id: str | None = None,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        max_stdin_bytes: int | None = None,
    ) -> SSHExecutionResult:
        if request.tool != "ssh_exec":
            raise ValueError(
                "SSHExecutor only accepts ssh_exec policy requests"
            )

        # The network path cannot be reached before an allow decision.
        decision = self.policy.evaluate(request)
        if decision.decision == Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision == Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        if not decision.normalized_executable:
            raise SSHPolicyDenied(decision)

        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self.default_timeout_seconds
        )
        output_limit = (
            max_output_bytes
            if max_output_bytes is not None
            else self.default_max_output_bytes
        )
        stdin_limit = (
            max_stdin_bytes
            if max_stdin_bytes is not None
            else self.default_max_stdin_bytes
        )
        req_id = request_id or f"req_{uuid.uuid4().hex}"

        envelope = ExecEnvelope(
            request_id=req_id,
            profile=request.profile,
            executable=decision.normalized_executable,
            argv=request.args,
            cwd=decision.normalized_cwd,
            env=request.env,
            limits=ExecutionLimits(
                timeout_seconds=timeout,
                max_output_bytes=output_limit,
                max_stdin_bytes=stdin_limit,
            ),
        )
        payload = encode_request(envelope, stdin)

        return await self.transport.run(
            host=request.host,
            payload=payload,
            request_id=req_id,
            timeout_seconds=timeout,
            max_output_bytes=output_limit,
        )
