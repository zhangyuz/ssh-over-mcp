from __future__ import annotations

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.approvals.authorization import ExecutionAuthorizationGate
from ssh_over_mcp.approvals.binding import fingerprint_bytes
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.policy.models import EvaluationRequest

from .connection import SSHConnectionManager
from .errors import SSHPolicyDenied
from .protocol import ExecEnvelope, ExecutionLimits, encode_request
from .transport import SSHExecutionResult, StructuredSSHTransport


class SSHExecutor:
    """Policy-gated structured execution over a pooled SSH connection."""

    def __init__(
        self,
        *,
        authorizer: ExecutionAuthorizationGate,
        connections: SSHConnectionManager,
        default_timeout_seconds: float = 60.0,
        default_max_output_bytes: int = 1024 * 1024,
        default_max_stdin_bytes: int = 1024 * 1024,
        cleanup_timeout_seconds: float = 2.0,
        transport: StructuredSSHTransport | None = None,
    ) -> None:
        self.authorizer = authorizer
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
        context: OperationContext,
        stdin: bytes = b"",
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        max_stdin_bytes: int | None = None,
    ) -> SSHExecutionResult:
        if request.tool != "ssh_exec":
            raise ValueError(
                "SSHExecutor only accepts ssh_exec policy requests"
            )

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
        decision = await self.authorizer.authorize(
            context,
            request,
            ApprovalExecutionFacts(
                effective_timeout_seconds=timeout,
                effective_max_output_bytes=output_limit,
                effective_max_stdin_bytes=stdin_limit,
                stdin_length=len(stdin),
                stdin_fingerprint=fingerprint_bytes(stdin),
            ),
        )
        if not decision.normalized_executable:
            raise SSHPolicyDenied(decision)

        req_id = context.request_id

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
