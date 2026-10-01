from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
)
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHConnectionError,
    SSHCredentialError,
    SSHHostKeyVerificationError,
    SSHPolicyDenied,
)
from ssh_over_mcp.ssh.protocol import ProtocolError

from .errors import (
    ExecutionApprovalRequiredError,
    ExecutionCredentialError,
    ExecutionFailureError,
    ExecutionHostKeyError,
    ExecutionPolicyDeniedError,
    ExecutionRequestError,
    ExecutionTransportError,
    HostNotVisibleError,
    InvalidExplainToolError,
    RuntimeConfigurationError,
)
from .models import (
    HostsListResult,
    HostSummary,
    PolicyExplainRequest,
    PolicyExplainResult,
    PrincipalContext,
    SSHExecRequest,
    SSHExecResult,
)

if TYPE_CHECKING:
    from ssh_over_mcp.ssh.executor import SSHExecutor


_EXPLAINABLE_TOOLS = frozenset(
    {
        "ssh_exec",
        "fs_stat",
        "fs_read",
        "fs_mkdir",
        "fs_write",
    }
)

_PUBLIC_REASONS = {
    Decision.ALLOW: "allowed by central policy",
    Decision.DENY: "denied by central policy",
    Decision.APPROVAL_REQUIRED: "approval required by central policy",
}


class MCPService:
    def __init__(
        self,
        *,
        inventory: Inventory,
        policy: PolicyEngine,
        ssh_executor: SSHExecutor | None = None,
    ) -> None:
        self._inventory = inventory
        self._policy = policy
        self._ssh_executor = ssh_executor

    @staticmethod
    def _is_visible(host: Host, profile: str) -> bool:
        return not host.allowed_roles or profile in host.allowed_roles

    def _visible_host(
        self,
        principal: PrincipalContext,
        alias: str,
    ) -> Host:
        host = self._inventory.hosts.get(alias)
        if host is None or not self._is_visible(host, principal.profile):
            raise HostNotVisibleError("host is not visible")
        return host

    @staticmethod
    def _summary(alias: str) -> HostSummary:
        return HostSummary(alias=alias)

    def list_hosts(
        self,
        principal: PrincipalContext,
    ) -> HostsListResult:
        visible = tuple(
            self._summary(alias)
            for alias, host in sorted(self._inventory.hosts.items())
            if self._is_visible(host, principal.profile)
        )
        return HostsListResult(hosts=visible)

    def get_host(
        self,
        principal: PrincipalContext,
        alias: str,
    ) -> HostSummary:
        self._visible_host(principal, alias)
        return self._summary(alias)

    def explain_policy(
        self,
        principal: PrincipalContext,
        request: PolicyExplainRequest,
    ) -> PolicyExplainResult:
        self._visible_host(principal, request.host)
        if request.tool not in _EXPLAINABLE_TOOLS:
            raise InvalidExplainToolError(
                "policy explanation tool is invalid"
            )

        decision = self._policy.evaluate(
            EvaluationRequest(
                profile=principal.profile,
                host=request.host,
                tool=request.tool,
                executable=request.executable,
                args=request.args,
                cwd=request.cwd,
                path=request.path,
                env=request.env,
                privilege=request.privilege,
            )
        )

        return PolicyExplainResult(
            decision=decision.decision,
            reason=_PUBLIC_REASONS[decision.decision],
            risk=decision.risk,
            normalized_executable=decision.normalized_executable,
            normalized_cwd=decision.normalized_cwd,
            normalized_path=decision.normalized_path,
            approval_required=decision.approval_required,
            policy_version=decision.policy_version,
        )

    async def ssh_exec(
        self,
        principal: PrincipalContext,
        request: SSHExecRequest,
    ) -> SSHExecResult:
        self._visible_host(principal, request.host)
        executor = self._ssh_executor
        if executor is None:
            raise RuntimeConfigurationError(
                "runtime configuration is invalid"
            )

        if (
            request.timeout_seconds is not None
            and request.timeout_seconds > executor.default_timeout_seconds
        ):
            raise ExecutionRequestError(
                "execution request is invalid"
            )

        stdin = (
            b""
            if request.stdin is None
            else request.stdin.encode("utf-8")
        )
        if len(stdin) > executor.default_max_stdin_bytes:
            raise ExecutionRequestError(
                "execution request is invalid"
            )

        evaluation = EvaluationRequest(
            profile=principal.profile,
            host=request.host,
            tool="ssh_exec",
            executable=request.executable,
            args=request.args,
            cwd=request.cwd,
            env=request.env,
            privilege="user",
        )

        try:
            result = await executor.execute(
                evaluation,
                stdin=stdin,
                timeout_seconds=request.timeout_seconds,
            )
        except SSHPolicyDenied:
            raise ExecutionPolicyDeniedError(
                "execution denied by central policy"
            ) from None
        except SSHApprovalRequired:
            raise ExecutionApprovalRequiredError(
                "execution requires approval"
            ) from None
        except SSHCredentialError:
            raise ExecutionCredentialError(
                "SSH credential unavailable"
            ) from None
        except SSHHostKeyVerificationError:
            raise ExecutionHostKeyError(
                "SSH host key verification failed"
            ) from None
        except SSHConnectionError:
            raise ExecutionTransportError(
                "SSH transport failed"
            ) from None
        except ProtocolError:
            raise ExecutionRequestError(
                "execution request is invalid"
            ) from None
        except Exception:
            raise ExecutionFailureError(
                "SSH execution failed"
            ) from None

        return SSHExecResult(
            request_id=result.request_id,
            host=result.host,
            exit_status=result.exit_status,
            exit_signal=result.exit_signal,
            stdout_base64=base64.b64encode(result.stdout).decode("ascii"),
            stderr_base64=base64.b64encode(result.stderr).decode("ascii"),
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            truncated=result.truncated,
        )
