from __future__ import annotations

from typing import TYPE_CHECKING

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
)

from .errors import (
    HostNotVisibleError,
    InvalidExplainToolError,
)
from .models import (
    HostsListResult,
    HostSummary,
    PolicyExplainRequest,
    PolicyExplainResult,
    PrincipalContext,
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
