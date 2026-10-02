from __future__ import annotations

from typing import Protocol

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
)
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHPolicyDenied,
)

from .binding import build_approval_binding, safe_summary_from_binding
from .models import ApprovalExecutionFacts


class PolicyEvaluator(Protocol):
    def evaluate(self, request: EvaluationRequest) -> PolicyDecision: ...


class AuditLedger(Protocol):
    async def append_audit(self, event: AuditEventInput) -> str: ...


class ExecutionAuthorizationGate(Protocol):
    async def authorize(
        self,
        context: OperationContext,
        request: EvaluationRequest,
        facts: ApprovalExecutionFacts,
    ) -> PolicyDecision: ...


_EVENT_BY_DECISION = {
    Decision.ALLOW: AuditEventType.POLICY_ALLOWED,
    Decision.DENY: AuditEventType.POLICY_DENIED,
    Decision.APPROVAL_REQUIRED: AuditEventType.APPROVAL_REQUIRED,
}


class AuditOnlyExecutionAuthorizer:
    def __init__(
        self,
        *,
        policy: PolicyEvaluator,
        ledger: AuditLedger,
    ) -> None:
        self.policy = policy
        self.ledger = ledger

    async def authorize(
        self,
        context: OperationContext,
        request: EvaluationRequest,
        facts: ApprovalExecutionFacts,
    ) -> PolicyDecision:
        decision = self.policy.evaluate(request)
        binding = build_approval_binding(
            context.principal,
            request,
            decision,
            facts,
        )
        summary = safe_summary_from_binding(
            binding,
            decision.risk,
        )
        try:
            await self.ledger.append_audit(
                AuditEventInput(
                    event_type=_EVENT_BY_DECISION[decision.decision],
                    request_id=context.request_id,
                    principal_id=context.principal.principal_id,
                    profile=context.principal.profile,
                    host=request.host,
                    tool=request.tool,
                    policy_version=decision.policy_version,
                    decision=decision.decision,
                    risk=decision.risk,
                    safe_summary=summary,
                )
            )
        except Exception:  # noqa: BLE001
            raise SSHAuditPersistenceError(
                "audit persistence failed"
            ) from None

        if decision.decision is Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision is Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        return decision
