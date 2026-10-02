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
from .models import (
    ApprovalBindingInput,
    ApprovalExecutionFacts,
    ApprovalState,
    ApprovalStatus,
)


class PolicyEvaluator(Protocol):
    def evaluate(self, request: EvaluationRequest) -> PolicyDecision: ...


class AuditLedger(Protocol):
    async def append_audit(self, event: AuditEventInput) -> str: ...


class ApprovalLedger(AuditLedger, Protocol):
    async def ensure_approval(
        self,
        *,
        binding: ApprovalBindingInput,
        risk,
        request_id: str,
    ) -> ApprovalStatus: ...

    async def consume_approval(
        self,
        *,
        approval_id: str,
        binding: ApprovalBindingInput,
        request_id: str,
    ) -> ApprovalStatus: ...


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


_UNUSABLE_APPROVAL_CODES = frozenset(
    {"not_found", "not_authorized", "conflict", "expired"}
)


class ExecutionAuthorizer:
    def __init__(
        self,
        *,
        policy: PolicyEvaluator,
        ledger: ApprovalLedger,
    ) -> None:
        self.policy = policy
        self.ledger = ledger

    async def _append_policy_event(
        self,
        *,
        context: OperationContext,
        request: EvaluationRequest,
        decision: PolicyDecision,
        binding: ApprovalBindingInput,
    ) -> None:
        summary = safe_summary_from_binding(binding, decision.risk)
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

        if decision.decision is Decision.ALLOW:
            await self._append_policy_event(
                context=context,
                request=request,
                decision=decision,
                binding=binding,
            )
            return decision

        if decision.decision is Decision.DENY:
            await self._append_policy_event(
                context=context,
                request=request,
                decision=decision,
                binding=binding,
            )
            raise SSHPolicyDenied(decision)

        approval_id = context.approval_id
        if approval_id is None:
            try:
                status = await self.ledger.ensure_approval(
                    binding=binding,
                    risk=decision.risk,
                    request_id=context.request_id,
                )
            except Exception:  # noqa: BLE001
                raise SSHAuditPersistenceError(
                    "approval persistence failed"
                ) from None
            raise SSHApprovalRequired(
                decision,
                approval_status=status,
            )

        await self._append_policy_event(
            context=context,
            request=request,
            decision=decision,
            binding=binding,
        )
        try:
            status = await self.ledger.consume_approval(
                approval_id=approval_id,
                binding=binding,
                request_id=context.request_id,
            )
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) in _UNUSABLE_APPROVAL_CODES:
                raise SSHApprovalRequired(decision) from None
            raise SSHAuditPersistenceError(
                "approval persistence failed"
            ) from None

        if status.state is not ApprovalState.CONSUMED:
            raise SSHApprovalRequired(decision)
        return decision
