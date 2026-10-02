from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.approvals.binding import (
    build_approval_binding,
    safe_summary_from_binding,
)
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.policy.models import EvaluationRequest, PolicyDecision

from .models import AuditEventInput, AuditEventType

if TYPE_CHECKING:
    from ssh_over_mcp.ssh.transport import SSHExecutionResult


class AuditPersistenceFailure(RuntimeError):
    """A required Security Ledger audit append failed."""


class AuditLedger(Protocol):
    async def append_audit(self, event: AuditEventInput) -> str: ...


class AuditRecorder:
    def __init__(self, ledger: AuditLedger) -> None:
        self.ledger = ledger

    async def _append(self, event: AuditEventInput) -> str:
        try:
            return await self.ledger.append_audit(event)
        except Exception:  # noqa: BLE001
            raise AuditPersistenceFailure(
                "audit persistence failed"
            ) from None

    async def request_received(
        self,
        context: OperationContext,
        *,
        tool: str,
        host: str | None = None,
    ) -> str:
        return await self._append(
            AuditEventInput(
                event_type=AuditEventType.REQUEST_RECEIVED,
                request_id=context.request_id,
                principal_id=context.principal.principal_id,
                profile=context.principal.profile,
                host=host,
                tool=tool,
            )
        )

    async def simple_event(
        self,
        event_type: AuditEventType,
        *,
        context: OperationContext,
        tool: str,
        host: str | None = None,
    ) -> str:
        return await self._append(
            AuditEventInput(
                event_type=event_type,
                request_id=context.request_id,
                principal_id=context.principal.principal_id,
                profile=context.principal.profile,
                host=host,
                tool=tool,
            )
        )

    async def execution_event(
        self,
        event_type: AuditEventType,
        *,
        context: OperationContext,
        request: EvaluationRequest,
        decision: PolicyDecision,
        facts: ApprovalExecutionFacts,
        result: SSHExecutionResult | None = None,
    ) -> str:
        if result is not None and result.request_id != context.request_id:
            raise ValueError("audit result request ID does not match context")

        binding = build_approval_binding(
            context.principal,
            request,
            decision,
            facts,
        )
        summary = safe_summary_from_binding(binding, decision.risk)
        return await self._append(
            AuditEventInput(
                event_type=event_type,
                request_id=context.request_id,
                principal_id=context.principal.principal_id,
                profile=context.principal.profile,
                host=request.host,
                tool=request.tool,
                policy_version=decision.policy_version,
                decision=decision.decision,
                risk=decision.risk,
                safe_summary=summary,
                exit_status=(result.exit_status if result is not None else None),
                exit_signal=(result.exit_signal if result is not None else None),
                duration_ms=(result.duration_ms if result is not None else None),
                stdout_bytes=(len(result.stdout) if result is not None else None),
                stderr_bytes=(len(result.stderr) if result is not None else None),
                timed_out=(result.timed_out if result is not None else None),
                truncated=(result.truncated if result is not None else None),
            )
        )
