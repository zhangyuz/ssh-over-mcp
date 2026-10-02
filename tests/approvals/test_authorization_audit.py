from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.errors import SSHApprovalRequired, SSHPolicyDenied


class Policy:
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.calls = []

    def evaluate(self, request: EvaluationRequest) -> PolicyDecision:
        self.calls.append(request)
        return self.decision


class Ledger:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.events = []

    async def append_audit(self, event) -> str:
        self.events.append(event)
        if self.error is not None:
            raise self.error
        return "evt_" + ("1" * 32)


def _context() -> OperationContext:
    return OperationContext(
        request_id="req_" + ("a" * 32),
        principal=PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        executable="/usr/bin/git",
        args=("status",),
        cwd="/srv/app",
        env={"SAFE": "value"},
        privilege="user",
    )


def _decision(decision: Decision) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="internal policy reason",
        risk=(
            RiskLevel.HIGH
            if decision is Decision.APPROVAL_REQUIRED
            else RiskLevel.LOW
        ),
        normalized_executable=(
            "/usr/bin/git"
            if decision is not Decision.DENY
            else None
        ),
        normalized_cwd=(
            "/srv/app"
            if decision is not Decision.DENY
            else None
        ),
        approval_required=decision is Decision.APPROVAL_REQUIRED,
        policy_version="sha256:test-policy",
    )


def _facts() -> ApprovalExecutionFacts:
    return ApprovalExecutionFacts(
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=1024,
        effective_max_stdin_bytes=1024,
        stdin_length=5,
        stdin_fingerprint="sha256:" + ("b" * 64),
    )


@pytest.mark.asyncio
async def test_audit_only_authorizer_allows_after_policy_event() -> None:
    from ssh_over_mcp.approvals.authorization import (
        AuditOnlyExecutionAuthorizer,
    )

    policy = Policy(_decision(Decision.ALLOW))
    ledger = Ledger()
    authorizer = AuditOnlyExecutionAuthorizer(
        policy=policy,
        ledger=ledger,
    )

    decision = await authorizer.authorize(
        _context(),
        _request(),
        _facts(),
    )

    assert decision.decision is Decision.ALLOW
    assert policy.calls == [_request()]
    assert len(ledger.events) == 1
    event = ledger.events[0]
    assert event.event_type is AuditEventType.POLICY_ALLOWED
    assert event.request_id == _context().request_id
    assert event.principal_id == "static:developer"
    assert event.profile == "developer"
    assert event.host == "dev01"
    assert event.tool == "ssh_exec"
    assert event.policy_version == "sha256:test-policy"
    assert event.decision is Decision.ALLOW
    assert event.risk is RiskLevel.LOW
    assert event.safe_summary is not None
    assert event.safe_summary.normalized_executable == "/usr/bin/git"
    assert event.safe_summary.argv_count == 1
    assert event.safe_summary.env_names == ("SAFE",)
    assert "value" not in event.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision", "event_type", "error_type"),
    [
        (
            Decision.DENY,
            AuditEventType.POLICY_DENIED,
            SSHPolicyDenied,
        ),
        (
            Decision.APPROVAL_REQUIRED,
            AuditEventType.APPROVAL_REQUIRED,
            SSHApprovalRequired,
        ),
    ],
)
async def test_audit_only_authorizer_records_failure_before_raising(
    decision: Decision,
    event_type: AuditEventType,
    error_type: type[Exception],
) -> None:
    from ssh_over_mcp.approvals.authorization import (
        AuditOnlyExecutionAuthorizer,
    )

    policy = Policy(_decision(decision))
    ledger = Ledger()
    authorizer = AuditOnlyExecutionAuthorizer(
        policy=policy,
        ledger=ledger,
    )

    with pytest.raises(error_type):
        await authorizer.authorize(
            _context(),
            _request(),
            _facts(),
        )

    assert len(policy.calls) == 1
    assert len(ledger.events) == 1
    assert ledger.events[0].event_type is event_type


@pytest.mark.asyncio
async def test_audit_only_authorizer_ledger_failure_is_stable_and_sanitized() -> None:
    from ssh_over_mcp.approvals.authorization import (
        AuditOnlyExecutionAuthorizer,
    )
    from ssh_over_mcp.ssh.errors import SSHAuditPersistenceError

    ledger = Ledger(RuntimeError("SUPERSECRET ledger failure"))
    authorizer = AuditOnlyExecutionAuthorizer(
        policy=Policy(_decision(Decision.ALLOW)),
        ledger=ledger,
    )

    with pytest.raises(
        SSHAuditPersistenceError,
        match="audit persistence failed",
    ) as exc_info:
        await authorizer.authorize(
            _context(),
            _request(),
            _facts(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
    assert len(ledger.events) == 1
