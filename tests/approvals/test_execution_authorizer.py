from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.binding import (
    build_approval_binding,
    safe_summary_from_binding,
)
from ssh_over_mcp.approvals.models import (
    ApprovalExecutionFacts,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHPolicyDenied,
)


class Policy:
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.calls: list[EvaluationRequest] = []

    def evaluate(self, request: EvaluationRequest) -> PolicyDecision:
        self.calls.append(request)
        return self.decision


class RemoteLedgerError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__("remote ledger error")
        self.code = code


class Ledger:
    def __init__(self) -> None:
        self.events = []
        self.ensure_calls = []
        self.consume_calls = []
        self.ensure_error: Exception | None = None
        self.consume_error: Exception | None = None
        self.ensure_status: ApprovalStatus | None = None
        self.consume_status: ApprovalStatus | None = None

    async def append_audit(self, event) -> str:
        self.events.append(event)
        return "evt_" + ("1" * 32)

    async def ensure_approval(self, *, binding, risk, request_id):
        self.ensure_calls.append((binding, risk, request_id))
        if self.ensure_error is not None:
            raise self.ensure_error
        assert self.ensure_status is not None
        return self.ensure_status

    async def consume_approval(self, *, approval_id, binding, request_id):
        self.consume_calls.append((approval_id, binding, request_id))
        if self.consume_error is not None:
            raise self.consume_error
        assert self.consume_status is not None
        return self.consume_status


def _request(*, args: tuple[str, ...] = ("status",)) -> EvaluationRequest:
    return EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        executable="/usr/bin/git",
        args=args,
        cwd="/srv/app",
        env={"SAFE": "value"},
        privilege="user",
    )


def _decision(decision: Decision, *, policy_version: str = "sha256:policy") -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="internal policy detail",
        risk=RiskLevel.HIGH if decision is Decision.APPROVAL_REQUIRED else RiskLevel.LOW,
        normalized_executable="/usr/bin/git" if decision is not Decision.DENY else None,
        normalized_cwd="/srv/app" if decision is not Decision.DENY else None,
        approval_required=decision is Decision.APPROVAL_REQUIRED,
        policy_version=policy_version,
    )


def _facts() -> ApprovalExecutionFacts:
    return ApprovalExecutionFacts(
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=1024,
        effective_max_stdin_bytes=1024,
        stdin_length=5,
        stdin_fingerprint="sha256:" + ("b" * 64),
    )


def _context(*, approval_id: str | None = None) -> OperationContext:
    return OperationContext(
        request_id="req_" + ("a" * 32),
        principal=PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, 18, 0, tzinfo=UTC),
        approval_id=approval_id,
    )


def _status(
    *,
    state: ApprovalState,
    approval_id: str = "apr_" + ("c" * 32),
    request: EvaluationRequest | None = None,
    decision: PolicyDecision | None = None,
) -> ApprovalStatus:
    request = request or _request()
    decision = decision or _decision(Decision.APPROVAL_REQUIRED)
    binding = build_approval_binding(
        _context().principal,
        request,
        decision,
        _facts(),
    )
    return ApprovalStatus(
        approval_id=approval_id,
        state=state,
        expires_at=datetime(2026, 10, 1, 18, 10, tzinfo=UTC),
        host=binding.host,
        tool=binding.tool,
        risk=decision.risk,
        safe_summary=safe_summary_from_binding(binding, decision.risk),
        binding_fingerprint="hmac-sha256:v1:" + ("d" * 16),
    )


@pytest.mark.asyncio
async def test_allow_ignores_stale_approval_handle() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    ledger = Ledger()
    policy = Policy(_decision(Decision.ALLOW))
    authorizer = ExecutionAuthorizer(policy=policy, ledger=ledger)

    decision = await authorizer.authorize(
        _context(approval_id="apr_" + ("9" * 32)),
        _request(),
        _facts(),
    )

    assert decision.decision is Decision.ALLOW
    assert ledger.ensure_calls == []
    assert ledger.consume_calls == []
    assert [event.event_type for event in ledger.events] == [
        AuditEventType.POLICY_ALLOWED
    ]


@pytest.mark.asyncio
async def test_deny_never_consumes_supplied_approval() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    ledger = Ledger()
    authorizer = ExecutionAuthorizer(
        policy=Policy(_decision(Decision.DENY)),
        ledger=ledger,
    )

    with pytest.raises(SSHPolicyDenied):
        await authorizer.authorize(
            _context(approval_id="apr_" + ("9" * 32)),
            _request(),
            _facts(),
        )

    assert ledger.ensure_calls == []
    assert ledger.consume_calls == []
    assert [event.event_type for event in ledger.events] == [
        AuditEventType.POLICY_DENIED
    ]


@pytest.mark.asyncio
async def test_approval_required_without_handle_creates_pending_status() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    decision = _decision(Decision.APPROVAL_REQUIRED)
    ledger = Ledger()
    ledger.ensure_status = _status(state=ApprovalState.PENDING, decision=decision)
    authorizer = ExecutionAuthorizer(policy=Policy(decision), ledger=ledger)

    with pytest.raises(SSHApprovalRequired) as exc_info:
        await authorizer.authorize(_context(), _request(), _facts())

    assert exc_info.value.approval_status == ledger.ensure_status
    assert len(ledger.ensure_calls) == 1
    binding, risk, request_id = ledger.ensure_calls[0]
    assert binding.principal_id == "static:developer"
    assert binding.argv_count == 1
    assert risk is RiskLevel.HIGH
    assert request_id == _context().request_id
    assert ledger.events == []


@pytest.mark.asyncio
async def test_granted_exact_approval_is_consumed_before_authorization() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    approval_id = "apr_" + ("c" * 32)
    decision = _decision(Decision.APPROVAL_REQUIRED)
    ledger = Ledger()
    ledger.consume_status = _status(
        state=ApprovalState.CONSUMED,
        approval_id=approval_id,
        decision=decision,
    )
    authorizer = ExecutionAuthorizer(policy=Policy(decision), ledger=ledger)

    result = await authorizer.authorize(
        _context(approval_id=approval_id),
        _request(),
        _facts(),
    )

    assert result == decision
    assert ledger.ensure_calls == []
    assert len(ledger.consume_calls) == 1
    consumed_id, binding, request_id = ledger.consume_calls[0]
    assert consumed_id == approval_id
    assert binding.policy_version == "sha256:policy"
    assert request_id == _context().request_id
    assert [event.event_type for event in ledger.events] == [
        AuditEventType.APPROVAL_REQUIRED
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code",
    ["not_found", "not_authorized", "conflict", "expired"],
)
async def test_unusable_supplied_approval_is_normalized_without_oracle_detail(
    code: str,
) -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    decision = _decision(Decision.APPROVAL_REQUIRED)
    ledger = Ledger()
    ledger.consume_error = RemoteLedgerError(code)
    authorizer = ExecutionAuthorizer(policy=Policy(decision), ledger=ledger)

    with pytest.raises(SSHApprovalRequired) as exc_info:
        await authorizer.authorize(
            _context(approval_id="apr_" + ("9" * 32)),
            _request(),
            _facts(),
        )

    assert exc_info.value.approval_status is None
    assert code not in str(exc_info.value)


@pytest.mark.asyncio
async def test_approval_ledger_failure_is_sanitized() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    decision = _decision(Decision.APPROVAL_REQUIRED)
    ledger = Ledger()
    ledger.ensure_error = RuntimeError("SUPERSECRET ledger failure")
    authorizer = ExecutionAuthorizer(policy=Policy(decision), ledger=ledger)

    with pytest.raises(
        SSHAuditPersistenceError,
        match="approval persistence failed",
    ) as exc_info:
        await authorizer.authorize(_context(), _request(), _facts())

    assert "SUPERSECRET" not in str(exc_info.value)


class BindingCheckingLedger(Ledger):
    def __init__(self, expected_binding) -> None:
        super().__init__()
        self.expected_binding = expected_binding
        self.consume_status = _status(state=ApprovalState.CONSUMED)

    async def consume_approval(self, *, approval_id, binding, request_id):
        self.consume_calls.append((approval_id, binding, request_id))
        if binding != self.expected_binding:
            raise RemoteLedgerError("not_authorized")
        assert self.consume_status is not None
        return self.consume_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("eval_request", "context", "decision"),
    [
        (
            _request(args=("log",)),
            _context(approval_id="apr_" + ("c" * 32)),
            _decision(Decision.APPROVAL_REQUIRED),
        ),
        (
            EvaluationRequest(
                profile="ops",
                host="dev01",
                tool="ssh_exec",
                executable="/usr/bin/git",
                args=("status",),
                cwd="/srv/app",
                env={"SAFE": "value"},
                privilege="user",
            ),
            OperationContext(
                request_id="req_" + ("e" * 32),
                principal=PrincipalContext(
                    principal_id="static:ops",
                    profile="ops",
                ),
                received_at=datetime(2026, 10, 1, 18, 0, tzinfo=UTC),
                approval_id="apr_" + ("c" * 32),
            ),
            _decision(Decision.APPROVAL_REQUIRED),
        ),
        (
            _request(),
            _context(approval_id="apr_" + ("c" * 32)),
            _decision(
                Decision.APPROVAL_REQUIRED,
                policy_version="sha256:new-policy",
            ),
        ),
    ],
)
async def test_binding_change_cannot_consume_existing_grant(
    eval_request: EvaluationRequest,
    context: OperationContext,
    decision: PolicyDecision,
) -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    original_decision = _decision(Decision.APPROVAL_REQUIRED)
    expected = build_approval_binding(
        _context().principal,
        _request(),
        original_decision,
        _facts(),
    )
    ledger = BindingCheckingLedger(expected)
    authorizer = ExecutionAuthorizer(policy=Policy(decision), ledger=ledger)

    with pytest.raises(SSHApprovalRequired):
        await authorizer.authorize(context, eval_request, _facts())

    assert len(ledger.consume_calls) == 1


@pytest.mark.asyncio
async def test_policy_change_to_allow_does_not_consume_old_grant() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer

    ledger = Ledger()
    authorizer = ExecutionAuthorizer(
        policy=Policy(_decision(Decision.ALLOW)),
        ledger=ledger,
    )

    result = await authorizer.authorize(
        _context(approval_id="apr_" + ("c" * 32)),
        _request(),
        _facts(),
    )

    assert result.decision is Decision.ALLOW
    assert ledger.consume_calls == []


class SingleUseLedger(Ledger):
    def __init__(self, status: ApprovalStatus) -> None:
        super().__init__()
        self.consume_status = status
        self._consumed = False

    async def consume_approval(self, *, approval_id, binding, request_id):
        import asyncio

        self.consume_calls.append((approval_id, binding, request_id))
        await asyncio.sleep(0)
        if self._consumed:
            raise RemoteLedgerError("conflict")
        self._consumed = True
        assert self.consume_status is not None
        return self.consume_status


class RecordingTransport:
    def __init__(self) -> None:
        self.calls = []

    async def run(self, **kwargs):
        from ssh_over_mcp.ssh.transport import SSHExecutionResult

        self.calls.append(kwargs)
        return SSHExecutionResult(
            request_id=kwargs["request_id"],
            host=kwargs["host"],
            exit_status=0,
            duration_ms=1,
        )


@pytest.mark.asyncio
async def test_concurrent_retries_with_one_grant_reach_transport_once() -> None:
    import asyncio

    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer
    from ssh_over_mcp.audit.recorder import AuditRecorder
    from ssh_over_mcp.ssh.executor import SSHExecutor

    approval_id = "apr_" + ("c" * 32)
    decision = _decision(Decision.APPROVAL_REQUIRED)
    ledger = SingleUseLedger(
        _status(
            state=ApprovalState.CONSUMED,
            approval_id=approval_id,
            decision=decision,
        )
    )
    authorizer = ExecutionAuthorizer(policy=Policy(decision), ledger=ledger)
    transport = RecordingTransport()
    executor = SSHExecutor(
        authorizer=authorizer,
        audit=AuditRecorder(ledger),
        connections=object(),
        transport=transport,
    )

    async def execute(request_id_char: str):
        context = OperationContext(
            request_id="req_" + (request_id_char * 32),
            principal=_context().principal,
            received_at=_context().received_at,
            approval_id=approval_id,
        )
        return await executor.execute(
            _request(),
            context=context,
            stdin=b"hello",
            timeout_seconds=60.0,
            max_output_bytes=1024,
            max_stdin_bytes=1024,
        )

    results = await asyncio.gather(
        execute("1"),
        execute("2"),
        return_exceptions=True,
    )

    assert sum(not isinstance(item, BaseException) for item in results) == 1
    failures = [item for item in results if isinstance(item, BaseException)]
    assert len(failures) == 1
    assert isinstance(failures[0], SSHApprovalRequired)
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_approval_ledger_failure_keeps_transport_zero() -> None:
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer
    from ssh_over_mcp.audit.recorder import AuditRecorder
    from ssh_over_mcp.ssh.executor import SSHExecutor

    decision = _decision(Decision.APPROVAL_REQUIRED)
    ledger = Ledger()
    ledger.ensure_error = RuntimeError("SUPERSECRET ledger unavailable")
    transport = RecordingTransport()
    executor = SSHExecutor(
        authorizer=ExecutionAuthorizer(
            policy=Policy(decision),
            ledger=ledger,
        ),
        audit=AuditRecorder(ledger),
        connections=object(),
        transport=transport,
    )

    with pytest.raises(
        SSHAuditPersistenceError,
        match="approval persistence failed",
    ) as exc_info:
        await executor.execute(
            _request(),
            context=_context(),
            stdin=b"hello",
            timeout_seconds=60.0,
            max_output_bytes=1024,
            max_stdin_bytes=1024,
        )

    assert "SUPERSECRET" not in str(exc_info.value)
    assert transport.calls == []
