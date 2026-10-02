from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer
from ssh_over_mcp.approvals.binding import (
    build_approval_binding,
    fingerprint_argv,
    fingerprint_bytes,
    fingerprint_text,
    safe_summary_from_binding,
)
from ssh_over_mcp.approvals.ledger import (
    LedgerConflictError,
    LedgerExpiredError,
    LedgerNotAuthorizedError,
    LedgerNotFoundError,
    SecurityLedgerStore,
)
from ssh_over_mcp.approvals.models import (
    ApprovalBindingInput,
    ApprovalEnvFingerprint,
    ApprovalExecutionFacts,
    ApprovalState,
)
from ssh_over_mcp.approvals.storage import LedgerDatabase, LedgerStorageSettings
from ssh_over_mcp.audit.recorder import (
    AuditPersistenceFailure,
    AuditRecorder,
)
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHAuditPersistenceOutcomeUncertain,
    SSHFilesystemWriteCommittedUncertain,
    SSHPolicyDenied,
    SSHRequestOutcomeUncertain,
)
from ssh_over_mcp.ssh.executor import SSHExecutor
from ssh_over_mcp.ssh.filesystem import SSHFilesystemClient
from ssh_over_mcp.ssh.transport import SSHExecutionResult


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


def _settings(tmp_path: Path) -> LedgerStorageSettings:
    data_dir = tmp_path / "ledger"
    data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(data_dir, 0o700)
    key_path = data_dir / "ledger.key"
    if not key_path.exists():
        key_path.write_bytes(b"K" * 32)
    os.chmod(key_path, 0o600)
    info = data_dir.stat()
    return LedgerStorageSettings(
        db_path=data_dir / "ledger.db",
        hmac_key_path=key_path,
        service_uid=info.st_uid,
        service_gid=info.st_gid,
    )


def _open_store(
    tmp_path: Path,
    clock: Clock,
    *,
    ttl_seconds: int = 600,
) -> tuple[LedgerDatabase, SecurityLedgerStore]:
    database = LedgerDatabase.open(_settings(tmp_path))
    return database, SecurityLedgerStore(
        database,
        b"K" * 32,
        clock=clock,
        default_ttl_seconds=ttl_seconds,
    )


def _request_id(label: str) -> str:
    return "req_" + hashlib.sha256(label.encode()).hexdigest()[:32]


def _principal(principal_id: str = "static:developer") -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal_id,
        profile="developer",
    )


def _context(
    label: str,
    *,
    approval_id: str | None = None,
    principal_id: str = "static:developer",
) -> OperationContext:
    return OperationContext(
        request_id=_request_id(label),
        principal=_principal(principal_id),
        received_at=datetime(2026, 10, 2, 11, 0, tzinfo=UTC),
        approval_id=approval_id,
    )


def _full_binding(*, path: str = "/srv/app/file") -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_write",
        privilege="user",
        policy_version="sha256:policy-v1",
        normalized_executable="/usr/bin/tool",
        normalized_cwd="/srv/app",
        normalized_path=path,
        argv_count=1,
        argv_fingerprint=fingerprint_argv(("ARG_SECRET",)),
        env_fingerprints=(
            ApprovalEnvFingerprint(
                name="TOKEN",
                value_fingerprint=fingerprint_text("ENV_SECRET"),
            ),
        ),
        stdin_length=len(b"STDIN"),
        stdin_fingerprint=fingerprint_bytes(b"STDIN"),
        content_length=len(b"CONTENT"),
        content_fingerprint=fingerprint_bytes(b"CONTENT"),
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
        effective_max_stdin_bytes=1024,
        effective_tool_bytes=2048,
    )


def _summary(binding: ApprovalBindingInput):
    return safe_summary_from_binding(binding, RiskLevel.HIGH)


class StoreRemoteError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__("ledger operation unavailable")
        self.code = code


class AsyncStoreLedger:
    def __init__(self, store: SecurityLedgerStore) -> None:
        self.store = store
        self.consume_calls = 0
        self.ensure_calls = 0
        self.append_calls = 0

    async def append_audit(self, event) -> str:
        self.append_calls += 1
        return self.store.append_audit(event)

    async def ensure_approval(self, *, binding, risk, request_id):
        self.ensure_calls += 1
        return self.store.ensure_approval(
            binding,
            safe_summary_from_binding(binding, risk),
            request_id,
        )

    async def consume_approval(self, *, approval_id, binding, request_id):
        self.consume_calls += 1
        await asyncio.sleep(0)
        try:
            return self.store.consume(
                approval_id,
                binding,
                request_id,
            )
        except LedgerExpiredError:
            raise StoreRemoteError("expired") from None
        except LedgerNotAuthorizedError:
            raise StoreRemoteError("not_authorized") from None
        except LedgerNotFoundError:
            raise StoreRemoteError("not_found") from None
        except LedgerConflictError:
            raise StoreRemoteError("conflict") from None


class MutablePolicy:
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.calls: list[EvaluationRequest] = []

    def evaluate(self, request: EvaluationRequest) -> PolicyDecision:
        self.calls.append(request)
        return self.decision


def _approval_case(
    tool: str,
) -> tuple[EvaluationRequest, PolicyDecision, ApprovalExecutionFacts]:
    common = {
        "profile": "developer",
        "host": "dev01",
        "tool": tool,
        "privilege": "user",
    }
    decision_kwargs = {
        "decision": Decision.APPROVAL_REQUIRED,
        "reason": "operator approval required",
        "risk": RiskLevel.HIGH,
        "approval_required": True,
        "policy_version": "sha256:phase5",
    }
    if tool == "ssh_exec":
        request = EvaluationRequest(
            **common,
            executable="/usr/bin/git",
            args=("status",),
            cwd="/srv/app",
            env={"TOKEN": "ENV_SECRET"},
        )
        decision = PolicyDecision(
            **decision_kwargs,
            normalized_executable="/usr/bin/git",
            normalized_cwd="/srv/app",
        )
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=1024,
            effective_max_stdin_bytes=1024,
            stdin_length=5,
            stdin_fingerprint=fingerprint_bytes(b"hello"),
        )
        return request, decision, facts

    request = EvaluationRequest(
        **common,
        path=f"/srv/app/{tool}",
    )
    decision = PolicyDecision(
        **decision_kwargs,
        normalized_path=f"/srv/app/{tool}",
    )
    if tool == "fs_stat":
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=64 * 1024,
        )
    elif tool == "fs_read":
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=4096,
            effective_tool_bytes=4096,
        )
    elif tool == "fs_mkdir":
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=4096,
        )
    elif tool == "fs_write":
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=4096,
            content_length=7,
            content_fingerprint=fingerprint_bytes(b"CONTENT"),
        )
    else:  # pragma: no cover - guarded by parametrization
        raise AssertionError(tool)
    return request, decision, facts


class RecordingTransport:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        exit_status: int | None = 0,
    ) -> None:
        self.stdout = stdout
        self.exit_status = exit_status
        self.calls: list[dict[str, object]] = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return SSHExecutionResult(
            request_id=kwargs["request_id"],
            host=kwargs["host"],
            exit_status=self.exit_status,
            stdout=self.stdout,
            duration_ms=1,
        )


class FaultLedger:
    def __init__(
        self,
        *,
        fail_append_on: int | None = None,
        fail_ensure: bool = False,
        fail_consume: bool = False,
    ) -> None:
        self.fail_append_on = fail_append_on
        self.fail_ensure = fail_ensure
        self.fail_consume = fail_consume
        self.append_calls = 0
        self.status = None

    async def append_audit(self, event) -> str:
        self.append_calls += 1
        if self.fail_append_on == self.append_calls:
            raise RuntimeError("SUPERSECRET ledger append failure")
        return "evt_" + ("a" * 32)

    async def ensure_approval(self, *, binding, risk, request_id):
        if self.fail_ensure:
            raise RuntimeError("SUPERSECRET approval persistence failure")
        assert self.status is not None
        return self.status

    async def consume_approval(self, *, approval_id, binding, request_id):
        if self.fail_consume:
            raise RuntimeError("SUPERSECRET approval consume failure")
        assert self.status is not None
        return self.status


def test_restart_matrix_preserves_terminal_states_and_expiry_once(
    tmp_path: Path,
) -> None:
    clock = Clock(datetime(2026, 10, 2, 10, 0, tzinfo=UTC))

    database, store = _open_store(tmp_path, clock, ttl_seconds=10)
    expired_binding = _full_binding(path="/srv/app/expired")
    expired = store.ensure_approval(
        expired_binding,
        _summary(expired_binding),
        _request_id("expired"),
    )
    clock.advance(seconds=11)
    expired_status = store.get_approval(expired.approval_id)
    assert expired_status is not None
    assert expired_status.state is ApprovalState.EXPIRED
    database.close()

    database, store = _open_store(tmp_path, clock, ttl_seconds=600)
    statuses: dict[str, str] = {}
    for state_name in ("pending", "granted", "denied", "consumed"):
        binding = _full_binding(path=f"/srv/app/{state_name}")
        status = store.ensure_approval(
            binding,
            _summary(binding),
            _request_id(state_name),
        )
        if state_name == "granted":
            status = store.grant(
                status.approval_id,
                operator_identity="uid:0:gid:0",
            )
        elif state_name == "denied":
            status = store.deny(
                status.approval_id,
                operator_identity="uid:0:gid:0",
            )
        elif state_name == "consumed":
            store.grant(
                status.approval_id,
                operator_identity="uid:0:gid:0",
            )
            status = store.consume(
                status.approval_id,
                binding,
                _request_id("consume-retry"),
            )
        statuses[state_name] = status.approval_id
    database.close()

    database, restarted = _open_store(tmp_path, clock, ttl_seconds=600)
    try:
        expected = {
            "pending": ApprovalState.PENDING,
            "granted": ApprovalState.GRANTED,
            "denied": ApprovalState.DENIED,
            "consumed": ApprovalState.CONSUMED,
        }
        for name, expected_state in expected.items():
            status = restarted.get_approval(statuses[name])
            assert status is not None
            assert status.state is expected_state

        for _ in range(2):
            status = restarted.get_approval(expired.approval_id)
            assert status is not None
            assert status.state is ApprovalState.EXPIRED
        expiry_events = database.connection.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE event_type='approval_expired' AND approval_id=?",
            (expired.approval_id,),
        ).fetchone()
        assert expiry_events == (1,)
    finally:
        database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool",
    ["ssh_exec", "fs_stat", "fs_read", "fs_mkdir", "fs_write"],
)
async def test_concurrent_single_use_matrix_reaches_operation_once(
    tmp_path: Path,
    tool: str,
) -> None:
    clock = Clock(datetime(2026, 10, 2, 10, 0, tzinfo=UTC))
    database, store = _open_store(tmp_path / tool, clock)
    try:
        request, decision, facts = _approval_case(tool)
        binding = build_approval_binding(
            _principal(),
            request,
            decision,
            facts,
        )
        pending = store.ensure_approval(
            binding,
            safe_summary_from_binding(binding, decision.risk),
            _request_id(f"{tool}-pending"),
        )
        store.grant(
            pending.approval_id,
            operator_identity="uid:0:gid:0",
        )
        ledger = AsyncStoreLedger(store)
        authorizer = ExecutionAuthorizer(
            policy=MutablePolicy(decision),
            ledger=ledger,
        )
        operation_calls = 0

        async def attempt(label: str):
            nonlocal operation_calls
            result = await authorizer.authorize(
                _context(label, approval_id=pending.approval_id),
                request,
                facts,
            )
            operation_calls += 1
            return result

        results = await asyncio.gather(
            attempt(f"{tool}-a"),
            attempt(f"{tool}-b"),
            return_exceptions=True,
        )

        assert sum(not isinstance(item, BaseException) for item in results) == 1
        failures = [item for item in results if isinstance(item, BaseException)]
        assert len(failures) == 1
        assert isinstance(failures[0], SSHApprovalRequired)
        assert operation_calls == 1
        assert ledger.consume_calls == 2
        consumed = store.get_approval(pending.approval_id)
        assert consumed is not None
        assert consumed.state is ApprovalState.CONSUMED
    finally:
        database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("current_decision", "expected_error", "should_consume"),
    [
        (Decision.DENY, SSHPolicyDenied, False),
        (Decision.ALLOW, None, False),
        (Decision.APPROVAL_REQUIRED, None, True),
    ],
)
async def test_current_policy_change_matrix(
    tmp_path: Path,
    current_decision: Decision,
    expected_error,
    should_consume: bool,
) -> None:
    clock = Clock(datetime(2026, 10, 2, 10, 0, tzinfo=UTC))
    database, store = _open_store(
        tmp_path / current_decision.value,
        clock,
    )
    try:
        request, original, facts = _approval_case("fs_read")
        binding = build_approval_binding(
            _principal(),
            request,
            original,
            facts,
        )
        pending = store.ensure_approval(
            binding,
            safe_summary_from_binding(binding, original.risk),
            _request_id(f"{current_decision.value}-pending"),
        )
        store.grant(
            pending.approval_id,
            operator_identity="uid:0:gid:0",
        )

        if current_decision is Decision.DENY:
            current = PolicyDecision(
                decision=Decision.DENY,
                reason="now denied",
                risk=RiskLevel.HIGH,
                approval_required=False,
                policy_version=original.policy_version,
            )
        elif current_decision is Decision.ALLOW:
            current = original.model_copy(
                update={
                    "decision": Decision.ALLOW,
                    "approval_required": False,
                }
            )
        else:
            current = original

        ledger = AsyncStoreLedger(store)
        authorizer = ExecutionAuthorizer(
            policy=MutablePolicy(current),
            ledger=ledger,
        )
        call = authorizer.authorize(
            _context(
                f"{current_decision.value}-retry",
                approval_id=pending.approval_id,
            ),
            request,
            facts,
        )

        if expected_error is not None:
            with pytest.raises(expected_error):
                await call
        else:
            result = await call
            assert result.decision is current_decision

        status = store.get_approval(pending.approval_id)
        assert status is not None
        assert (
            status.state is ApprovalState.CONSUMED
        ) is should_consume
        assert ledger.consume_calls == (1 if should_consume else 0)
    finally:
        database.close()


def test_binding_mismatch_matrix_stays_pre_consume(
    tmp_path: Path,
) -> None:
    clock = Clock(datetime(2026, 10, 2, 10, 0, tzinfo=UTC))
    database, store = _open_store(tmp_path, clock)
    try:
        binding = _full_binding()
        pending = store.ensure_approval(
            binding,
            _summary(binding),
            _request_id("binding-pending"),
        )
        store.grant(
            pending.approval_id,
            operator_identity="uid:0:gid:0",
        )

        mutations = {
            "principal": {"principal_id": "static:other"},
            "host": {"host": "dev02"},
            "tool": {"tool": "fs_read"},
            "path": {"normalized_path": "/srv/app/other"},
            "argv": {"argv_fingerprint": fingerprint_argv(("OTHER",))},
            "env": {
                "env_fingerprints": (
                    ApprovalEnvFingerprint(
                        name="TOKEN",
                        value_fingerprint=fingerprint_text("OTHER"),
                    ),
                )
            },
            "stdin": {"stdin_fingerprint": fingerprint_bytes(b"OTHER")},
            "content": {
                "content_fingerprint": fingerprint_bytes(b"OTHER")
            },
            "read_limit": {"effective_tool_bytes": 4096},
            "effective_limit": {"effective_max_output_bytes": 8192},
        }

        for label, update in mutations.items():
            with pytest.raises(
                LedgerNotAuthorizedError,
                match="binding does not match",
            ):
                store.consume(
                    pending.approval_id,
                    binding.model_copy(update=update),
                    _request_id(f"mismatch-{label}"),
                )
            status = store.get_approval(pending.approval_id)
            assert status is not None
            assert status.state is ApprovalState.GRANTED

        consumed = store.consume(
            pending.approval_id,
            binding,
            _request_id("binding-exact"),
        )
        assert consumed.state is ApprovalState.CONSUMED
    finally:
        database.close()


@pytest.mark.asyncio
async def test_approval_persistence_outages_block_transport() -> None:
    request, decision, _facts = _approval_case("ssh_exec")
    transport = RecordingTransport(stdout=b"ok")

    ensure_ledger = FaultLedger(fail_ensure=True)
    ensure_executor = SSHExecutor(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(decision),
            ledger=ensure_ledger,
        ),
        audit=AuditRecorder(ensure_ledger),
        connections=object(),
        transport=transport,
    )
    with pytest.raises(
        SSHAuditPersistenceError,
        match="approval persistence failed",
    ):
        await ensure_executor.execute(
            request,
            context=_context("ensure-outage"),
            stdin=b"hello",
            timeout_seconds=60.0,
            max_output_bytes=1024,
            max_stdin_bytes=1024,
        )
    assert transport.calls == []

    consume_ledger = FaultLedger(fail_consume=True)
    consume_executor = SSHExecutor(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(decision),
            ledger=consume_ledger,
        ),
        audit=AuditRecorder(consume_ledger),
        connections=object(),
        transport=transport,
    )
    with pytest.raises(
        SSHAuditPersistenceError,
        match="approval persistence failed",
    ):
        await consume_executor.execute(
            request,
            context=_context(
                "consume-outage",
                approval_id="apr_" + ("a" * 32),
            ),
            stdin=b"hello",
            timeout_seconds=60.0,
            max_output_bytes=1024,
            max_stdin_bytes=1024,
        )
    assert transport.calls == []


@pytest.mark.asyncio
async def test_execution_audit_outage_matrix_preserves_network_boundaries() -> None:
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        executable="/usr/bin/git",
        args=("status",),
        cwd="/srv/app",
        privilege="user",
    )
    allow = PolicyDecision(
        decision=Decision.ALLOW,
        reason="allowed",
        risk=RiskLevel.LOW,
        normalized_executable="/usr/bin/git",
        normalized_cwd="/srv/app",
        policy_version="sha256:phase5",
    )

    start_ledger = FaultLedger(fail_append_on=2)
    start_transport = RecordingTransport(stdout=b"ok")
    start_executor = SSHExecutor(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(allow),
            ledger=start_ledger,
        ),
        audit=AuditRecorder(start_ledger),
        connections=object(),
        transport=start_transport,
    )
    with pytest.raises(
        SSHAuditPersistenceError,
        match="audit persistence failed",
    ):
        await start_executor.execute(
            request,
            context=_context("start-audit-outage"),
        )
    assert start_transport.calls == []

    completion_ledger = FaultLedger(fail_append_on=3)
    completion_transport = RecordingTransport(stdout=b"ok")
    completion_executor = SSHExecutor(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(allow),
            ledger=completion_ledger,
        ),
        audit=AuditRecorder(completion_ledger),
        connections=object(),
        transport=completion_transport,
    )
    with pytest.raises(
        SSHAuditPersistenceOutcomeUncertain,
        match="do not retry blindly",
    ):
        await completion_executor.execute(
            request,
            context=_context("completion-audit-outage"),
        )
    assert len(completion_transport.calls) == 1


@pytest.mark.asyncio
async def test_filesystem_completion_audit_outage_semantics() -> None:
    read_request, read_decision, _read_facts = _approval_case("fs_read")
    read_ledger = FaultLedger(fail_append_on=3)
    read_transport = RecordingTransport(stdout=b"data")
    read_client = SSHFilesystemClient(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(
                read_decision.model_copy(
                    update={
                        "decision": Decision.ALLOW,
                        "approval_required": False,
                    }
                )
            ),
            ledger=read_ledger,
        ),
        audit=AuditRecorder(read_ledger),
        transport=read_transport,
    )
    with pytest.raises(
        SSHAuditPersistenceError,
        match="audit persistence failed",
    ):
        await read_client.read(
            read_request,
            context=_context("read-completion-outage"),
            max_bytes=4096,
        )
    assert len(read_transport.calls) == 1

    mkdir_request, mkdir_decision, _mkdir_facts = _approval_case("fs_mkdir")
    mkdir_ledger = FaultLedger(fail_append_on=3)
    mkdir_transport = RecordingTransport()
    mkdir_client = SSHFilesystemClient(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(
                mkdir_decision.model_copy(
                    update={
                        "decision": Decision.ALLOW,
                        "approval_required": False,
                    }
                )
            ),
            ledger=mkdir_ledger,
        ),
        audit=AuditRecorder(mkdir_ledger),
        transport=mkdir_transport,
    )
    with pytest.raises(
        SSHAuditPersistenceOutcomeUncertain,
        match="do not retry blindly",
    ):
        await mkdir_client.mkdir(
            mkdir_request,
            context=_context("mkdir-completion-outage"),
        )
    assert len(mkdir_transport.calls) == 1

    write_request, write_decision, _write_facts = _approval_case("fs_write")
    write_ledger = FaultLedger(fail_append_on=3)
    write_transport = RecordingTransport(exit_status=74)
    write_client = SSHFilesystemClient(
        authorizer=ExecutionAuthorizer(
            policy=MutablePolicy(
                write_decision.model_copy(
                    update={
                        "decision": Decision.ALLOW,
                        "approval_required": False,
                    }
                )
            ),
            ledger=write_ledger,
        ),
        audit=AuditRecorder(write_ledger),
        transport=write_transport,
    )
    with pytest.raises(
        SSHFilesystemWriteCommittedUncertain,
        match="durability uncertain",
    ):
        await write_client.write(
            write_request,
            b"CONTENT",
            context=_context("write-status74-audit-outage"),
        )
    assert len(write_transport.calls) == 1


@pytest.mark.asyncio
async def test_request_audit_outage_is_sanitized() -> None:
    recorder = AuditRecorder(FaultLedger(fail_append_on=1))
    with pytest.raises(
        AuditPersistenceFailure,
        match="audit persistence failed",
    ) as exc_info:
        await recorder.request_received(
            _context("request-audit-outage"),
            tool="fs_read",
            host="dev01",
        )
    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["cancelled", "transport_uncertain"])
async def test_consumed_mkdir_approval_is_not_restored_after_transport_abort(
    tmp_path: Path,
    outcome: str,
) -> None:
    clock = Clock(datetime(2026, 10, 2, 10, 0, tzinfo=UTC))
    database, store = _open_store(tmp_path / outcome, clock)
    try:
        request, decision, facts = _approval_case("fs_mkdir")
        binding = build_approval_binding(
            _principal(),
            request,
            decision,
            facts,
        )
        pending = store.ensure_approval(
            binding,
            safe_summary_from_binding(binding, decision.risk),
            _request_id(f"{outcome}-pending"),
        )
        store.grant(
            pending.approval_id,
            operator_identity="uid:0:gid:0",
        )
        ledger = AsyncStoreLedger(store)

        class AbortTransport:
            def __init__(self) -> None:
                self.calls = []

            async def run(self, **kwargs):
                self.calls.append(kwargs)
                if outcome == "cancelled":
                    raise asyncio.CancelledError
                raise SSHRequestOutcomeUncertain(
                    "SUPERSECRET transport uncertainty"
                )

        transport = AbortTransport()
        client = SSHFilesystemClient(
            authorizer=ExecutionAuthorizer(
                policy=MutablePolicy(decision),
                ledger=ledger,
            ),
            audit=AuditRecorder(ledger),
            transport=transport,
        )
        context = _context(
            f"{outcome}-attempt",
            approval_id=pending.approval_id,
        )

        if outcome == "cancelled":
            with pytest.raises(asyncio.CancelledError):
                await client.mkdir(request, context=context)
        else:
            with pytest.raises(
                SSHRequestOutcomeUncertain,
                match="remote filesystem mutation outcome is uncertain",
            ):
                await client.mkdir(request, context=context)

        status = store.get_approval(pending.approval_id)
        assert status is not None
        assert status.state is ApprovalState.CONSUMED
        assert len(transport.calls) == 1

        retry_transport = RecordingTransport()
        retry_client = SSHFilesystemClient(
            authorizer=ExecutionAuthorizer(
                policy=MutablePolicy(decision),
                ledger=ledger,
            ),
            audit=AuditRecorder(ledger),
            transport=retry_transport,
        )
        with pytest.raises(SSHApprovalRequired):
            await retry_client.mkdir(
                request,
                context=_context(
                    f"{outcome}-retry",
                    approval_id=pending.approval_id,
                ),
            )
        assert retry_transport.calls == []
    finally:
        database.close()
