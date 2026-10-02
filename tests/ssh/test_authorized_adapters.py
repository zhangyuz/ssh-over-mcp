from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

import ssh_over_mcp.ssh.errors as ssh_errors
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.binding import fingerprint_bytes
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.executor import SSHExecutor
from ssh_over_mcp.ssh.filesystem import SSHFilesystemClient
from ssh_over_mcp.ssh.protocol import (
    ExecEnvelope,
    FsReadEnvelope,
    FsWriteEnvelope,
    decode_request,
)
from ssh_over_mcp.ssh.transport import SSHExecutionResult


class RecordingAuthorizer:
    def __init__(
        self,
        decision: PolicyDecision,
        error: Exception | None = None,
    ) -> None:
        self.decision = decision
        self.error = error
        self.calls = []

    async def authorize(self, context, request, facts):
        self.calls.append((context, request, facts))
        if self.error is not None:
            raise self.error
        return self.decision


class RecordingAuditLedger:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.fail_on_call = fail_on_call
        self.calls = 0
        self.events = []

    async def append_audit(self, event) -> str:
        self.calls += 1
        if self.fail_on_call == self.calls:
            raise RuntimeError("SUPERSECRET audit backend detail")
        self.events.append(event)
        return "evt_" + ("d" * 32)


class RecordingTransport:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        exit_status: int | None = 0,
        error: BaseException | None = None,
    ) -> None:
        self.stdout = stdout
        self.exit_status = exit_status
        self.error = error
        self.calls = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return SSHExecutionResult(
            request_id=kwargs["request_id"],
            host=kwargs["host"],
            exit_status=self.exit_status,
            stdout=self.stdout,
            duration_ms=1,
        )


def _context() -> OperationContext:
    return OperationContext(
        request_id="req_" + ("c" * 32),
        principal=PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


def _exec_request() -> EvaluationRequest:
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


def _allow_exec() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason="ok",
        risk=RiskLevel.LOW,
        normalized_executable="/usr/bin/git",
        normalized_cwd="/srv/app",
        policy_version="sha256:test",
    )


def _allow_path(path: str) -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason="ok",
        risk=RiskLevel.LOW,
        normalized_path=path,
        policy_version="sha256:test",
    )


@pytest.mark.asyncio
async def test_executor_uses_authorizer_and_context_request_id() -> None:
    authorizer = RecordingAuthorizer(_allow_exec())
    transport = RecordingTransport(stdout=b"ok")
    executor = SSHExecutor(
        authorizer=authorizer,
        audit=AuditRecorder(RecordingAuditLedger()),
        connections=object(),
        transport=transport,
    )
    context = _context()

    result = await executor.execute(
        _exec_request(),
        context=context,
        stdin=b"hello",
        timeout_seconds=7.0,
        max_output_bytes=1234,
        max_stdin_bytes=5678,
    )

    assert result.request_id == context.request_id
    assert len(authorizer.calls) == 1
    seen_context, seen_request, facts = authorizer.calls[0]
    assert seen_context == context
    assert seen_request == _exec_request()
    assert facts.effective_timeout_seconds == 7.0
    assert facts.effective_max_output_bytes == 1234
    assert facts.effective_max_stdin_bytes == 5678
    assert facts.stdin_length == 5
    assert facts.stdin_fingerprint == fingerprint_bytes(b"hello")

    call = transport.calls[0]
    assert call["request_id"] == context.request_id
    envelope, body = decode_request(call["payload"])
    assert isinstance(envelope, ExecEnvelope)
    assert envelope.request_id == context.request_id
    assert body == b"hello"


@pytest.mark.asyncio
async def test_executor_authorizer_failure_happens_before_transport() -> None:
    authorizer = RecordingAuthorizer(
        _allow_exec(),
        RuntimeError("ledger unavailable"),
    )
    transport = RecordingTransport()
    executor = SSHExecutor(
        authorizer=authorizer,
        audit=AuditRecorder(RecordingAuditLedger()),
        connections=object(),
        transport=transport,
    )

    with pytest.raises(RuntimeError, match="ledger unavailable"):
        await executor.execute(
            _exec_request(),
            context=_context(),
        )

    assert transport.calls == []


@pytest.mark.asyncio
async def test_fs_read_binds_effective_read_limit_and_context_request_id() -> None:
    authorizer = RecordingAuthorizer(_allow_path("/srv/app/file"))
    transport = RecordingTransport(stdout=b"data")
    client = SSHFilesystemClient(
        authorizer=authorizer,
        audit=AuditRecorder(RecordingAuditLedger()),
        transport=transport,
    )
    context = _context()
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="fs_read",
        path="/srv/app/./file",
        privilege="user",
    )

    result = await client.read(
        request,
        context=context,
        max_bytes=1024,
    )

    assert result.request_id == context.request_id
    _, seen_request, facts = authorizer.calls[0]
    assert seen_request == request
    assert facts.effective_timeout_seconds == 60.0
    assert facts.effective_max_output_bytes == 4096
    assert facts.effective_tool_bytes == 1024

    call = transport.calls[0]
    envelope, body = decode_request(call["payload"])
    assert isinstance(envelope, FsReadEnvelope)
    assert envelope.request_id == context.request_id
    assert envelope.path == "/srv/app/file"
    assert envelope.max_bytes == 1024
    assert body == b""


@pytest.mark.asyncio
async def test_fs_write_binds_content_fingerprint_before_transport() -> None:
    authorizer = RecordingAuthorizer(_allow_path("/srv/app/new.bin"))
    transport = RecordingTransport()
    client = SSHFilesystemClient(
        authorizer=authorizer,
        audit=AuditRecorder(RecordingAuditLedger()),
        transport=transport,
    )
    context = _context()
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="fs_write",
        path="/srv/app/new.bin",
        privilege="user",
    )

    result = await client.write(
        request,
        b"\x00\xffAB",
        context=context,
    )

    assert result.request_id == context.request_id
    _, _, facts = authorizer.calls[0]
    assert facts.content_length == 4
    assert facts.content_fingerprint == fingerprint_bytes(b"\x00\xffAB")
    assert facts.effective_timeout_seconds == 60.0
    assert facts.effective_max_output_bytes == 4096

    call = transport.calls[0]
    envelope, body = decode_request(call["payload"])
    assert isinstance(envelope, FsWriteEnvelope)
    assert envelope.request_id == context.request_id
    assert envelope.content_length == 4
    assert body == b"\x00\xffAB"


@pytest.mark.asyncio
async def test_executor_records_started_and_completed_events() -> None:
    ledger = RecordingAuditLedger()
    audit = AuditRecorder(ledger)
    executor = SSHExecutor(
        authorizer=RecordingAuthorizer(_allow_exec()),
        connections=object(),
        transport=RecordingTransport(stdout=b"ok"),
        audit=audit,
    )

    result = await executor.execute(
        _exec_request(),
        context=_context(),
    )

    assert result.stdout == b"ok"
    assert [event.event_type for event in ledger.events] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_COMPLETED,
    ]
    assert ledger.events[1].stdout_bytes == 2


@pytest.mark.asyncio
async def test_executor_started_audit_failure_happens_before_transport() -> None:
    audit_error = getattr(ssh_errors, "SSHAuditPersistenceError", None)
    assert audit_error is not None

    ledger = RecordingAuditLedger(fail_on_call=1)
    transport = RecordingTransport()
    executor = SSHExecutor(
        authorizer=RecordingAuthorizer(_allow_exec()),
        connections=object(),
        transport=transport,
        audit=AuditRecorder(ledger),
    )

    with pytest.raises(
        audit_error,
        match="audit persistence failed",
    ) as exc_info:
        await executor.execute(
            _exec_request(),
            context=_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
    assert transport.calls == []


@pytest.mark.asyncio
async def test_executor_success_audit_failure_is_non_retryable_uncertain() -> None:
    uncertain_error = getattr(
        ssh_errors,
        "SSHAuditPersistenceOutcomeUncertain",
        None,
    )
    assert uncertain_error is not None

    ledger = RecordingAuditLedger(fail_on_call=2)
    executor = SSHExecutor(
        authorizer=RecordingAuthorizer(_allow_exec()),
        connections=object(),
        transport=RecordingTransport(stdout=b"ok"),
        audit=AuditRecorder(ledger),
    )

    with pytest.raises(
        uncertain_error,
        match="audit persistence outcome is uncertain; do not retry blindly",
    ) as exc_info:
        await executor.execute(
            _exec_request(),
            context=_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
    assert [event.event_type for event in ledger.events] == [
        AuditEventType.EXECUTION_STARTED,
    ]


@pytest.mark.asyncio
async def test_executor_cancellation_records_cancelled_without_completion() -> None:
    ledger = RecordingAuditLedger()
    executor = SSHExecutor(
        authorizer=RecordingAuthorizer(_allow_exec()),
        connections=object(),
        transport=RecordingTransport(error=asyncio.CancelledError()),
        audit=AuditRecorder(ledger),
    )

    with pytest.raises(asyncio.CancelledError):
        await executor.execute(
            _exec_request(),
            context=_context(),
        )

    assert [event.event_type for event in ledger.events] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_CANCELLED,
    ]


@pytest.mark.asyncio
async def test_fs_read_completion_audit_failure_is_stable_audit_error() -> None:
    audit_error = getattr(ssh_errors, "SSHAuditPersistenceError", None)
    assert audit_error is not None

    ledger = RecordingAuditLedger(fail_on_call=2)
    client = SSHFilesystemClient(
        authorizer=RecordingAuthorizer(_allow_path("/srv/app/file")),
        transport=RecordingTransport(stdout=b"data"),
        audit=AuditRecorder(ledger),
    )
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="fs_read",
        path="/srv/app/file",
        privilege="user",
    )

    with pytest.raises(
        audit_error,
        match="audit persistence failed",
    ):
        await client.read(
            request,
            context=_context(),
            max_bytes=1024,
        )


@pytest.mark.asyncio
async def test_fs_mkdir_uncertain_outcome_remains_more_specific_when_audit_fails() -> None:
    ledger = RecordingAuditLedger(fail_on_call=2)
    client = SSHFilesystemClient(
        authorizer=RecordingAuthorizer(_allow_path("/srv/app/new-dir")),
        transport=RecordingTransport(
            error=ssh_errors.SSHRequestOutcomeUncertain(
                "SUPERSECRET transport uncertainty"
            )
        ),
        audit=AuditRecorder(ledger),
    )
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        path="/srv/app/new-dir",
        privilege="user",
    )

    with pytest.raises(
        ssh_errors.SSHRequestOutcomeUncertain,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.mkdir(
            request,
            context=_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_mkdir_success_audit_failure_is_non_retryable_uncertain() -> None:
    ledger = RecordingAuditLedger(fail_on_call=2)
    transport = RecordingTransport()
    client = SSHFilesystemClient(
        authorizer=RecordingAuthorizer(_allow_path("/srv/app/new-dir")),
        transport=transport,
        audit=AuditRecorder(ledger),
    )
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        path="/srv/app/new-dir",
        privilege="user",
    )

    with pytest.raises(
        ssh_errors.SSHAuditPersistenceOutcomeUncertain,
        match="audit persistence outcome is uncertain; do not retry blindly",
    ) as exc_info:
        await client.mkdir(
            request,
            context=_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
    assert len(transport.calls) == 1
    assert [event.event_type for event in ledger.events] == [
        AuditEventType.EXECUTION_STARTED,
    ]
