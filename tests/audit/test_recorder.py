from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import AuditPersistenceFailure, AuditRecorder
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.transport import SSHExecutionResult


class RecordingLedger:
    def __init__(self) -> None:
        self.events = []
        self.error: Exception | None = None

    async def append_audit(self, event) -> str:
        if self.error is not None:
            raise self.error
        self.events.append(event)
        return "evt_" + ("a" * 32)


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
        env={"TOKEN": "SUPERSECRET_ENV"},
        privilege="user",
    )


def _decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason="SUPERSECRET_POLICY_REASON",
        risk=RiskLevel.LOW,
        normalized_executable="/usr/bin/git",
        normalized_cwd="/srv/app",
        policy_version="sha256:test",
    )


@pytest.mark.asyncio
async def test_request_received_event_uses_trusted_context() -> None:
    ledger = RecordingLedger()
    recorder = AuditRecorder(ledger)

    await recorder.request_received(
        _context(),
        tool="ssh_exec",
        host="dev01",
    )

    event = ledger.events[0]
    assert event.event_type is AuditEventType.REQUEST_RECEIVED
    assert event.request_id == _context().request_id
    assert event.principal_id == "static:developer"
    assert event.profile == "developer"
    assert event.host == "dev01"
    assert event.tool == "ssh_exec"
    assert event.safe_summary is None


@pytest.mark.asyncio
async def test_recorder_sanitizes_ledger_failure() -> None:
    ledger = RecordingLedger()
    ledger.error = RuntimeError("SUPERSECRET ledger traceback detail")
    recorder = AuditRecorder(ledger)

    with pytest.raises(
        AuditPersistenceFailure,
        match="audit persistence failed",
    ) as exc_info:
        await recorder.request_received(
            _context(),
            tool="ssh_exec",
            host="dev01",
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_execution_event_has_safe_summary_and_bounded_result_metadata() -> None:
    ledger = RecordingLedger()
    recorder = AuditRecorder(ledger)
    facts = ApprovalExecutionFacts(
        effective_timeout_seconds=7.0,
        effective_max_output_bytes=4096,
        effective_max_stdin_bytes=1024,
        stdin_length=4,
        stdin_fingerprint="sha256:" + ("1" * 64),
    )
    result = SSHExecutionResult(
        request_id=_context().request_id,
        host="dev01",
        exit_status=0,
        stdout=b"SUPERSECRET_STDOUT",
        stderr=b"SUPERSECRET_STDERR",
        duration_ms=12,
    )

    await recorder.execution_event(
        AuditEventType.EXECUTION_COMPLETED,
        context=_context(),
        request=_request(),
        decision=_decision(),
        facts=facts,
        result=result,
    )

    event = ledger.events[0]
    assert event.event_type is AuditEventType.EXECUTION_COMPLETED
    assert event.safe_summary is not None
    assert event.safe_summary.env_names == ("TOKEN",)
    assert event.stdout_bytes == len(result.stdout)
    assert event.stderr_bytes == len(result.stderr)
    rendered = event.model_dump_json()
    assert "SUPERSECRET_ENV" not in rendered
    assert "SUPERSECRET_STDOUT" not in rendered
    assert "SUPERSECRET_STDERR" not in rendered
    assert "SUPERSECRET_POLICY_REASON" not in rendered


@pytest.mark.asyncio
async def test_filesystem_write_audit_retains_only_content_fingerprint() -> None:
    ledger = RecordingLedger()
    recorder = AuditRecorder(ledger)
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="fs_write",
        path="/srv/app/new.bin",
        privilege="user",
    )
    decision = PolicyDecision(
        decision=Decision.ALLOW,
        reason="SUPERSECRET_POLICY_REASON",
        risk=RiskLevel.MEDIUM,
        normalized_path="/srv/app/new.bin",
        policy_version="sha256:test",
    )
    raw_content = b"SUPERSECRET_FILE_BYTES"
    facts = ApprovalExecutionFacts(
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
        content_length=len(raw_content),
        content_fingerprint="sha256:" + ("2" * 64),
    )

    await recorder.execution_event(
        AuditEventType.EXECUTION_COMPLETED,
        context=_context(),
        request=request,
        decision=decision,
        facts=facts,
        result=SSHExecutionResult(
            request_id=_context().request_id,
            host="dev01",
            exit_status=0,
            duration_ms=1,
        ),
    )

    event = ledger.events[0]
    assert event.safe_summary is not None
    assert event.safe_summary.content_length == len(raw_content)
    assert event.safe_summary.content_fingerprint == "sha256:" + ("2" * 64)
    rendered = event.model_dump_json()
    assert "SUPERSECRET_FILE_BYTES" not in rendered
    assert "SUPERSECRET_POLICY_REASON" not in rendered
