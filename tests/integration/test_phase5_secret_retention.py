from __future__ import annotations

import os
import traceback
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext, SSHExecRequest
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.approvals.binding import (
    build_approval_binding,
    fingerprint_bytes,
    safe_summary_from_binding,
)
from ssh_over_mcp.approvals.ledger import SecurityLedgerStore
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.approvals.protocol import (
    AppendAuditRequest,
    EnsureApprovalRequest,
    encode_ledger_message,
)
from ssh_over_mcp.approvals.storage import LedgerDatabase, LedgerStorageSettings
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.errors import SSHPolicyDenied
from ssh_over_mcp.ssh.transport import SSHExecutionResult

ARGV_SECRET = "ARGV_MARKER_5F"
ENV_SECRET = "ENV_MARKER_5F"
STDIN_SECRET = b"STDIN_MARKER_5F"
WRITE_SECRET = b"WRITE_MARKER_5F"
STDOUT_SECRET = b"STDOUT_MARKER_5F"
STDERR_SECRET = b"STDERR_MARKER_5F"
CREDENTIAL_SECRET = "secret://CREDENTIAL_MARKER_5F"
HOST_KEY_SECRET = "HOST_KEY_MARKER_5F"
SSH_USER_SECRET = "SSH_USER_MARKER_5F"
POLICY_SECRET = "POLICY_REASON_MARKER_5F"


def _settings(tmp_path: Path) -> LedgerStorageSettings:
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    key = root / "ledger.key"
    key.write_bytes(b"K" * 32)
    os.chmod(key, 0o600)
    info = root.stat()
    return LedgerStorageSettings(
        db_path=root / "ledger.db",
        hmac_key_path=key,
        service_uid=info.st_uid,
        service_gid=info.st_gid,
    )


class AsyncStoreLedger:
    def __init__(self, store: SecurityLedgerStore) -> None:
        self.store = store
        self.events = []

    async def append_audit(self, event) -> str:
        self.events.append(event)
        return self.store.append_audit(event)


def _context() -> OperationContext:
    return OperationContext(
        request_id="req_" + ("1" * 32),
        principal=PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 2, 11, 0, tzinfo=UTC),
    )


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        executable="/usr/bin/tool",
        args=(ARGV_SECRET,),
        cwd="/srv/app",
        env={"TOKEN": ENV_SECRET},
        privilege="user",
    )


def _decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.APPROVAL_REQUIRED,
        reason=POLICY_SECRET,
        risk=RiskLevel.HIGH,
        normalized_executable="/usr/bin/tool",
        normalized_cwd="/srv/app",
        approval_required=True,
        policy_version="sha256:phase5",
    )


def _facts() -> ApprovalExecutionFacts:
    return ApprovalExecutionFacts(
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
        effective_max_stdin_bytes=1024,
        stdin_length=len(STDIN_SECRET),
        stdin_fingerprint=fingerprint_bytes(STDIN_SECRET),
        content_length=len(WRITE_SECRET),
        content_fingerprint=fingerprint_bytes(WRITE_SECRET),
    )


@pytest.mark.asyncio
async def test_ledger_frames_rows_and_admin_status_retain_only_safe_metadata(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    database = LedgerDatabase.open(settings)
    store = SecurityLedgerStore(
        database,
        b"K" * 32,
        clock=lambda: datetime(2026, 10, 2, 11, 0, tzinfo=UTC),
    )
    request = _request()
    decision = _decision()
    facts = _facts()
    binding = build_approval_binding(
        _context().principal,
        request,
        decision,
        facts,
    )
    summary = safe_summary_from_binding(binding, decision.risk)
    try:
        ensure = EnsureApprovalRequest(
            message_id="msg_" + ("1" * 32),
            request_id=_context().request_id,
            binding=binding,
            risk=decision.risk,
        )
        ensure_frame = encode_ledger_message(ensure)
        status = store.ensure_approval(
            binding,
            summary,
            _context().request_id,
        )

        ledger = AsyncStoreLedger(store)
        recorder = AuditRecorder(ledger)
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
                stdout=STDOUT_SECRET,
                stderr=STDERR_SECRET,
                duration_ms=1,
            ),
        )
        audit_frame = encode_ledger_message(
            AppendAuditRequest(
                message_id="msg_" + ("2" * 32),
                event=ledger.events[0],
            )
        )
        visible_status = status.model_dump_json()
        persisted = "\n".join(
            str(tuple(row))
            for table in ("approvals", "audit_events")
            for row in database.connection.execute(f"SELECT * FROM {table}")
        )

        combined = (
            ensure_frame
            + audit_frame
            + visible_status.encode()
            + persisted.encode()
        )
        for forbidden in (
            ARGV_SECRET.encode(),
            ENV_SECRET.encode(),
            STDIN_SECRET,
            WRITE_SECRET,
            STDOUT_SECRET,
            STDERR_SECRET,
            CREDENTIAL_SECRET.encode(),
            HOST_KEY_SECRET.encode(),
            SSH_USER_SECRET.encode(),
            POLICY_SECRET.encode(),
        ):
            assert forbidden not in combined

        assert binding.argv_count == 1
        assert binding.argv_fingerprint.startswith("sha256:")
        assert binding.env_fingerprints[0].name == "TOKEN"
        assert binding.env_fingerprints[0].value_fingerprint.startswith("sha256:")
        assert binding.stdin_length == len(STDIN_SECRET)
        assert binding.stdin_fingerprint.startswith("sha256:")
        assert binding.content_length == len(WRITE_SECRET)
        assert binding.content_fingerprint.startswith("sha256:")
        assert ledger.events[0].stdout_bytes == len(STDOUT_SECRET)
        assert ledger.events[0].stderr_bytes == len(STDERR_SECRET)
    finally:
        database.close()


class RaisingExecutor:
    default_timeout_seconds = 60.0
    default_max_output_bytes = 1024 * 1024
    default_max_stdin_bytes = 1024 * 1024

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def execute(self, request, **kwargs):
        raise self.error


@pytest.mark.asyncio
async def test_public_error_and_full_traceback_do_not_echo_request_or_host_secrets() -> None:
    inventory = Inventory(
        hosts={
            "visible": Host(
                address="10.0.0.1",
                ssh_user=SSH_USER_SECRET,
                credential_ref=CREDENTIAL_SECRET,
                host_key=HOST_KEY_SECRET,
                allowed_roles=frozenset({"developer"}),
            )
        }
    )
    denied = PolicyDecision(
        decision=Decision.DENY,
        reason=POLICY_SECRET,
        risk=RiskLevel.HIGH,
        approval_required=False,
        policy_version="sha256:phase5",
    )
    service = MCPService(
        inventory=inventory,
        policy=object(),
        ssh_executor=RaisingExecutor(SSHPolicyDenied(denied)),
    )
    request = SSHExecRequest(
        host="visible",
        executable="/usr/bin/tool",
        args=(ARGV_SECRET,),
        env={"TOKEN": ENV_SECRET},
        stdin=STDIN_SECRET.decode(),
    )

    rendered = ""
    try:
        await service.ssh_exec(_context(), request)
    except api_errors.PolicyDeniedError as exc:
        rendered = str(exc) + "\n" + traceback.format_exc()
    else:  # pragma: no cover
        raise AssertionError("policy denial unexpectedly succeeded")

    assert "request denied by central policy" in rendered
    for forbidden in (
        ARGV_SECRET,
        ENV_SECRET,
        STDIN_SECRET.decode(),
        CREDENTIAL_SECRET,
        HOST_KEY_SECRET,
        SSH_USER_SECRET,
        POLICY_SECRET,
    ):
        assert forbidden not in rendered
