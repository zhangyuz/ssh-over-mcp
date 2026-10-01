from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_over_mcp.approvals.models import ApprovalSafeSummary
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.policy.models import Decision, RiskLevel


def _summary() -> ApprovalSafeSummary:
    return ApprovalSafeSummary(
        principal_id="static:developer",
        profile="developer",
        host="host-a",
        tool="ssh_exec",
        privilege="user",
        policy_version="1",
        risk=RiskLevel.MEDIUM,
        normalized_executable="/usr/bin/git",
        argv_count=1,
        argv_fingerprint="sha256:" + ("a" * 64),
        env_names=("SAFE",),
    )


def test_audit_event_type_values_are_exact() -> None:
    assert [event.value for event in AuditEventType] == [
        "request_received",
        "policy_allowed",
        "policy_denied",
        "approval_required",
        "approval_granted",
        "approval_denied",
        "approval_expired",
        "approval_consumed",
        "execution_started",
        "execution_completed",
        "execution_failed",
        "execution_cancelled",
        "remote_policy_denied",
        "host_key_failure",
        "mutation_outcome_uncertain",
        "filesystem_write_committed_durability_uncertain",
    ]


def test_audit_event_input_is_bounded_closed_world_metadata_only() -> None:
    event = AuditEventInput(
        event_type=AuditEventType.POLICY_ALLOWED,
        request_id="req_" + ("a" * 32),
        principal_id="static:developer",
        profile="developer",
        host="host-a",
        tool="ssh_exec",
        policy_version="1",
        decision=Decision.ALLOW,
        risk=RiskLevel.MEDIUM,
        safe_summary=_summary(),
        duration_ms=1,
        stdout_bytes=2,
        stderr_bytes=3,
        timed_out=False,
        truncated=False,
    )

    assert event.stdout_bytes == 2
    assert event.stderr_bytes == 3

    with pytest.raises(ValidationError):
        AuditEventInput.model_validate(
            {**event.model_dump(), "stdout": "SUPERSECRET"}
        )


def test_audit_model_has_no_raw_secret_or_output_body_fields() -> None:
    forbidden = {
        "args",
        "argv",
        "env",
        "env_values",
        "stdin",
        "body",
        "content",
        "stdout",
        "stderr",
        "credential",
        "credential_ref",
        "private_key",
        "token",
    }
    assert forbidden.isdisjoint(AuditEventInput.model_fields)


@pytest.mark.parametrize(
    "field",
    [
        "duration_ms",
        "stdout_bytes",
        "stderr_bytes",
    ],
)
def test_audit_event_rejects_negative_counters(field: str) -> None:
    payload = {
        "event_type": AuditEventType.EXECUTION_COMPLETED,
        "request_id": "req_" + ("a" * 32),
        "principal_id": "static:developer",
        "profile": "developer",
        "host": "host-a",
        "tool": "ssh_exec",
        field: -1,
    }
    with pytest.raises(ValidationError):
        AuditEventInput.model_validate(payload)
