from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ssh_over_mcp.approvals.models import (
    ApprovalBindingInput,
    ApprovalEnvFingerprint,
    ApprovalExecutionFacts,
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.policy.models import RiskLevel

_SHA_A = "sha256:" + ("a" * 64)
_SHA_B = "sha256:" + ("b" * 64)
_HMAC_SHORT = "hmac-sha256:v1:" + ("c" * 16)


def test_approval_state_values_are_exact() -> None:
    assert [state.value for state in ApprovalState] == [
        "pending",
        "granted",
        "denied",
        "expired",
        "consumed",
    ]


def test_approval_models_are_closed_world_and_frozen() -> None:
    summary = ApprovalSafeSummary(
        principal_id="static:developer",
        profile="developer",
        host="host-a",
        tool="ssh_exec",
        privilege="user",
        policy_version="1",
        risk=RiskLevel.HIGH,
        normalized_executable="/usr/bin/git",
        normalized_cwd="/srv/app",
        argv_count=1,
        argv_fingerprint=_SHA_A,
        env_names=("SAFE",),
        stdin_length=0,
        stdin_fingerprint=_SHA_B,
        effective_timeout_seconds=10.0,
        effective_max_output_bytes=4096,
        effective_max_stdin_bytes=65536,
    )

    with pytest.raises(ValidationError):
        ApprovalSafeSummary.model_validate(
            {**summary.model_dump(), "unexpected": "value"}
        )
    with pytest.raises(ValidationError):
        summary.host = "other-host"


def test_approval_domain_has_no_raw_secret_value_fields() -> None:
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

    for model_type in (
        ApprovalExecutionFacts,
        ApprovalSafeSummary,
        ApprovalBindingInput,
        ApprovalStatus,
    ):
        assert forbidden.isdisjoint(model_type.model_fields)


def test_approval_execution_facts_reject_non_finite_or_negative_limits() -> None:
    with pytest.raises(ValidationError):
        ApprovalExecutionFacts(effective_timeout_seconds=float("nan"))
    with pytest.raises(ValidationError):
        ApprovalExecutionFacts(effective_timeout_seconds=float("inf"))
    with pytest.raises(ValidationError):
        ApprovalExecutionFacts(effective_max_output_bytes=-1)


def test_approval_binding_has_fixed_secret_safe_field_set() -> None:
    binding = ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="host-a",
        tool="ssh_exec",
        privilege="user",
        policy_version="1",
        normalized_executable="/usr/bin/git",
        normalized_cwd="/srv/app",
        argv_count=2,
        argv_fingerprint=_SHA_A,
        env_fingerprints=(
            ApprovalEnvFingerprint(
                name="A",
                value_fingerprint=_SHA_A,
            ),
            ApprovalEnvFingerprint(
                name="B",
                value_fingerprint=_SHA_B,
            ),
        ),
        stdin_length=0,
        stdin_fingerprint=_SHA_B,
        effective_timeout_seconds=10.0,
        effective_max_output_bytes=4096,
        effective_max_stdin_bytes=65536,
    )

    assert binding.binding_version == 1
    assert binding.env_fingerprints[0].name == "A"
    assert "SUPERSECRET" not in binding.model_dump_json()


def test_approval_status_requires_utc_expiry_and_strict_ids() -> None:
    summary = ApprovalSafeSummary(
        principal_id="static:developer",
        profile="developer",
        host="host-a",
        tool="ssh_exec",
        privilege="user",
        policy_version="1",
        risk=RiskLevel.HIGH,
        argv_count=0,
        argv_fingerprint=_SHA_A,
        env_names=(),
    )

    status = ApprovalStatus(
        approval_id="apr_" + ("a" * 32),
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        host="host-a",
        tool="ssh_exec",
        risk=RiskLevel.HIGH,
        safe_summary=summary,
        binding_fingerprint=_HMAC_SHORT,
    )
    assert status.expires_at.tzinfo is UTC

    with pytest.raises(ValidationError):
        ApprovalStatus(
            approval_id="apr_bad",
            state=ApprovalState.PENDING,
            expires_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
            host="host-a",
            tool="ssh_exec",
            risk=RiskLevel.HIGH,
            safe_summary=summary,
            binding_fingerprint=_HMAC_SHORT,
        )

    with pytest.raises(ValidationError):
        ApprovalStatus(
            approval_id="apr_" + ("a" * 32),
            state=ApprovalState.PENDING,
            expires_at=datetime.fromisoformat("2026-10-01T12:00:00"),
            host="host-a",
            tool="ssh_exec",
            risk=RiskLevel.HIGH,
            safe_summary=summary,
            binding_fingerprint=_HMAC_SHORT,
        )
