from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ssh_over_mcp.approvals.models import ApprovalSafeSummary
from ssh_over_mcp.policy.models import Decision, RiskLevel

_MAX_IDENTITY_CHARS = 256
_MAX_TOOL_CHARS = 128
_MAX_POLICY_VERSION_CHARS = 256
_MAX_SIGNAL_CHARS = 128


class AuditEventType(StrEnum):
    REQUEST_RECEIVED = "request_received"
    POLICY_ALLOWED = "policy_allowed"
    POLICY_DENIED = "policy_denied"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_CONSUMED = "approval_consumed"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_CANCELLED = "execution_cancelled"
    REMOTE_POLICY_DENIED = "remote_policy_denied"
    HOST_KEY_FAILURE = "host_key_failure"
    MUTATION_OUTCOME_UNCERTAIN = "mutation_outcome_uncertain"
    FILESYSTEM_WRITE_COMMITTED_DURABILITY_UNCERTAIN = (
        "filesystem_write_committed_durability_uncertain"
    )


class AuditEventInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: AuditEventType
    request_id: str = Field(pattern=r"^req_[0-9a-f]{32}$")
    principal_id: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    profile: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    host: str | None = Field(
        default=None,
        min_length=1,
        max_length=_MAX_IDENTITY_CHARS,
    )
    tool: str | None = Field(
        default=None,
        min_length=1,
        max_length=_MAX_TOOL_CHARS,
    )
    policy_version: str | None = Field(
        default=None,
        min_length=1,
        max_length=_MAX_POLICY_VERSION_CHARS,
    )
    decision: Decision | None = None
    risk: RiskLevel | None = None
    approval_id: str | None = Field(
        default=None,
        pattern=r"^apr_[0-9a-f]{32}$",
    )
    safe_summary: ApprovalSafeSummary | None = None
    exit_status: int | None = None
    exit_signal: str | None = Field(
        default=None,
        max_length=_MAX_SIGNAL_CHARS,
    )
    duration_ms: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    stdout_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    stderr_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    timed_out: bool | None = None
    truncated: bool | None = None
