from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ssh_over_mcp.policy.models import RiskLevel

_MAX_IDENTITY_CHARS = 256
_MAX_TOOL_CHARS = 128
_MAX_POLICY_VERSION_CHARS = 256
_MAX_PATH_CHARS = 4096
_MAX_ENV_ITEMS = 128
_MAX_ENV_NAME_CHARS = 128
_MAX_SIGNAL_CHARS = 128

_SHA256 = Annotated[
    str,
    Field(pattern=r"^sha256:[0-9a-f]{64}$"),
]
_SHORT_HMAC = Annotated[
    str,
    Field(pattern=r"^hmac-sha256:v1:[0-9a-f]{16}$"),
]


class ApprovalState(StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class ApprovalEnvFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=_MAX_ENV_NAME_CHARS)
    value_fingerprint: _SHA256


class ApprovalExecutionFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    effective_timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        allow_inf_nan=False,
    )
    effective_max_output_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    effective_max_stdin_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    effective_tool_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    stdin_length: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    stdin_fingerprint: _SHA256 | None = None
    content_length: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    content_fingerprint: _SHA256 | None = None


class ApprovalSafeSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    profile: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    host: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    tool: str = Field(min_length=1, max_length=_MAX_TOOL_CHARS)
    privilege: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    policy_version: str = Field(
        min_length=1,
        max_length=_MAX_POLICY_VERSION_CHARS,
    )
    risk: RiskLevel
    normalized_executable: str | None = Field(
        default=None,
        max_length=_MAX_PATH_CHARS,
    )
    normalized_cwd: str | None = Field(
        default=None,
        max_length=_MAX_PATH_CHARS,
    )
    normalized_path: str | None = Field(
        default=None,
        max_length=_MAX_PATH_CHARS,
    )
    argv_count: int = Field(default=0, strict=True, ge=0, le=256)
    argv_fingerprint: _SHA256 | None = None
    env_names: tuple[
        Annotated[str, Field(min_length=1, max_length=_MAX_ENV_NAME_CHARS)],
        ...,
    ] = Field(default_factory=tuple, max_length=_MAX_ENV_ITEMS)
    stdin_length: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    stdin_fingerprint: _SHA256 | None = None
    content_length: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    content_fingerprint: _SHA256 | None = None
    effective_timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        allow_inf_nan=False,
    )
    effective_max_output_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    effective_max_stdin_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    effective_tool_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )


class ApprovalBindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    binding_version: Literal[1] = 1
    principal_id: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    profile: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    host: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    tool: str = Field(min_length=1, max_length=_MAX_TOOL_CHARS)
    privilege: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    policy_version: str = Field(
        min_length=1,
        max_length=_MAX_POLICY_VERSION_CHARS,
    )
    normalized_executable: str | None = Field(
        default=None,
        max_length=_MAX_PATH_CHARS,
    )
    normalized_cwd: str | None = Field(
        default=None,
        max_length=_MAX_PATH_CHARS,
    )
    normalized_path: str | None = Field(
        default=None,
        max_length=_MAX_PATH_CHARS,
    )
    argv_count: int = Field(default=0, strict=True, ge=0, le=256)
    argv_fingerprint: _SHA256 | None = None
    env_fingerprints: tuple[ApprovalEnvFingerprint, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_ENV_ITEMS,
    )
    stdin_length: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    stdin_fingerprint: _SHA256 | None = None
    content_length: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    content_fingerprint: _SHA256 | None = None
    effective_timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        allow_inf_nan=False,
    )
    effective_max_output_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    effective_max_stdin_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )
    effective_tool_bytes: int | None = Field(
        default=None,
        strict=True,
        ge=0,
    )

    @field_validator("env_fingerprints")
    @classmethod
    def validate_env_fingerprints(
        cls,
        value: tuple[ApprovalEnvFingerprint, ...],
    ) -> tuple[ApprovalEnvFingerprint, ...]:
        names = tuple(item.name for item in value)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError(
                "environment fingerprints must be unique and sorted"
            )
        return value


class ApprovalStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=r"^apr_[0-9a-f]{32}$")
    state: ApprovalState
    expires_at: datetime
    host: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    tool: str = Field(min_length=1, max_length=_MAX_TOOL_CHARS)
    risk: RiskLevel
    safe_summary: ApprovalSafeSummary
    binding_fingerprint: _SHORT_HMAC

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("expires_at must be timezone-aware UTC")
        return value
