from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RoleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    inherits: tuple[str, ...] = ()
    env_allow: tuple[str, ...] = ()
    env_deny: tuple[str, ...] = ()
    shell: bool = False
    sudo: bool = False


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    effect: Effect
    roles: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    host_labels: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    argv_prefix: tuple[str, ...] = ()
    cwd: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    privileges: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def trimmed_id(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("rule id must be trimmed")
        return value


class RiskPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_required: frozenset[RiskLevel] = frozenset(
        {RiskLevel.HIGH, RiskLevel.CRITICAL}
    )


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1)
    default: Literal["deny"] = "deny"
    roles: dict[str, RoleSpec]
    rules: tuple[PolicyRule, ...]
    risk: RiskPolicy = RiskPolicy()

    @field_validator("roles")
    @classmethod
    def nonempty_roles(cls, roles: dict[str, RoleSpec]) -> dict[str, RoleSpec]:
        if not roles:
            raise ValueError("policy must define at least one role")
        return roles

    @field_validator("rules")
    @classmethod
    def unique_rule_ids(cls, rules: tuple[PolicyRule, ...]) -> tuple[PolicyRule, ...]:
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("policy rule ids must be unique")
        return rules


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: str = Field(min_length=1)
    host: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    executable: str | None = None
    args: tuple[str, ...] = ()
    cwd: str | None = None
    path: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    privilege: str = "user"
    approval_granted: bool = False


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    reason: str
    risk: RiskLevel
    matched_allow_rules: tuple[str, ...] = ()
    matched_deny_rules: tuple[str, ...] = ()
    effective_roles: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    normalized_executable: str | None = None
    normalized_cwd: str | None = None
    normalized_path: str | None = None
    approval_required: bool = False
    policy_version: str
