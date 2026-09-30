from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ssh_over_mcp.policy.models import Decision, RiskLevel

ExplainableTool = Literal[
    "ssh_exec",
    "fs_stat",
    "fs_read",
    "fs_mkdir",
    "fs_write",
]


class PrincipalContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: str = Field(min_length=1)


class HostSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alias: str = Field(min_length=1)
    labels: tuple[str, ...] = Field(default_factory=tuple)
    capabilities: tuple[str, ...] = Field(default_factory=tuple)


class HostsListResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hosts: tuple[HostSummary, ...] = Field(default_factory=tuple)


class PolicyExplainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1)
    tool: ExplainableTool
    executable: str | None = None
    args: tuple[str, ...] = Field(default_factory=tuple)
    cwd: str | None = None
    path: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    privilege: str = "user"


class PolicyExplainResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    reason: str
    risk: RiskLevel
    normalized_executable: str | None = None
    normalized_cwd: str | None = None
    normalized_path: str | None = None
    approval_required: bool
    policy_version: str
