from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ssh_over_mcp.policy.models import Decision, RiskLevel

MAX_MCP_METADATA_BYTES = 64 * 1024
MAX_MCP_PATH_CHARS = 4096
MAX_MCP_ARG_COUNT = 256
MAX_MCP_ARG_CHARS = 4096
MAX_MCP_ENV_ITEMS = 128
MAX_MCP_ENV_NAME_CHARS = 128
MAX_MCP_ENV_VALUE_CHARS = 8192
MAX_MCP_PRIVILEGE_CHARS = 64
MAX_MCP_STDIN_CHARS = 1024 * 1024

_MCP_PATH = Annotated[str, Field(max_length=MAX_MCP_PATH_CHARS)]
_MCP_REQUIRED_PATH = Annotated[
    str,
    Field(min_length=1, max_length=MAX_MCP_PATH_CHARS),
]
_MCP_ARG = Annotated[str, Field(max_length=MAX_MCP_ARG_CHARS)]
_MCP_ENV_NAME = Annotated[
    str,
    Field(min_length=1, max_length=MAX_MCP_ENV_NAME_CHARS),
]
_MCP_ENV_VALUE = Annotated[
    str,
    Field(max_length=MAX_MCP_ENV_VALUE_CHARS),
]

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
    executable: _MCP_PATH | None = None
    args: tuple[_MCP_ARG, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MCP_ARG_COUNT,
    )
    cwd: _MCP_PATH | None = None
    path: _MCP_PATH | None = None
    env: dict[_MCP_ENV_NAME, _MCP_ENV_VALUE] = Field(
        default_factory=dict,
        max_length=MAX_MCP_ENV_ITEMS,
    )
    privilege: str = Field(
        default="user",
        min_length=1,
        max_length=MAX_MCP_PRIVILEGE_CHARS,
    )

    @model_validator(mode="after")
    def validate_metadata_size(self) -> PolicyExplainRequest:
        if len(self.model_dump_json().encode("utf-8")) > MAX_MCP_METADATA_BYTES:
            raise ValueError("MCP tool metadata exceeds maximum size")
        return self


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


class SSHExecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1)
    executable: _MCP_REQUIRED_PATH
    args: tuple[_MCP_ARG, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MCP_ARG_COUNT,
    )
    cwd: _MCP_PATH | None = None
    env: dict[_MCP_ENV_NAME, _MCP_ENV_VALUE] = Field(
        default_factory=dict,
        max_length=MAX_MCP_ENV_ITEMS,
    )
    stdin: str | None = Field(
        default=None,
        max_length=MAX_MCP_STDIN_CHARS,
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        allow_inf_nan=False,
    )

    @model_validator(mode="after")
    def validate_metadata_size(self) -> SSHExecRequest:
        metadata = self.model_dump_json(exclude={"stdin"})
        if len(metadata.encode("utf-8")) > MAX_MCP_METADATA_BYTES:
            raise ValueError("MCP tool metadata exceeds maximum size")
        return self


class SSHExecResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    exit_status: int | None = None
    exit_signal: str | None = None
    stdout_base64: str
    stderr_base64: str
    duration_ms: int = Field(ge=0)
    timed_out: bool = False
    truncated: bool = False
