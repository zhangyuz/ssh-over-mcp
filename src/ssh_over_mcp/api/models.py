from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ssh_over_mcp.approvals.models import ApprovalSafeSummary, ApprovalState
from ssh_over_mcp.host_agent.visibility_policy_v5 import canonical_visibility_path
from ssh_over_mcp.inventory.models import MAX_HOST_ALIAS_CHARS
from ssh_over_mcp.policy.models import Decision, RiskLevel

MAX_MCP_METADATA_BYTES = 64 * 1024
MAX_MCP_HOST_CHARS = MAX_HOST_ALIAS_CHARS
MAX_MCP_IDENTITY_CHARS = 256
MAX_MCP_PATH_CHARS = 4096
MAX_MCP_ARG_COUNT = 256
MAX_MCP_ARG_CHARS = 4096
MAX_MCP_ENV_ITEMS = 128
MAX_MCP_ENV_NAME_CHARS = 128
MAX_MCP_ENV_VALUE_CHARS = 8192
MAX_MCP_PRIVILEGE_CHARS = 64
MAX_MCP_EXEC_STDIN_BYTES = 64 * 1024
MAX_MCP_EXEC_TIMEOUT_SECONDS = 60.0
MAX_MCP_FILESYSTEM_READ_BYTES = 1024 * 1024
MAX_MCP_FILESYSTEM_WRITE_BYTES = 64 * 1024
MAX_MCP_FILESYSTEM_WRITE_BASE64_CHARS = (
    ((MAX_MCP_FILESYSTEM_WRITE_BYTES + 2) // 3) * 4
)

MCPHostAlias = Annotated[
    str,
    Field(min_length=1, max_length=MAX_MCP_HOST_CHARS),
]
MCPApprovalID = Annotated[
    str,
    Field(pattern=r"^apr_[0-9a-f]{32}$"),
]
_MCP_BINDING_FINGERPRINT = Annotated[
    str,
    Field(pattern=r"^hmac-sha256:v1:[0-9a-f]{16}$"),
]
_MCP_PATH = Annotated[str, Field(max_length=MAX_MCP_PATH_CHARS)]
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

    principal_id: str = Field(
        min_length=1,
        max_length=MAX_MCP_IDENTITY_CHARS,
    )
    profile: str = Field(
        min_length=1,
        max_length=MAX_MCP_IDENTITY_CHARS,
    )


class HostSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alias: MCPHostAlias
    labels: tuple[str, ...] = Field(default_factory=tuple)
    capabilities: tuple[str, ...] = Field(default_factory=tuple)


class HostsListResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hosts: tuple[HostSummary, ...] = Field(default_factory=tuple)


class PolicyExplainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
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


class ApprovalStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: MCPApprovalID


class ApprovalStatusResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: MCPApprovalID
    state: ApprovalState
    expires_at: datetime
    host: MCPHostAlias
    tool: ExplainableTool
    risk: RiskLevel
    safe_summary: ApprovalSafeSummary
    binding_fingerprint: _MCP_BINDING_FINGERPRINT

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("expires_at must be timezone-aware UTC")
        return value


class SSHExecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
    executable: str = Field(
        min_length=1,
        max_length=MAX_MCP_PATH_CHARS,
    )
    args: tuple[_MCP_ARG, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MCP_ARG_COUNT,
    )
    cwd: _MCP_PATH | None = None
    env: dict[_MCP_ENV_NAME, _MCP_ENV_VALUE] = Field(
        default_factory=dict,
        max_length=MAX_MCP_ENV_ITEMS,
    )
    stdin: str = ""
    timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        le=MAX_MCP_EXEC_TIMEOUT_SECONDS,
    )
    approval_id: MCPApprovalID | None = None

    @model_validator(mode="after")
    def validate_execution_bounds(self) -> SSHExecRequest:
        if len(self.stdin.encode("utf-8")) > MAX_MCP_EXEC_STDIN_BYTES:
            raise ValueError("MCP ssh_exec stdin exceeds maximum size")
        if (
            len(
                self.model_dump_json(
                    exclude={"stdin"},
                ).encode("utf-8")
            )
            > MAX_MCP_METADATA_BYTES
        ):
            raise ValueError("MCP tool metadata exceeds maximum size")
        return self


class SSHExecResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1)
    host: MCPHostAlias
    exit_status: int | None = None
    exit_signal: str | None = None
    stdout_base64: str = ""
    stderr_base64: str = ""
    duration_ms: int = Field(ge=0)
    timed_out: bool = False
    truncated: bool = False


MCPListPath = Annotated[str, Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)]
MCPListMaxEntries = Annotated[int, Field(strict=True, ge=1, le=64)]


class FsListRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
    path: MCPListPath
    max_entries: MCPListMaxEntries

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return canonical_visibility_path(value)


class FsListEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: MCPListPath
    kind: Literal["regular", "directory"]
    size: int = Field(ge=0, le=2**63 - 1)
    mode: int = Field(ge=0, le=0o7777)
    uid: int = Field(ge=0, le=2**32 - 1)
    gid: int = Field(ge=0, le=2**32 - 1)
    mtime_ns: int = Field(ge=-(2**63), le=2**63 - 1)


class FsListResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1)
    host: MCPHostAlias
    path: MCPListPath
    entries: tuple[FsListEntry, ...] = Field(max_length=64)


class FsStatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    approval_id: MCPApprovalID | None = None


class FsStatResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1)
    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    kind: Literal["regular", "directory"]
    size: int = Field(ge=0)
    mode: int = Field(ge=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mtime_ns: int


class FsReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    max_bytes: int = Field(
        strict=True,
        ge=1,
        le=MAX_MCP_FILESYSTEM_READ_BYTES,
    )
    approval_id: MCPApprovalID | None = None


class FsReadResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1)
    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    data_base64: str


class FsMkdirRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    approval_id: MCPApprovalID | None = None


class FsMkdirResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1)
    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)


class FsWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    data_base64: str = Field(
        max_length=MAX_MCP_FILESYSTEM_WRITE_BASE64_CHARS,
    )
    approval_id: MCPApprovalID | None = None

    @field_validator("data_base64")
    @classmethod
    def validate_data_base64(cls, value: str) -> str:
        try:
            encoded = value.encode("ascii")
            decoded = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise ValueError("filesystem write data must be strict base64") from exc
        if len(decoded) > MAX_MCP_FILESYSTEM_WRITE_BYTES:
            raise ValueError("filesystem write data exceeds maximum size")
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("filesystem write data must be canonical base64")
        return value

    def decoded_data(self) -> bytes:
        return base64.b64decode(
            self.data_base64.encode("ascii"),
            validate=True,
        )


class FsWriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1)
    host: MCPHostAlias
    path: str = Field(min_length=1, max_length=MAX_MCP_PATH_CHARS)
    content_length: int = Field(ge=0, le=MAX_MCP_FILESYSTEM_WRITE_BYTES)
