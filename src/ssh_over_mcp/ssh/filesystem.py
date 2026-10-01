from __future__ import annotations

import uuid
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ssh_over_mcp.policy.models import Decision, EvaluationRequest

from .errors import (
    SSHApprovalRequired,
    SSHFilesystemWriteCommittedUncertain,
    SSHOutputLimitExceeded,
    SSHPolicyDenied,
    SSHRemoteOperationError,
    SSHRemotePolicyDenied,
    SSHRemoteResponseError,
    SSHRequestOutcomeUncertain,
    SSHRequestTimeout,
)
from .protocol import (
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    encode_request,
)
from .transport import SSHExecutionResult, StructuredSSHTransport

DEFAULT_FILESYSTEM_TIMEOUT_SECONDS = 60.0
MAX_FILESYSTEM_STAT_RESPONSE_BYTES = 64 * 1024
MAX_FILESYSTEM_READ_BYTES = 1024 * 1024
MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES = 4096
_REMOTE_WRITE_COMMITTED_EXIT_STATUS = 74
_REMOTE_POLICY_DENIED_EXIT_STATUS = 77


def _require_success(result: SSHExecutionResult) -> None:
    if result.timed_out:
        raise SSHRequestTimeout(
            "remote filesystem request timed out"
        )
    if result.truncated:
        raise SSHOutputLimitExceeded(
            "remote filesystem response exceeded output limit"
        )
    if result.exit_status == _REMOTE_POLICY_DENIED_EXIT_STATUS:
        raise SSHRemotePolicyDenied(
            "remote filesystem policy denied request"
        )
    if result.exit_signal is not None or result.exit_status != 0:
        raise SSHRemoteOperationError(
            "remote filesystem operation failed"
        )
    if result.stderr:
        raise SSHRemoteResponseError(
            "invalid remote filesystem response"
        )


class PolicyEvaluator(Protocol):
    def evaluate(self, request: EvaluationRequest): ...


class SSHFilesystemStatResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    path: str
    kind: Literal["regular", "directory"]
    size: int = Field(ge=0)
    mode: int = Field(ge=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mtime_ns: int


class SSHFilesystemReadResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    path: str
    data: bytes


class SSHFilesystemMkdirResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    path: str


class SSHFilesystemWriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    path: str
    content_length: int = Field(ge=0)


class _RemoteStatPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    kind: Literal["regular", "directory"]
    size: int = Field(ge=0)
    mode: int = Field(ge=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mtime_ns: int


class SSHFilesystemClient:
    """Policy-gated typed filesystem operations over structured SSH."""

    def __init__(
        self,
        *,
        policy: PolicyEvaluator,
        transport: StructuredSSHTransport,
        default_timeout_seconds: float = DEFAULT_FILESYSTEM_TIMEOUT_SECONDS,
    ) -> None:
        self.policy = policy
        self.transport = transport
        self.default_timeout_seconds = default_timeout_seconds

    async def stat(
        self,
        request: EvaluationRequest,
        *,
        request_id: str | None = None,
    ) -> SSHFilesystemStatResult:
        if request.tool != "fs_stat":
            raise ValueError("filesystem stat requires fs_stat policy request")

        decision = self.policy.evaluate(request)
        if decision.decision == Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision == Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = request_id or f"req_{uuid.uuid4().hex}"
        envelope = FsStatEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
        )
        result = await self.transport.run(
            host=request.host,
            payload=encode_request(envelope),
            request_id=req_id,
            timeout_seconds=self.default_timeout_seconds,
            max_output_bytes=MAX_FILESYSTEM_STAT_RESPONSE_BYTES,
        )
        _require_success(result)
        try:
            payload = _RemoteStatPayload.model_validate_json(result.stdout)
        except ValidationError:
            raise SSHRemoteResponseError(
                "invalid remote filesystem response"
            ) from None
        if payload.path != decision.normalized_path:
            raise SSHRemoteResponseError(
                "invalid remote filesystem response"
            )
        return SSHFilesystemStatResult(
            request_id=req_id,
            host=request.host,
            path=payload.path,
            kind=payload.kind,
            size=payload.size,
            mode=payload.mode,
            uid=payload.uid,
            gid=payload.gid,
            mtime_ns=payload.mtime_ns,
        )

    async def read(
        self,
        request: EvaluationRequest,
        *,
        max_bytes: int,
        request_id: str | None = None,
    ) -> SSHFilesystemReadResult:
        if request.tool != "fs_read":
            raise ValueError("filesystem read requires fs_read policy request")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
            or max_bytes > MAX_FILESYSTEM_READ_BYTES
        ):
            raise ValueError("filesystem read bound is invalid")

        decision = self.policy.evaluate(request)
        if decision.decision == Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision == Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = request_id or f"req_{uuid.uuid4().hex}"
        envelope = FsReadEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
            max_bytes=max_bytes,
        )
        result = await self.transport.run(
            host=request.host,
            payload=encode_request(envelope),
            request_id=req_id,
            timeout_seconds=self.default_timeout_seconds,
            max_output_bytes=max(
                max_bytes,
                MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
            ),
        )
        _require_success(result)
        if len(result.stdout) > max_bytes:
            raise SSHRemoteResponseError(
                "invalid remote filesystem response"
            )
        return SSHFilesystemReadResult(
            request_id=req_id,
            host=request.host,
            path=decision.normalized_path,
            data=result.stdout,
        )


    async def mkdir(
        self,
        request: EvaluationRequest,
        *,
        request_id: str | None = None,
    ) -> SSHFilesystemMkdirResult:
        if request.tool != "fs_mkdir":
            raise ValueError("filesystem mkdir requires fs_mkdir policy request")

        decision = self.policy.evaluate(request)
        if decision.decision == Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision == Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = request_id or f"req_{uuid.uuid4().hex}"
        envelope = FsMkdirEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
        )
        try:
            result = await self.transport.run(
                host=request.host,
                payload=encode_request(envelope),
                request_id=req_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
            )
        except SSHRequestOutcomeUncertain:
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            ) from None

        if (
            result.timed_out
            or result.truncated
            or result.exit_signal is not None
        ):
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )
        if result.exit_status == _REMOTE_POLICY_DENIED_EXIT_STATUS:
            raise SSHRemotePolicyDenied(
                "remote filesystem policy denied request"
            )
        if (
            result.exit_status != 0
            or result.stdout
            or result.stderr
        ):
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )

        return SSHFilesystemMkdirResult(
            request_id=req_id,
            host=request.host,
            path=decision.normalized_path,
        )


    async def write(
        self,
        request: EvaluationRequest,
        data: bytes,
        *,
        request_id: str | None = None,
    ) -> SSHFilesystemWriteResult:
        if request.tool != "fs_write":
            raise ValueError("filesystem write requires fs_write policy request")
        if not isinstance(data, bytes):
            raise TypeError("filesystem write data must be bytes")

        decision = self.policy.evaluate(request)
        if decision.decision == Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision == Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = request_id or f"req_{uuid.uuid4().hex}"
        envelope = FsWriteEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
            content_length=len(data),
        )
        try:
            result = await self.transport.run(
                host=request.host,
                payload=encode_request(envelope, data),
                request_id=req_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
            )
        except SSHRequestOutcomeUncertain:
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            ) from None

        if (
            result.timed_out
            or result.truncated
            or result.exit_signal is not None
        ):
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )
        if result.exit_status == _REMOTE_POLICY_DENIED_EXIT_STATUS:
            raise SSHRemotePolicyDenied(
                "remote filesystem policy denied request"
            )
        if result.exit_status == _REMOTE_WRITE_COMMITTED_EXIT_STATUS:
            raise SSHFilesystemWriteCommittedUncertain(
                "filesystem write committed; durability uncertain; "
                "do not retry blindly"
            )
        if (
            result.exit_status != 0
            or result.stdout
            or result.stderr
        ):
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )

        return SSHFilesystemWriteResult(
            request_id=req_id,
            host=request.host,
            path=decision.normalized_path,
            content_length=len(data),
        )
