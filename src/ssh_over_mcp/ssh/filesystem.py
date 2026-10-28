from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.approvals.authorization import ExecutionAuthorizationGate
from ssh_over_mcp.approvals.binding import fingerprint_bytes
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import AuditPersistenceFailure, AuditRecorder
from ssh_over_mcp.host_agent.visibility_policy_v5 import canonical_visibility_path
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import VisibilitySnapshotV5
from ssh_over_mcp.policy.models import Decision, EvaluationRequest
from ssh_over_mcp.policy.visibility_compiler_v5 import (
    compile_visibility_rules,
    reauthorize_list_paths,
)

from .errors import (
    SSHAuditPersistenceError,
    SSHAuditPersistenceOutcomeUncertain,
    SSHConnectionError,
    SSHCredentialError,
    SSHFilesystemWriteCommittedUncertain,
    SSHHostKeyVerificationError,
    SSHOutputLimitExceeded,
    SSHPolicyDenied,
    SSHRemoteOperationError,
    SSHRemotePolicyDenied,
    SSHRemoteResponseError,
    SSHRequestOutcomeUncertain,
    SSHRequestTimeout,
)
from .filesystem_list_v2 import (
    MAX_LIST_RESPONSE_BYTES,
    SSHFilesystemListResult,
    VisibilityAuthority,
    decode_list_response,
    pinned_host_identity,
)
from .protocol import (
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    encode_request,
)
from .protocol_v2 import FSListRequestV2, encode_request_v2
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
        authorizer: ExecutionAuthorizationGate,
        audit: AuditRecorder,
        transport: StructuredSSHTransport,
        default_timeout_seconds: float = DEFAULT_FILESYSTEM_TIMEOUT_SECONDS,
        visibility_authority: VisibilityAuthority | None = None,
    ) -> None:
        self.visibility_authority = visibility_authority
        self.authorizer = authorizer
        self.audit = audit
        self.transport = transport
        self.default_timeout_seconds = default_timeout_seconds

    async def _audit_required(
        self,
        event_type: AuditEventType,
        *,
        context: OperationContext,
        request: EvaluationRequest,
        decision,
        facts: ApprovalExecutionFacts,
        result: SSHExecutionResult | None = None,
        side_effect_completed: bool = False,
    ) -> None:
        try:
            await self.audit.execution_event(
                event_type,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
        except AuditPersistenceFailure:
            if side_effect_completed:
                raise SSHAuditPersistenceOutcomeUncertain(
                    "audit persistence outcome is uncertain; "
                    "do not retry blindly"
                ) from None
            raise SSHAuditPersistenceError(
                "audit persistence failed"
            ) from None

    async def _audit_preserve(
        self,
        event_type: AuditEventType,
        *,
        context: OperationContext,
        request: EvaluationRequest,
        decision,
        facts: ApprovalExecutionFacts,
        result: SSHExecutionResult | None = None,
    ) -> None:
        try:
            await self.audit.execution_event(
                event_type,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
        except AuditPersistenceFailure:
            pass

    async def list(
        self,
        *,
        host: str,
        path: str,
        context: OperationContext,
        max_entries: int,
    ) -> SSHFilesystemListResult:
        """Inactive v2 adapter: trusted authority injection is mandatory.

        Only logical host, canonical root and scan bound are caller inputs.
        Identity/profile/request ID come exclusively from OperationContext.
        """
        if type(max_entries) is not int or not 1 <= max_entries <= 64:
            raise ValueError("invalid filesystem listing bound")
        root = canonical_visibility_path(path)
        request = EvaluationRequest(
            host=host, path=root, tool="fs_list", profile=context.principal.profile
        )
        authority = self.visibility_authority
        if authority is None:
            raise SSHRemoteResponseError("filesystem visibility authority unavailable")
        try:
            engine = authority.engine
            if engine.inventory is not self.transport.connections.inventory:
                raise ValueError("inventory mismatch")
            digest = engine.policy_version.removeprefix("sha256:")
            epoch = authority.current_epoch(host=host, policy_sha256=digest)
            pin = pinned_host_identity(engine.inventory.hosts[host].host_key)
            # Bind stable intent, including epoch/budget/pin, using existing
            # approval facts. Never place a signing key or MAC in audit state.
            intent = json.dumps(
                {
                    "host": host,
                    "root": root,
                    "max_entries": max_entries,
                    "policy_epoch": epoch,
                    "policy_sha256": digest,
                    "host_key_sha256": pin,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        except Exception:  # noqa: BLE001 — trusted provider errors must fail closed
            raise SSHRemoteResponseError("filesystem visibility authority unavailable") from None
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=self.default_timeout_seconds,
            effective_max_output_bytes=MAX_LIST_RESPONSE_BYTES,
            stdin_length=len(intent),
            stdin_fingerprint=fingerprint_bytes(intent),
        )
        decision = await self.authorizer.authorize(context, request, facts)
        # Compiler cannot represent approval grants yet. Even a consumed grant
        # cannot turn approval-required policy into a subtree ALLOW.
        if decision.decision != Decision.ALLOW or decision.normalized_path != root:
            raise SSHPolicyDenied(decision)
        result = None
        try:
            compiled = compile_visibility_rules(
                engine, host=host, profile=request.profile, operation="fs_list", root=root
            )
            if compiled.policy_sha256 != digest or decision.policy_version != "sha256:" + digest:
                raise ValueError("policy changed")
            instant = int(time.time())
            snapshot = VisibilitySnapshotV5(
                version=5,
                request_id=context.request_id,
                host=host,
                host_key_sha256=pin,
                principal=context.principal.principal_id,
                profile=context.principal.profile,
                operation="fs_list",
                root=root,
                policy_epoch=epoch,
                central_policy_sha256=digest,
                snapshot_id=uuid.uuid4().hex,
                max_entries=max_entries,
                issued_at=instant,
                expires_at=instant + 60,
                rules=compiled.rules,
            )

            def active():
                return (
                    authority.engine is engine
                    and engine.inventory is self.transport.connections.inventory
                    and engine.policy_version == engine._hash_policy() == "sha256:" + digest
                    and authority.current_epoch(host=host, policy_sha256=digest) == epoch
                    and pinned_host_identity(engine.inventory.hosts[host].host_key) == pin
                    and snapshot.issued_at <= time.time() < snapshot.expires_at
                    and authority.is_active(snapshot) is True
                )

            def recheck(entries=()):
                return reauthorize_list_paths(
                    engine,
                    host=host,
                    profile=request.profile,
                    root=root,
                    response_policy_sha256=digest,
                    result_paths=(e.path for e in entries),
                    max_entries=max_entries,
                    is_epoch_active=active,
                )

            recheck()
            signed = authority.sign(snapshot)
            if signed.payload != snapshot:
                raise ValueError("signer changed binding")
            frame = encode_request_v2(
                FSListRequestV2(
                    request_id=context.request_id,
                    profile=context.principal.profile,
                    root=root,
                    max_entries=max_entries,
                    signed_snapshot=signed,
                )
            )
            await self._audit_required(
                AuditEventType.EXECUTION_STARTED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            recheck()
            result = await self.transport.run_v2(
                host=host,
                payload=frame,
                request_id=context.request_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=MAX_LIST_RESPONSE_BYTES,
            )
            if result.request_id != context.request_id or result.host != host:
                result = None  # Never feed foreign attribution into audit.
                raise ValueError("transport binding mismatch")
            _require_success(result)
            response = decode_list_response(result.stdout)
            if (
                response.request_id != context.request_id
                or response.host != host
                or response.root != root
                or response.policy_epoch != epoch
                or response.snapshot_id != snapshot.snapshot_id
            ):
                raise ValueError("response binding mismatch")
            recheck(response.entries)
            await self._audit_required(
                AuditEventType.EXECUTION_COMPLETED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            # Audit persistence awaits may overlap a policy update/revocation.
            recheck(response.entries)
            return response
        except asyncio.CancelledError:
            await self._audit_preserve(
                AuditEventType.EXECUTION_CANCELLED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise
        except SSHAuditPersistenceError:
            raise
        except Exception as exc:
            event = (
                AuditEventType.REMOTE_POLICY_DENIED
                if isinstance(exc, SSHRemotePolicyDenied)
                else AuditEventType.HOST_KEY_FAILURE
                if isinstance(exc, SSHHostKeyVerificationError)
                else AuditEventType.EXECUTION_FAILED
            )
            await self._audit_required(
                event,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            if isinstance(
                exc,
                (
                    SSHRemotePolicyDenied,
                    SSHConnectionError,
                    SSHCredentialError,
                    SSHHostKeyVerificationError,
                    SSHRequestTimeout,
                    SSHOutputLimitExceeded,
                    SSHRemoteOperationError,
                ),
            ):
                raise
            raise SSHRemoteResponseError("invalid remote filesystem listing") from None

    async def stat(
        self,
        request: EvaluationRequest,
        *,
        context: OperationContext,
    ) -> SSHFilesystemStatResult:
        if request.tool != "fs_stat":
            raise ValueError("filesystem stat requires fs_stat policy request")

        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=self.default_timeout_seconds,
            effective_max_output_bytes=MAX_FILESYSTEM_STAT_RESPONSE_BYTES,
        )
        decision = await self.authorizer.authorize(
            context,
            request,
            facts,
        )
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = context.request_id
        envelope = FsStatEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
        )
        await self._audit_required(
            AuditEventType.EXECUTION_STARTED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
        )
        try:
            result = await self.transport.run(
                host=request.host,
                payload=encode_request(envelope),
                request_id=req_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=MAX_FILESYSTEM_STAT_RESPONSE_BYTES,
            )
        except asyncio.CancelledError:
            await self._audit_preserve(
                AuditEventType.EXECUTION_CANCELLED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise
        except Exception as exc:
            await self._audit_required(
                (
                    AuditEventType.HOST_KEY_FAILURE
                    if isinstance(exc, SSHHostKeyVerificationError)
                    else AuditEventType.EXECUTION_FAILED
                ),
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise

        try:
            _require_success(result)
            payload = _RemoteStatPayload.model_validate_json(result.stdout)
            if payload.path != decision.normalized_path:
                raise SSHRemoteResponseError(
                    "invalid remote filesystem response"
                )
        except SSHRemotePolicyDenied:
            await self._audit_required(
                AuditEventType.REMOTE_POLICY_DENIED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise
        except ValidationError:
            await self._audit_required(
                AuditEventType.EXECUTION_FAILED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRemoteResponseError(
                "invalid remote filesystem response"
            ) from None
        except (
            SSHRemoteResponseError,
            SSHRemoteOperationError,
            SSHRequestTimeout,
            SSHOutputLimitExceeded,
        ):
            await self._audit_required(
                AuditEventType.EXECUTION_FAILED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise

        await self._audit_required(
            AuditEventType.EXECUTION_COMPLETED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
            result=result,
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
        context: OperationContext,
        max_bytes: int,
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

        transport_output_limit = max(
            max_bytes,
            MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
        )
        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=self.default_timeout_seconds,
            effective_max_output_bytes=transport_output_limit,
            effective_tool_bytes=max_bytes,
        )
        decision = await self.authorizer.authorize(
            context,
            request,
            facts,
        )
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = context.request_id
        envelope = FsReadEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
            max_bytes=max_bytes,
        )
        await self._audit_required(
            AuditEventType.EXECUTION_STARTED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
        )
        try:
            result = await self.transport.run(
                host=request.host,
                payload=encode_request(envelope),
                request_id=req_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=transport_output_limit,
            )
        except asyncio.CancelledError:
            await self._audit_preserve(
                AuditEventType.EXECUTION_CANCELLED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise
        except Exception as exc:
            await self._audit_required(
                (
                    AuditEventType.HOST_KEY_FAILURE
                    if isinstance(exc, SSHHostKeyVerificationError)
                    else AuditEventType.EXECUTION_FAILED
                ),
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise

        try:
            _require_success(result)
            if len(result.stdout) > max_bytes:
                raise SSHRemoteResponseError(
                    "invalid remote filesystem response"
                )
        except SSHRemotePolicyDenied:
            await self._audit_required(
                AuditEventType.REMOTE_POLICY_DENIED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise
        except (
            SSHRemoteResponseError,
            SSHRemoteOperationError,
            SSHRequestTimeout,
            SSHOutputLimitExceeded,
        ):
            await self._audit_required(
                AuditEventType.EXECUTION_FAILED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise

        await self._audit_required(
            AuditEventType.EXECUTION_COMPLETED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
            result=result,
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
        context: OperationContext,
    ) -> SSHFilesystemMkdirResult:
        if request.tool != "fs_mkdir":
            raise ValueError("filesystem mkdir requires fs_mkdir policy request")

        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=self.default_timeout_seconds,
            effective_max_output_bytes=MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
        )
        decision = await self.authorizer.authorize(
            context,
            request,
            facts,
        )
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = context.request_id
        envelope = FsMkdirEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
        )
        await self._audit_required(
            AuditEventType.EXECUTION_STARTED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
        )
        try:
            result = await self.transport.run(
                host=request.host,
                payload=encode_request(envelope),
                request_id=req_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
            )
        except asyncio.CancelledError:
            await self._audit_preserve(
                AuditEventType.EXECUTION_CANCELLED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise
        except SSHRequestOutcomeUncertain:
            await self._audit_preserve(
                AuditEventType.MUTATION_OUTCOME_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            ) from None
        except Exception as exc:
            await self._audit_required(
                (
                    AuditEventType.HOST_KEY_FAILURE
                    if isinstance(exc, SSHHostKeyVerificationError)
                    else AuditEventType.EXECUTION_FAILED
                ),
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise

        if (
            result.timed_out
            or result.truncated
            or result.exit_signal is not None
        ):
            await self._audit_preserve(
                AuditEventType.MUTATION_OUTCOME_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )
        if result.exit_status == _REMOTE_POLICY_DENIED_EXIT_STATUS:
            await self._audit_required(
                AuditEventType.REMOTE_POLICY_DENIED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRemotePolicyDenied(
                "remote filesystem policy denied request"
            )
        if (
            result.exit_status != 0
            or result.stdout
            or result.stderr
        ):
            await self._audit_preserve(
                AuditEventType.MUTATION_OUTCOME_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )

        await self._audit_required(
            AuditEventType.EXECUTION_COMPLETED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
            result=result,
            side_effect_completed=True,
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
        context: OperationContext,
    ) -> SSHFilesystemWriteResult:
        if request.tool != "fs_write":
            raise ValueError("filesystem write requires fs_write policy request")
        if not isinstance(data, bytes):
            raise TypeError("filesystem write data must be bytes")

        facts = ApprovalExecutionFacts(
            effective_timeout_seconds=self.default_timeout_seconds,
            effective_max_output_bytes=MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
            content_length=len(data),
            content_fingerprint=fingerprint_bytes(data),
        )
        decision = await self.authorizer.authorize(
            context,
            request,
            facts,
        )
        if not decision.normalized_path:
            raise SSHPolicyDenied(decision)

        req_id = context.request_id
        envelope = FsWriteEnvelope(
            request_id=req_id,
            profile=request.profile,
            path=decision.normalized_path,
            content_length=len(data),
        )
        await self._audit_required(
            AuditEventType.EXECUTION_STARTED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
        )
        try:
            result = await self.transport.run(
                host=request.host,
                payload=encode_request(envelope, data),
                request_id=req_id,
                timeout_seconds=self.default_timeout_seconds,
                max_output_bytes=MIN_FILESYSTEM_TRANSPORT_OUTPUT_BYTES,
            )
        except asyncio.CancelledError:
            await self._audit_preserve(
                AuditEventType.EXECUTION_CANCELLED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise
        except SSHRequestOutcomeUncertain:
            await self._audit_preserve(
                AuditEventType.MUTATION_OUTCOME_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            ) from None
        except Exception as exc:
            await self._audit_required(
                (
                    AuditEventType.HOST_KEY_FAILURE
                    if isinstance(exc, SSHHostKeyVerificationError)
                    else AuditEventType.EXECUTION_FAILED
                ),
                context=context,
                request=request,
                decision=decision,
                facts=facts,
            )
            raise

        if (
            result.timed_out
            or result.truncated
            or result.exit_signal is not None
        ):
            await self._audit_preserve(
                AuditEventType.MUTATION_OUTCOME_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )
        if result.exit_status == _REMOTE_POLICY_DENIED_EXIT_STATUS:
            await self._audit_required(
                AuditEventType.REMOTE_POLICY_DENIED,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRemotePolicyDenied(
                "remote filesystem policy denied request"
            )
        if result.exit_status == _REMOTE_WRITE_COMMITTED_EXIT_STATUS:
            await self._audit_preserve(
                AuditEventType.FILESYSTEM_WRITE_COMMITTED_DURABILITY_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHFilesystemWriteCommittedUncertain(
                "filesystem write committed; durability uncertain; "
                "do not retry blindly"
            )
        if (
            result.exit_status != 0
            or result.stdout
            or result.stderr
        ):
            await self._audit_preserve(
                AuditEventType.MUTATION_OUTCOME_UNCERTAIN,
                context=context,
                request=request,
                decision=decision,
                facts=facts,
                result=result,
            )
            raise SSHRequestOutcomeUncertain(
                "remote filesystem mutation outcome is uncertain"
            )

        await self._audit_required(
            AuditEventType.EXECUTION_COMPLETED,
            context=context,
            request=request,
            decision=decision,
            facts=facts,
            result=result,
            side_effect_completed=True,
        )
        return SSHFilesystemWriteResult(
            request_id=req_id,
            host=request.host,
            path=decision.normalized_path,
            content_length=len(data),
        )
