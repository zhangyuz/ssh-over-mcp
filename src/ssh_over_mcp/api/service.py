from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
)
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
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

from .context import OperationContext
from .errors import (
    ApprovalRequiredError,
    AuditPersistenceError,
    AuditPersistenceOutcomeUncertainError,
    FilesystemMutationOutcomeUncertainError,
    FilesystemOperationError,
    FilesystemWriteCommittedUncertainError,
    HostNotVisibleError,
    InvalidExecutionLimitError,
    InvalidExplainToolError,
    PolicyDeniedError,
    RemoteOutputLimitError,
    RemotePolicyDeniedError,
    RemoteTimeoutError,
    SSHCredentialUnavailableError,
    SSHExecutionError,
    SSHHostKeyError,
    SSHTransportError,
)
from .models import (
    FsMkdirRequest,
    FsMkdirResult,
    FsReadRequest,
    FsReadResult,
    FsStatRequest,
    FsStatResult,
    FsWriteRequest,
    FsWriteResult,
    HostsListResult,
    HostSummary,
    PolicyExplainRequest,
    PolicyExplainResult,
    PrincipalContext,
    SSHExecRequest,
    SSHExecResult,
)

if TYPE_CHECKING:
    from ssh_over_mcp.ssh.executor import SSHExecutor
    from ssh_over_mcp.ssh.filesystem import SSHFilesystemClient


_EXPLAINABLE_TOOLS = frozenset(
    {
        "ssh_exec",
        "fs_stat",
        "fs_read",
        "fs_mkdir",
        "fs_write",
    }
)

_PUBLIC_REASONS = {
    Decision.ALLOW: "allowed by central policy",
    Decision.DENY: "denied by central policy",
    Decision.APPROVAL_REQUIRED: "approval required by central policy",
}


class MCPService:
    def __init__(
        self,
        *,
        inventory: Inventory,
        policy: PolicyEngine,
        ssh_executor: SSHExecutor | None = None,
        ssh_filesystem: SSHFilesystemClient | None = None,
    ) -> None:
        self._inventory = inventory
        self._policy = policy
        self._ssh_executor = ssh_executor
        self._ssh_filesystem = ssh_filesystem

    @staticmethod
    def _is_visible(host: Host, profile: str) -> bool:
        return not host.allowed_roles or profile in host.allowed_roles

    def _visible_host(
        self,
        principal: PrincipalContext,
        alias: str,
    ) -> Host:
        host = self._inventory.hosts.get(alias)
        if host is None or not self._is_visible(host, principal.profile):
            raise HostNotVisibleError("host is not visible")
        return host

    @staticmethod
    def _summary(alias: str) -> HostSummary:
        return HostSummary(alias=alias)

    def list_hosts(
        self,
        context: OperationContext,
    ) -> HostsListResult:
        principal = context.principal
        visible = tuple(
            self._summary(alias)
            for alias, host in sorted(self._inventory.hosts.items())
            if self._is_visible(host, principal.profile)
        )
        return HostsListResult(hosts=visible)

    def get_host(
        self,
        context: OperationContext,
        alias: str,
    ) -> HostSummary:
        principal = context.principal
        self._visible_host(principal, alias)
        return self._summary(alias)

    def explain_policy(
        self,
        context: OperationContext,
        request: PolicyExplainRequest,
    ) -> PolicyExplainResult:
        principal = context.principal
        self._visible_host(principal, request.host)
        if request.tool not in _EXPLAINABLE_TOOLS:
            raise InvalidExplainToolError(
                "policy explanation tool is invalid"
            )

        decision = self._policy.evaluate(
            EvaluationRequest(
                profile=principal.profile,
                host=request.host,
                tool=request.tool,
                executable=request.executable,
                args=request.args,
                cwd=request.cwd,
                path=request.path,
                env=request.env,
                privilege=request.privilege,
            )
        )

        return PolicyExplainResult(
            decision=decision.decision,
            reason=_PUBLIC_REASONS[decision.decision],
            risk=decision.risk,
            normalized_executable=decision.normalized_executable,
            normalized_cwd=decision.normalized_cwd,
            normalized_path=decision.normalized_path,
            approval_required=decision.approval_required,
            policy_version=decision.policy_version,
        )


    async def ssh_exec(
        self,
        context: OperationContext,
        request: SSHExecRequest,
    ) -> SSHExecResult:
        principal = context.principal
        self._visible_host(principal, request.host)
        if self._ssh_executor is None:
            raise SSHExecutionError("SSH execution is unavailable")

        stdin = request.stdin.encode("utf-8")
        if (
            request.timeout_seconds is not None
            and request.timeout_seconds
            > self._ssh_executor.default_timeout_seconds
        ):
            raise InvalidExecutionLimitError(
                "execution limits are invalid"
            )
        if len(stdin) > self._ssh_executor.default_max_stdin_bytes:
            raise InvalidExecutionLimitError(
                "execution limits are invalid"
            )

        try:
            result = await self._ssh_executor.execute(
                EvaluationRequest(
                    profile=principal.profile,
                    host=request.host,
                    tool="ssh_exec",
                    executable=request.executable,
                    args=request.args,
                    cwd=request.cwd,
                    env=request.env,
                    privilege="user",
                ),
                context=context,
                stdin=stdin,
                timeout_seconds=request.timeout_seconds,
            )
        except SSHPolicyDenied:
            raise PolicyDeniedError(
                "request denied by central policy"
            ) from None
        except SSHApprovalRequired as exc:
            status = exc.approval_status
            if status is None:
                raise ApprovalRequiredError(
                    "approval required by central policy"
                ) from None
            raise ApprovalRequiredError.for_status(
                request_id=context.request_id,
                approval_id=status.approval_id,
                state=status.state,
                expires_at=status.expires_at,
            ) from None
        except SSHCredentialError:
            raise SSHCredentialUnavailableError(
                "SSH credential is unavailable"
            ) from None
        except SSHHostKeyVerificationError:
            raise SSHHostKeyError(
                "SSH host key verification failed"
            ) from None
        except SSHConnectionError:
            raise SSHTransportError("SSH transport failed") from None
        except SSHAuditPersistenceOutcomeUncertain:
            raise AuditPersistenceOutcomeUncertainError(
                "audit persistence outcome is uncertain; do not retry blindly"
            ) from None
        except SSHAuditPersistenceError:
            raise AuditPersistenceError("audit persistence failed") from None
        except Exception:  # noqa: BLE001
            # This is the public adapter boundary: foreign SSH/library
            # exceptions must never cross it with raw detail.
            raise SSHExecutionError("SSH execution failed") from None

        return SSHExecResult(
            request_id=result.request_id,
            host=result.host,
            exit_status=result.exit_status,
            exit_signal=result.exit_signal,
            stdout_base64=base64.b64encode(result.stdout).decode("ascii"),
            stderr_base64=base64.b64encode(result.stderr).decode("ascii"),
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            truncated=result.truncated,
        )

    async def fs_stat(
        self,
        context: OperationContext,
        request: FsStatRequest,
    ) -> FsStatResult:
        principal = context.principal
        self._visible_host(principal, request.host)
        if self._ssh_filesystem is None:
            raise FilesystemOperationError(
                "filesystem operation is unavailable"
            )

        try:
            result = await self._ssh_filesystem.stat(
                EvaluationRequest(
                    profile=principal.profile,
                    host=request.host,
                    tool="fs_stat",
                    path=request.path,
                    privilege="user",
                ),
                context=context,
            )
        except SSHPolicyDenied:
            raise PolicyDeniedError(
                "request denied by central policy"
            ) from None
        except SSHApprovalRequired:
            raise ApprovalRequiredError(
                "approval required by central policy"
            ) from None
        except SSHCredentialError:
            raise SSHCredentialUnavailableError(
                "SSH credential is unavailable"
            ) from None
        except SSHHostKeyVerificationError:
            raise SSHHostKeyError(
                "SSH host key verification failed"
            ) from None
        except SSHConnectionError:
            raise SSHTransportError("SSH transport failed") from None
        except SSHAuditPersistenceOutcomeUncertain:
            raise AuditPersistenceOutcomeUncertainError(
                "audit persistence outcome is uncertain; do not retry blindly"
            ) from None
        except SSHAuditPersistenceError:
            raise AuditPersistenceError("audit persistence failed") from None
        except SSHRemotePolicyDenied:
            raise RemotePolicyDeniedError(
                "remote filesystem policy denied request"
            ) from None
        except SSHRequestTimeout:
            raise RemoteTimeoutError(
                "remote filesystem request timed out"
            ) from None
        except SSHOutputLimitExceeded:
            raise RemoteOutputLimitError(
                "remote filesystem response exceeded output limit"
            ) from None
        except (SSHRemoteOperationError, SSHRemoteResponseError):
            raise FilesystemOperationError(
                "remote filesystem operation failed"
            ) from None
        except Exception:  # noqa: BLE001
            raise FilesystemOperationError(
                "remote filesystem operation failed"
            ) from None

        return FsStatResult(
            request_id=result.request_id,
            host=result.host,
            path=result.path,
            kind=result.kind,
            size=result.size,
            mode=result.mode,
            uid=result.uid,
            gid=result.gid,
            mtime_ns=result.mtime_ns,
        )

    async def fs_read(
        self,
        context: OperationContext,
        request: FsReadRequest,
    ) -> FsReadResult:
        principal = context.principal
        self._visible_host(principal, request.host)
        if self._ssh_filesystem is None:
            raise FilesystemOperationError(
                "filesystem operation is unavailable"
            )

        try:
            result = await self._ssh_filesystem.read(
                EvaluationRequest(
                    profile=principal.profile,
                    host=request.host,
                    tool="fs_read",
                    path=request.path,
                    privilege="user",
                ),
                context=context,
                max_bytes=request.max_bytes,
            )
        except SSHPolicyDenied:
            raise PolicyDeniedError(
                "request denied by central policy"
            ) from None
        except SSHApprovalRequired:
            raise ApprovalRequiredError(
                "approval required by central policy"
            ) from None
        except SSHCredentialError:
            raise SSHCredentialUnavailableError(
                "SSH credential is unavailable"
            ) from None
        except SSHHostKeyVerificationError:
            raise SSHHostKeyError(
                "SSH host key verification failed"
            ) from None
        except SSHConnectionError:
            raise SSHTransportError("SSH transport failed") from None
        except SSHAuditPersistenceOutcomeUncertain:
            raise AuditPersistenceOutcomeUncertainError(
                "audit persistence outcome is uncertain; do not retry blindly"
            ) from None
        except SSHAuditPersistenceError:
            raise AuditPersistenceError("audit persistence failed") from None
        except SSHRemotePolicyDenied:
            raise RemotePolicyDeniedError(
                "remote filesystem policy denied request"
            ) from None
        except SSHRequestTimeout:
            raise RemoteTimeoutError(
                "remote filesystem request timed out"
            ) from None
        except SSHOutputLimitExceeded:
            raise RemoteOutputLimitError(
                "remote filesystem response exceeded output limit"
            ) from None
        except (SSHRemoteOperationError, SSHRemoteResponseError):
            raise FilesystemOperationError(
                "remote filesystem operation failed"
            ) from None
        except Exception:  # noqa: BLE001
            raise FilesystemOperationError(
                "remote filesystem operation failed"
            ) from None

        return FsReadResult(
            request_id=result.request_id,
            host=result.host,
            path=result.path,
            data_base64=base64.b64encode(result.data).decode("ascii"),
        )

    async def fs_mkdir(
        self,
        context: OperationContext,
        request: FsMkdirRequest,
    ) -> FsMkdirResult:
        principal = context.principal
        self._visible_host(principal, request.host)
        if self._ssh_filesystem is None:
            raise FilesystemOperationError(
                "filesystem operation is unavailable"
            )

        try:
            result = await self._ssh_filesystem.mkdir(
                EvaluationRequest(
                    profile=principal.profile,
                    host=request.host,
                    tool="fs_mkdir",
                    path=request.path,
                    privilege="user",
                ),
                context=context,
            )
        except SSHPolicyDenied:
            raise PolicyDeniedError(
                "request denied by central policy"
            ) from None
        except SSHApprovalRequired:
            raise ApprovalRequiredError(
                "approval required by central policy"
            ) from None
        except SSHCredentialError:
            raise SSHCredentialUnavailableError(
                "SSH credential is unavailable"
            ) from None
        except SSHHostKeyVerificationError:
            raise SSHHostKeyError(
                "SSH host key verification failed"
            ) from None
        except SSHConnectionError:
            raise SSHTransportError("SSH transport failed") from None
        except SSHAuditPersistenceOutcomeUncertain:
            raise AuditPersistenceOutcomeUncertainError(
                "audit persistence outcome is uncertain; do not retry blindly"
            ) from None
        except SSHAuditPersistenceError:
            raise AuditPersistenceError("audit persistence failed") from None
        except SSHRemotePolicyDenied:
            raise RemotePolicyDeniedError(
                "remote filesystem policy denied request"
            ) from None
        except SSHRequestOutcomeUncertain:
            raise FilesystemMutationOutcomeUncertainError(
                "remote filesystem mutation outcome is uncertain; "
                "do not retry blindly"
            ) from None
        except Exception:  # noqa: BLE001
            raise FilesystemMutationOutcomeUncertainError(
                "remote filesystem mutation outcome is uncertain; "
                "do not retry blindly"
            ) from None

        return FsMkdirResult(
            request_id=result.request_id,
            host=result.host,
            path=result.path,
        )


    async def fs_write(
        self,
        context: OperationContext,
        request: FsWriteRequest,
    ) -> FsWriteResult:
        principal = context.principal
        self._visible_host(principal, request.host)
        if self._ssh_filesystem is None:
            raise FilesystemOperationError(
                "filesystem operation is unavailable"
            )

        data = request.decoded_data()
        try:
            result = await self._ssh_filesystem.write(
                EvaluationRequest(
                    profile=principal.profile,
                    host=request.host,
                    tool="fs_write",
                    path=request.path,
                    privilege="user",
                ),
                data,
                context=context,
            )
        except SSHPolicyDenied:
            raise PolicyDeniedError(
                "request denied by central policy"
            ) from None
        except SSHApprovalRequired:
            raise ApprovalRequiredError(
                "approval required by central policy"
            ) from None
        except SSHCredentialError:
            raise SSHCredentialUnavailableError(
                "SSH credential is unavailable"
            ) from None
        except SSHHostKeyVerificationError:
            raise SSHHostKeyError(
                "SSH host key verification failed"
            ) from None
        except SSHConnectionError:
            raise SSHTransportError("SSH transport failed") from None
        except SSHAuditPersistenceOutcomeUncertain:
            raise AuditPersistenceOutcomeUncertainError(
                "audit persistence outcome is uncertain; do not retry blindly"
            ) from None
        except SSHAuditPersistenceError:
            raise AuditPersistenceError("audit persistence failed") from None
        except SSHRemotePolicyDenied:
            raise RemotePolicyDeniedError(
                "remote filesystem policy denied request"
            ) from None
        except SSHFilesystemWriteCommittedUncertain:
            raise FilesystemWriteCommittedUncertainError(
                "filesystem write committed; durability uncertain; "
                "do not retry blindly"
            ) from None
        except SSHRequestOutcomeUncertain:
            raise FilesystemMutationOutcomeUncertainError(
                "remote filesystem mutation outcome is uncertain; "
                "do not retry blindly"
            ) from None
        except Exception:  # noqa: BLE001
            raise FilesystemMutationOutcomeUncertainError(
                "remote filesystem mutation outcome is uncertain; "
                "do not retry blindly"
            ) from None

        return FsWriteResult(
            request_id=result.request_id,
            host=result.host,
            path=result.path,
            content_length=result.content_length,
        )
