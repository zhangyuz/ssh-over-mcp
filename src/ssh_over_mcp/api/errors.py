from datetime import datetime


class ApiError(RuntimeError):
    """Base class for stable Phase 4 application errors."""


class PrincipalConfigurationError(ApiError):
    """Raised when the server-owned principal cannot be constructed."""


class HostNotVisibleError(ApiError):
    """Raised when a host is absent or hidden from the trusted principal."""


class InvalidExplainToolError(ApiError):
    """Raised when policy explanation receives an unsupported tool identifier."""


class RuntimeConfigurationError(ApiError):
    """Raised when local MCP runtime settings are invalid."""


class InvalidExecutionLimitError(ApiError):
    """Raised when MCP input attempts to widen server-owned execution bounds."""


class PolicyDeniedError(ApiError):
    """Stable public error for central-policy denial."""


class ApprovalRequiredError(ApiError):
    """Stable public error for approval-required execution."""

    @classmethod
    def for_status(
        cls,
        *,
        request_id: str,
        approval_id: str,
        state: str,
        expires_at: datetime,
    ) -> "ApprovalRequiredError":
        state_text = str(state)
        expiry_text = expires_at.isoformat()
        return cls(
            "approval required: "
            f"request_id={request_id} "
            f"approval_id={approval_id} "
            f"state={state_text} "
            f"expires_at={expiry_text}; "
            "retry the exact operation with this approval_id only after approval"
        )


class SSHCredentialUnavailableError(ApiError):
    """Stable public error for credential resolution failure."""


class SSHHostKeyError(ApiError):
    """Stable public error for host-key verification failure."""


class SSHTransportError(ApiError):
    """Stable public error for SSH transport failure."""


class SSHExecutionError(ApiError):
    """Stable public error for unexpected execution-boundary failure."""


class AuditPersistenceError(ApiError):
    """Stable public error when required audit persistence fails."""


class AuditPersistenceOutcomeUncertainError(ApiError):
    """A side effect may have completed but required audit persistence failed."""


class RemotePolicyDeniedError(ApiError):
    """Stable public error for host-agent policy denial."""


class RemoteTimeoutError(ApiError):
    """Stable public error for a bounded remote request timeout."""


class RemoteOutputLimitError(ApiError):
    """Stable public error for a bounded remote response overflow."""


class FilesystemOperationError(ApiError):
    """Stable public error for remote filesystem failure."""


class FilesystemMutationOutcomeUncertainError(ApiError):
    """The remote mutation may have committed; blind retry is unsafe."""


class FilesystemWriteCommittedUncertainError(ApiError):
    """A file was published but its directory durability is uncertain."""
