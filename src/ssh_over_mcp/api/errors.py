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


class SSHCredentialUnavailableError(ApiError):
    """Stable public error for credential resolution failure."""


class SSHHostKeyError(ApiError):
    """Stable public error for host-key verification failure."""


class SSHTransportError(ApiError):
    """Stable public error for SSH transport failure."""


class SSHExecutionError(ApiError):
    """Stable public error for unexpected execution-boundary failure."""


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
