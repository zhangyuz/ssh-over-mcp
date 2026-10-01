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


class ExecutionRequestError(ApiError):
    """Raised when an execution request attempts to exceed server-owned bounds."""


class ExecutionPolicyDeniedError(ApiError):
    """Raised when central policy denies execution."""


class ExecutionApprovalRequiredError(ApiError):
    """Raised when execution requires an approval path not available in Phase 4."""


class ExecutionCredentialError(ApiError):
    """Raised when server-owned SSH credentials are unavailable."""


class ExecutionHostKeyError(ApiError):
    """Raised when pinned SSH host identity verification fails."""


class ExecutionTransportError(ApiError):
    """Raised when the SSH transport cannot execute the request."""


class ExecutionFailureError(ApiError):
    """Raised when execution fails without a more specific public category."""
