class ApiError(RuntimeError):
    """Base class for stable Phase 4 application errors."""


class PrincipalConfigurationError(ApiError):
    """Raised when the server-owned principal cannot be constructed."""


class HostNotVisibleError(ApiError):
    """Raised when a host is absent or hidden from the trusted principal."""


class InvalidExplainToolError(ApiError):
    """Raised when policy explanation receives an unsupported tool identifier."""
