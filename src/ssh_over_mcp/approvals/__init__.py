from __future__ import annotations

from importlib import import_module

from .models import (
    ApprovalBindingInput,
    ApprovalEnvFingerprint,
    ApprovalExecutionFacts,
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)

_LAZY_EXPORTS = {
    "SecurityLedgerAdminClient": (".client", "SecurityLedgerAdminClient"),
    "SecurityLedgerClient": (".client", "SecurityLedgerClient"),
    "SecurityLedgerRuntimeSettings": (
        ".runtime",
        "SecurityLedgerRuntimeSettings",
    ),
    "SecurityLedgerService": (".service", "SecurityLedgerService"),
}

__all__ = [
    "ApprovalBindingInput",
    "ApprovalEnvFingerprint",
    "ApprovalExecutionFacts",
    "ApprovalSafeSummary",
    "ApprovalState",
    "ApprovalStatus",
    "SecurityLedgerAdminClient",
    "SecurityLedgerClient",
    "SecurityLedgerRuntimeSettings",
    "SecurityLedgerService",
]


def __getattr__(name: str) -> object:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attribute_name = target
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
