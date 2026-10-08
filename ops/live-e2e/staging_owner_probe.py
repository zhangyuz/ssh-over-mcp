"""Dormant literal signal-zero presence check for one approved incident owner.

This does not send a delivered signal, accept a PID, or authorize cleanup.
Only an already-authorized, separately reviewed native preflight may call it.
"""

from __future__ import annotations

import os


class OwnerProbeError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("staging preflight rejected")


def require_owner_absent() -> None:
    """Only ESRCH proves the fixed historical provider owner is absent."""
    try:
        os.kill(38013, 0)
    except ProcessLookupError:
        return
    except (OSError, ValueError, TypeError, OverflowError, RuntimeError):
        raise OwnerProbeError() from None
    raise OwnerProbeError()
