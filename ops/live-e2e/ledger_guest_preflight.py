"""Fixed no-core policy for the trusted, disposable Linux guest only."""

from __future__ import annotations

import os
import resource
import sys
from pathlib import Path

_CORE_PATTERN = Path("/proc/sys/kernel/core_pattern")


class ProfileError(RuntimeError):
    """The disposable guest cannot establish or verify its fixed profile."""


def _require_zero_core_limits() -> None:
    try:
        limits = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError) as exc:
        raise ProfileError("guest core limits are unavailable") from exc
    if limits != (0, 0):
        raise ProfileError("guest core limits must both be zero")


def require_no_core() -> None:
    """Verify effective policy without modifying or repairing any state."""
    if sys.platform != "linux":
        raise ProfileError("guest core policy requires Linux")
    _require_zero_core_limits()
    try:
        pattern = _CORE_PATTERN.read_bytes()
    except OSError as exc:
        raise ProfileError("guest core pattern is unavailable") from exc
    if pattern != b"core\n":
        raise ProfileError("guest core pattern is not the fixed non-pipe pattern")


def establish_guest_no_core() -> None:
    """Called only by the gate after verified root/workspace/fresh-state checks."""
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ProfileError("guest core setup requires Linux guest root")
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as exc:
        raise ProfileError("guest core limits could not be set") from exc
    _require_zero_core_limits()
    try:
        _CORE_PATTERN.write_text("core\n", encoding="ascii")
    except OSError as exc:
        raise ProfileError("guest core pattern could not be set") from exc
    require_no_core()
