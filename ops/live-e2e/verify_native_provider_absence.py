"""Read-only, fixed-authority postrun provider-marker check for trusted main.

The callable accepts a disposable directory to permit real filesystem
adversarial tests; the executable entrypoint never accepts an alternate root.
"""

from __future__ import annotations

import os
import pwd
import sys
from contextlib import ExitStack
from pathlib import Path

FIXED_PROVIDER_HOME = "/Users/gha-e2e-orchestrator"
_PROVIDER_ACCOUNT = "gha-e2e-orchestrator"
_PROVIDER_UID = 502
_CACHE_COMPONENTS = ("Library", "Caches", "ssh-over-mcp-e2e")
_MARKER = "active-run.json"


def assert_marker_absent_at(home: Path) -> None:
    """Only an absent marker *leaf* is success under the held no-follow chain.

    For actual host calls, main() always passes FIXED_PROVIDER_HOME. This
    argument exists for isolated tests, not the production CLI/workflow.
    """
    if not home.is_absolute():
        raise ValueError("provider home must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as opened:
        fd = os.open(home, flags)
        opened.callback(os.close, fd)
        for component in _CACHE_COMPONENTS:
            fd = os.open(component, flags, dir_fd=fd)
            opened.callback(os.close, fd)
        try:
            os.stat(_MARKER, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError("provider marker entry still present")


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise ValueError("provider check takes no path or other arguments")
        if os.environ.get("HOME") != FIXED_PROVIDER_HOME:
            raise ValueError("HOME does not match fixed trusted provider home")
        account = pwd.getpwnam(_PROVIDER_ACCOUNT)
        if account.pw_uid != _PROVIDER_UID or account.pw_dir != FIXED_PROVIDER_HOME:
            raise ValueError("dedicated provider account is not the pinned identity")
        if os.getuid() != _PROVIDER_UID or os.geteuid() != _PROVIDER_UID:
            raise ValueError("native postrun check must run as UID502")
        assert_marker_absent_at(Path(FIXED_PROVIDER_HOME))
        return 0
    except (OSError, KeyError, ValueError) as exc:
        print(f"::error::Unable to prove fixed provider marker absent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
