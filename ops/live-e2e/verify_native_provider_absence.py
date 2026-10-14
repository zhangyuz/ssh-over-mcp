"""Read-only, fixed-authority postrun provider-marker check for trusted main.

The callable accepts a disposable directory to permit real filesystem
adversarial tests; the executable entrypoint never accepts an alternate root.
"""

from __future__ import annotations

import os
import pwd
import stat
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
    Exact edge revalidation detects observed parent swaps but cannot make
    POSIX directory lookup atomic against a malicious same-UID concurrent
    writer; native provider execution assumes a serialized single-writer context.
    """
    if not home.is_absolute():
        raise ValueError("provider home must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def identity(observation: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            observation.st_dev,
            observation.st_ino,
            observation.st_uid,
            observation.st_gid,
            observation.st_mode,
        )

    with ExitStack() as opened:
        fd = os.open(home, flags)
        opened.callback(os.close, fd)
        home_identity = identity(os.fstat(fd))
        # Retain every originally opened parent and child FD/identity. A no-follow
        # open alone is NOT proof that the current canonical directory name
        # continues to refer to the opened inode after a concurrent rename.
        edges: list[tuple[int, str, int, tuple[int, int, int, int, int]]] = []
        for component in _CACHE_COMPONENTS:
            parent_fd = fd
            fd = os.open(component, flags, dir_fd=parent_fd)
            opened.callback(os.close, fd)
            edges.append((parent_fd, component, fd, identity(os.fstat(fd))))

        def verify_canonical_chain() -> None:
            root = os.stat(home, follow_symlinks=False)
            if not stat.S_ISDIR(root.st_mode) or identity(root) != home_identity:
                raise ValueError("fixed provider home identity drift")
            if identity(os.fstat(edges[0][0])) != home_identity:
                raise ValueError("opened provider home FD drift")
            for parent_fd, name, child_fd, pinned in edges:
                observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(observed.st_mode)
                    or identity(observed) != pinned
                    or identity(os.fstat(child_fd)) != pinned
                ):
                    raise ValueError(f"provider directory entry drift: {name}")

        # Check before and after observing ENOENT to detect a renamed/replaced
        # parent. This is not an atomic snapshot against hostile same-UID writes.
        verify_canonical_chain()
        try:
            os.stat(_MARKER, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            verify_canonical_chain()
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
