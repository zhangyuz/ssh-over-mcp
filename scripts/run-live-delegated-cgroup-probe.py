#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_BUILD_TIMEOUT_SECONDS = 60
_TEST_TIMEOUT_SECONDS = 90
_REQUIRED_ENV = (
    "SSH_OVER_MCP_LIVE_CGROUP_ROOT",
    "SSH_OVER_MCP_LIVE_CGROUP_HOST_SOURCE",
    "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID",
    "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID",
    "SSH_OVER_MCP_LIVE_CGROUP_HOST_UID",
    "SSH_OVER_MCP_LIVE_CGROUP_HOST_GID",
    "SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_UID",
    "SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_GID",
    "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_CLIENT_GID",
)


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("live delegated-cgroup proof requires Linux", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("live delegated-cgroup proof requires root bootstrap", file=sys.stderr)
        return 2

    missing = [name for name in _REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print(
            "missing required live fixture values: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    repository = Path(__file__).resolve().parents[1]
    probe = Path(f"/tmp/ssh-over-mcp-cgroup-workload-probe-{os.getpid()}")
    env = os.environ.copy()
    env["SSH_OVER_MCP_RUN_LIVE_CGROUP"] = "1"
    env["SSH_OVER_MCP_LIVE_CGROUP_PROBE_ELF"] = str(probe)

    try:
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-o",
                str(probe),
                "tests/live/cgroup_workload_probe.c",
            ],
            cwd=repository,
            check=True,
            timeout=_BUILD_TIMEOUT_SECONDS,
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/live/test_delegated_cgroup.py",
                "-k",
                "production_manager_client_barrier_and_migration_denial or real_pid_and_cpu_enforcement or real_memory_enforcement_with_request_scope_oom_attribution",
            ],
            cwd=repository,
            env=env,
            check=True,
            timeout=_TEST_TIMEOUT_SECONDS,
        )
    finally:
        probe.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
