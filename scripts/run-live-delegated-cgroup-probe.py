#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

_BUILD_TIMEOUT_SECONDS = 60
_MANAGER_TEST_TIMEOUT_SECONDS = 60
_ROOT_TEST_TIMEOUT_SECONDS = 120
_EXPECTED_COMMIT_ENV = "SSH_OVER_MCP_LIVE_EXPECTED_COMMIT"
_SOURCE_PID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_SOURCE_PID"
_REQUIRED_ENV = (
    "SSH_OVER_MCP_LIVE_CGROUP_ROOT",
    "SSH_OVER_MCP_LIVE_CGROUP_HOST_SOURCE",
    _SOURCE_PID_ENV,
    "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID",
    "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID",
    "SSH_OVER_MCP_LIVE_CGROUP_HOST_UID",
    "SSH_OVER_MCP_LIVE_CGROUP_HOST_GID",
    "SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_UID",
    "SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_GID",
    "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_CLIENT_GID",
    _EXPECTED_COMMIT_ENV,
)


def _git_output(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={repository}", *args],
        cwd=repository,
        text=True,
        timeout=10,
    ).strip()


def _validate_exact_checkout(repository: Path) -> str:
    expected = os.environ[_EXPECTED_COMMIT_ENV].lower()
    if re.fullmatch(r"[0-9a-f]{40}", expected) is None:
        raise RuntimeError(f"{_EXPECTED_COMMIT_ENV} must be a full 40-hex commit")

    actual = _git_output(repository, "rev-parse", "--verify", "HEAD^{commit}").lower()
    if actual != expected:
        raise RuntimeError(
            f"live checkout commit mismatch: expected {expected}, observed {actual}"
        )

    dirty = _git_output(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if dirty:
        raise RuntimeError("live checkout must contain no modified or untracked files")
    return actual


def _required_id(name: str) -> int:
    raw = os.environ[name]
    if re.fullmatch(r"[0-9]+", raw) is None:
        raise RuntimeError(f"{name} must be a decimal integer")
    value = int(raw, 10)
    if not 0 < value < (1 << 32) - 1:
        raise RuntimeError(f"{name} must be a non-root Linux uid/gid")
    return value


def _required_pid(name: str) -> int:
    raw = os.environ[name]
    if re.fullmatch(r"[0-9]+", raw) is None:
        raise RuntimeError(f"{name} must be a decimal integer")
    value = int(raw, 10)
    if value <= 1:
        raise RuntimeError(f"{name} must be a positive non-init PID")
    return value


def _audit_metadata(commit: str) -> None:
    root = Path(os.environ["SSH_OVER_MCP_LIVE_CGROUP_ROOT"]).resolve(strict=True)
    source = Path(
        os.environ["SSH_OVER_MCP_LIVE_CGROUP_HOST_SOURCE"]
    ).resolve(strict=True)
    controllers = (root / "cgroup.controllers").read_text(
        encoding="ascii"
    ).split()
    metadata = {
        "commit": commit,
        "kernel_release": os.uname().release,
        "machine": os.uname().machine,
        "cgroup_root": str(root),
        "host_source": str(source),
        "source_pid": _required_pid(_SOURCE_PID_ENV),
        "controllers": sorted(controllers),
        "manager_uid": _required_id("SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID"),
        "manager_gid": _required_id("SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID"),
        "host_uid": _required_id("SSH_OVER_MCP_LIVE_CGROUP_HOST_UID"),
        "host_gid": _required_id("SSH_OVER_MCP_LIVE_CGROUP_HOST_GID"),
        "workload_uid": _required_id("SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_UID"),
        "workload_gid": _required_id("SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_GID"),
        "manager_client_gid": _required_id(
            "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_CLIENT_GID"
        ),
    }
    print(
        "live-cgroup-metadata=" + json.dumps(metadata, sort_keys=True),
        flush=True,
    )


def _manager_setpriv_prefix() -> list[str]:
    setpriv = shutil.which("setpriv")
    if setpriv is None:
        raise RuntimeError("setpriv is required for the live manager phase")

    manager_uid = _required_id("SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID")
    manager_gid = _required_id("SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID")
    client_gid = _required_id("SSH_OVER_MCP_LIVE_CGROUP_MANAGER_CLIENT_GID")

    args = [
        setpriv,
        f"--reuid={manager_uid}",
        f"--regid={manager_gid}",
    ]
    if client_gid == manager_gid:
        args.append("--clear-groups")
    else:
        args.append(f"--groups={client_gid}")
    args.extend(
        (
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
        )
    )
    return args


def _run_pytest(
    repository: Path,
    env: dict[str, str],
    *,
    expression: str,
    timeout_seconds: int,
    manager_identity: bool,
) -> None:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/live/test_delegated_cgroup.py",
        "-k",
        expression,
    ]
    if manager_identity:
        command = [*_manager_setpriv_prefix(), *command]

    subprocess.run(
        command,
        cwd=repository,
        env=env,
        check=True,
        timeout=timeout_seconds,
    )


def _retire_operator_source() -> None:
    source = Path(
        os.environ["SSH_OVER_MCP_LIVE_CGROUP_HOST_SOURCE"]
    ).resolve(strict=True)
    source_pid = _required_pid(_SOURCE_PID_ENV)
    members = {
        int(value, 10)
        for value in (source / "cgroup.procs").read_text(encoding="ascii").split()
    }
    if members != {source_pid}:
        raise RuntimeError(
            "operator source cgroup must contain only the configured source PID "
            "before bootstrap cleanup"
        )

    status = Path(f"/proc/{source_pid}/status").read_text(encoding="ascii")
    state_line = next(
        line for line in status.splitlines() if line.startswith("State:")
    )
    if state_line.split()[1] != "T":
        raise RuntimeError("operator source PID must still be stopped before cleanup")

    os.kill(source_pid, signal.SIGKILL)
    deadline = time.monotonic() + 2.0
    while (source / "cgroup.procs").read_text(encoding="ascii").strip():
        if time.monotonic() >= deadline:
            raise RuntimeError("operator source cgroup did not become empty")
        time.sleep(0.01)


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
        commit = _validate_exact_checkout(repository)
        _audit_metadata(commit)

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

        _run_pytest(
            repository,
            env,
            expression=(
                "preflight_live_delegated_cgroup_fixture or "
                "real_cgroup_backend_create_attach_limits_and_cleanup"
            ),
            timeout_seconds=_MANAGER_TEST_TIMEOUT_SECONDS,
            manager_identity=True,
        )

        _retire_operator_source()

        _run_pytest(
            repository,
            env,
            expression=(
                "production_manager_client_barrier_and_migration_denial or "
                "real_pid_and_cpu_enforcement or "
                "real_memory_enforcement_with_request_scope_oom_attribution or "
                "recursive_cgroup_kill_removes_descendants_and_preserves_sibling"
            ),
            timeout_seconds=_ROOT_TEST_TIMEOUT_SECONDS,
            manager_identity=False,
        )
    finally:
        probe.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
