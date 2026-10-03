#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import platform
import pwd
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

LIMA_VERSION = "2.2.0"
INSTANCE_NAME = "ssh-over-mcp-e2e"
EXPECTED_REPOSITORY = "zhangyuz/ssh-over-mcp"
REPOSITORY_URL = "https://github.com/zhangyuz/ssh-over-mcp.git"
ORCHESTRATOR_USER = "gha-e2e-orchestrator"
ORCHESTRATOR_HOME = Path("/Users/gha-e2e-orchestrator")
ORCHESTRATOR_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
IMAGE_DIGEST = (
    "sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477"
)
GUEST_BUNDLE = Path("/tmp/ssh-over-mcp-target.bundle")
GUEST_WORKSPACE = Path("/opt/ssh-over-mcp-e2e/workspace")
GUEST_CONFIG = Path("/etc/ssh-over-mcp/live-e2e-gate.conf")
ROOT = Path(__file__).resolve().parents[1]
LIMA_CONFIG = ROOT / "ops" / "live-e2e" / "lima-ubuntu-26.04.yaml"
HOST_TOKEN_ENV = "SSH_OVER_MCP_E2E_GITHUB_TOKEN"
_COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}\Z")


class OrchestratorError(RuntimeError):
    """Trusted host orchestration cannot proceed safely."""


class _Lifecycle(Protocol):
    def verify_host(self) -> None: ...
    def instance_exists(self) -> bool: ...
    def create_bundle(self, target: str) -> Path: ...
    def start_guest(self) -> None: ...
    def copy_bundle(self, bundle: Path) -> None: ...
    def bootstrap_guest(self, target: str) -> None: ...
    def guest_head(self) -> str: ...
    def run_guest_gate(self) -> int: ...
    def delete_guest(self) -> None: ...
    def verify_guest_absent(self) -> None: ...
    def cleanup_host(self) -> None: ...


def _validated_target_commit(value: str) -> str:
    if _COMMIT_RE.fullmatch(value) is None:
        raise OrchestratorError("target commit must be exact 40-hex")
    return value.lower()


def _validated_workflow_context(env: Mapping[str, str]) -> str:
    if env.get("GITHUB_ACTIONS") != "true":
        raise OrchestratorError("E2E orchestrator requires GitHub Actions")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise OrchestratorError("E2E orchestrator requires workflow_dispatch")
    if env.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise OrchestratorError("unexpected GitHub repository")
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise OrchestratorError("E2E orchestrator requires trusted main")
    workflow_sha = env.get("GITHUB_SHA", "")
    if _COMMIT_RE.fullmatch(workflow_sha) is None:
        raise OrchestratorError("trusted workflow SHA must be exact 40-hex")
    return workflow_sha.lower()


def _guest_command_environment(env: Mapping[str, str]) -> dict[str, str]:
    del env
    return {
        "HOME": str(ORCHESTRATOR_HOME),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": ORCHESTRATOR_PATH,
    }


def _host_git_commands(
    bare: Path,
    bundle: Path,
    target: str,
) -> list[list[str]]:
    return [
        ["git", "init", "--bare", str(bare)],
        [
            "git",
            "-C",
            str(bare),
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            REPOSITORY_URL,
            target,
        ],
        ["git", "-C", str(bare), "update-ref", "refs/e2e/target", "FETCH_HEAD"],
        ["git", "-C", str(bare), "rev-parse", "refs/e2e/target^{commit}"],
        [
            "git",
            "-C",
            str(bare),
            "bundle",
            "create",
            str(bundle),
            "refs/e2e/target",
        ],
    ]


def _lima_start_command(config: Path) -> list[str]:
    return [
        "limactl",
        "start",
        f"--name={INSTANCE_NAME}",
        "--tty=false",
        "--plain",
        "--mount-none",
        "--timeout=10m",
        str(config),
    ]


def _run(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout: int,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )


def _git_environment(
    env: Mapping[str, str],
    *,
    askpass: Path,
) -> dict[str, str]:
    token = env.get(HOST_TOKEN_ENV)
    if not token:
        raise OrchestratorError("host read token is required")
    return {
        "GIT_ASKPASS": str(askpass),
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(ORCHESTRATOR_HOME),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": ORCHESTRATOR_PATH,
        HOST_TOKEN_ENV: token,
    }


def _write_askpass(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  *Username*) printf "%s\\n" "x-access-token" ;;\n'
        '  *Password*) printf "%s\\n" "$SSH_OVER_MCP_E2E_GITHUB_TOKEN" ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _parse_lima_instances(raw: str) -> set[str]:
    names: set[str] = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        document = json.loads(line)
        name = document.get("name")
        if isinstance(name, str):
            names.add(name)
    return names


class _SystemLifecycle:
    def __init__(self, env: Mapping[str, str]) -> None:
        self._host_env = dict(env)
        self._guest_env = _guest_command_environment(env)
        self._temp: tempfile.TemporaryDirectory[str] | None = None

    def verify_host(self) -> None:
        _validated_workflow_context(self._host_env)
        if platform.system() != "Darwin" or platform.machine() != "x86_64":
            raise OrchestratorError("E2E orchestrator requires Intel macOS")
        if os.geteuid() == 0:
            raise OrchestratorError("E2E orchestrator must be non-root")
        try:
            account = pwd.getpwuid(os.geteuid())
        except KeyError as exc:
            raise OrchestratorError("E2E orchestrator account is unavailable") from exc
        if account.pw_name != ORCHESTRATOR_USER:
            raise OrchestratorError("unexpected E2E orchestrator account")
        if Path(account.pw_dir) != ORCHESTRATOR_HOME:
            raise OrchestratorError("unexpected E2E orchestrator home")
        try:
            admin_gid = grp.getgrnam("admin").gr_gid
        except KeyError as exc:
            raise OrchestratorError("macOS admin group is unavailable") from exc
        if admin_gid in os.getgroups():
            raise OrchestratorError("E2E orchestrator account must be non-admin")
        version = _run(
            ["limactl", "--version"],
            env=self._guest_env,
            timeout=10,
        ).stdout.strip()
        if version != f"limactl version {LIMA_VERSION}":
            raise OrchestratorError("unexpected Lima version")
        hv = _run(
            ["sysctl", "-n", "kern.hv_support"],
            env=self._guest_env,
            timeout=10,
        ).stdout.strip()
        if hv != "1":
            raise OrchestratorError("macOS Hypervisor support is unavailable")
        if not LIMA_CONFIG.is_file():
            raise OrchestratorError("trusted Lima config is unavailable")

    def instance_exists(self) -> bool:
        result = _run(
            ["limactl", "list", "--json"],
            env=self._guest_env,
            timeout=20,
        )
        return INSTANCE_NAME in _parse_lima_instances(result.stdout)
    def create_bundle(self, target: str) -> Path:
        self._temp = tempfile.TemporaryDirectory(prefix="ssh-over-mcp-e2e-")
        root = Path(self._temp.name)
        root.chmod(0o700)
        bare = root / "target.git"
        bundle = root / "target.bundle"
        askpass = root / "git-askpass"
        _write_askpass(askpass)
        git_env = _git_environment(self._host_env, askpass=askpass)

        commands = _host_git_commands(bare, bundle, target)
        try:
            _run(commands[0], env=git_env, timeout=30)
            _run(commands[1], env=git_env, timeout=120)
            _run(commands[2], env=git_env, timeout=30)
            observed = _run(
                commands[3],
                env=git_env,
                timeout=30,
            ).stdout.strip().lower()
            if observed != target:
                raise OrchestratorError("bare repository target mismatch")
            _run(commands[4], env=git_env, timeout=60)
            if not bundle.is_file():
                raise OrchestratorError("target bundle was not created")
            return bundle
        finally:
            git_env.pop(HOST_TOKEN_ENV, None)
            self._host_env.pop(HOST_TOKEN_ENV, None)

    def start_guest(self) -> None:
        _run(
            _lima_start_command(LIMA_CONFIG),
            env=self._guest_env,
            timeout=660,
        )

    def copy_bundle(self, bundle: Path) -> None:
        _run(
            [
                "limactl",
                "copy",
                str(bundle),
                f"{INSTANCE_NAME}:{GUEST_BUNDLE}",
            ],
            env=self._guest_env,
            timeout=120,
        )

    def _guest(
        self,
        *command: str,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        return _run(
            ["limactl", "shell", INSTANCE_NAME, "--", *command],
            env=self._guest_env,
            timeout=timeout,
        )

    def bootstrap_guest(self, target: str) -> None:
        script = (
            "set -eu; "
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update >/dev/null; "
            "apt-get install -y git openssh-server sudo python3 python3-venv "
            "python3-pip gcc >/dev/null; "
            f"rm -rf {GUEST_WORKSPACE}; "
            f"mkdir -p {GUEST_WORKSPACE.parent} /etc/ssh-over-mcp; "
            f"git clone {GUEST_BUNDLE} {GUEST_WORKSPACE} >/dev/null; "
            f"git -C {GUEST_WORKSPACE} checkout --detach {target} >/dev/null; "
            f"printf 'EXPECTED_COMMIT={target}\\n' > {GUEST_CONFIG}; "
            f"chmod 0600 {GUEST_CONFIG}"
        )
        self._guest("sudo", "/bin/sh", "-c", script, timeout=600)

    def guest_head(self) -> str:
        return self._guest(
            "git",
            "-C",
            str(GUEST_WORKSPACE),
            "rev-parse",
            "HEAD",
            timeout=30,
        ).stdout.strip().lower()

    def run_guest_gate(self) -> int:
        gate = GUEST_WORKSPACE / "ops" / "live-e2e" / "ssh-over-mcp-live-e2e-gate"
        result = self._guest(
            "sudo",
            "/usr/bin/python3",
            str(gate),
            timeout=900,
        )
        return result.returncode

    def delete_guest(self) -> None:
        _run(
            ["limactl", "delete", "--force", INSTANCE_NAME],
            env=self._guest_env,
            timeout=180,
        )

    def verify_guest_absent(self) -> None:
        if self.instance_exists():
            raise OrchestratorError("disposable E2E guest still exists after deletion")

    def cleanup_host(self) -> None:
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None


def _orchestrate(target: str, ops: _Lifecycle) -> int:
    creation_attempted = False
    created_guest = False
    try:
        ops.verify_host()
        if ops.instance_exists():
            raise OrchestratorError(
                f"fixed E2E guest {INSTANCE_NAME!r} already exists; "
                "operator inspection required"
            )
        bundle = ops.create_bundle(target)
        creation_attempted = True
        ops.start_guest()
        created_guest = True
        ops.copy_bundle(bundle)
        ops.bootstrap_guest(target)
        if ops.guest_head() != target:
            raise OrchestratorError("guest checkout target mismatch")
        return ops.run_guest_gate()
    finally:
        try:
            should_delete = created_guest
            if creation_attempted and not created_guest:
                should_delete = ops.instance_exists()
            if should_delete:
                ops.delete_guest()
                ops.verify_guest_absent()
        finally:
            ops.cleanup_host()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        raise OrchestratorError(
            "usage: run-live-local-e2e-orchestrator.py <40-hex>"
        )
    target = _validated_target_commit(arguments[0])
    host_env = dict(os.environ)
    os.environ.pop(HOST_TOKEN_ENV, None)
    return _orchestrate(target, _SystemLifecycle(host_env))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OrchestratorError, subprocess.SubprocessError, OSError, ValueError) as exc:
        print(f"live local E2E orchestrator failed: {exc}", file=sys.stderr)
        raise SystemExit(70) from None
