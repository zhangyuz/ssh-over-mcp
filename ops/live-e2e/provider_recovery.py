from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

_PUBLIC_ERROR = "live E2E recovery validation failed"
ORCHESTRATOR_HOME = Path("/Users/gha-e2e-orchestrator")
PROVIDER_STATE = ORCHESTRATOR_HOME / "Library/Caches/ssh-over-mcp-e2e/active-run.json"
MAX_MARKER_BYTES = 4096
QEMU_NAME = "qemu-system-x86_64"
_TARGET_RE = re.compile(r"^[0-9a-f]{40}$")


class RecoveryError(RuntimeError):
    """Raised when stale-provider recovery cannot be proven safe."""


@dataclass(frozen=True, slots=True)
class StaleProviderState:
    target: str
    owner_pid: int
    device: int
    inode: int


def _fail() -> RecoveryError:
    return RecoveryError(_PUBLIC_ERROR)


def _read_bounded(fd: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(1024, MAX_MARKER_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_MARKER_BYTES:
            raise _fail()
    return b"".join(chunks)


def _validate_marker_stat(info: os.stat_result, *, expected_uid: int) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise _fail()
    if info.st_uid != expected_uid:
        raise _fail()
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise _fail()
    if info.st_nlink != 1:
        raise _fail()
    if info.st_size <= 0 or info.st_size > MAX_MARKER_BYTES:
        raise _fail()


def load_stale_state(path: Path = PROVIDER_STATE, *, expected_uid: int) -> StaleProviderState:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        raise _fail() from None
    try:
        info = os.fstat(fd)
        _validate_marker_stat(info, expected_uid=expected_uid)
        raw = _read_bounded(fd)
    except OSError:
        raise _fail() from None
    finally:
        os.close(fd)

    try:
        payload = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise _fail() from None
    if not isinstance(payload, dict) or set(payload) != {"target", "owner_pid"}:
        raise _fail()
    target = payload["target"]
    owner_pid = payload["owner_pid"]
    if not isinstance(target, str) or _TARGET_RE.fullmatch(target) is None:
        raise _fail()
    if type(owner_pid) is not int or owner_pid <= 0:
        raise _fail()
    return StaleProviderState(
        target=target,
        owner_pid=owner_pid,
        device=info.st_dev,
        inode=info.st_ino,
    )


def _read_process_inventory(*, uid: int) -> str:
    try:
        result = subprocess.run(
            ["/bin/ps", "-ww", "-U", str(uid), "-o", "pid=,comm="],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        raise _fail() from None
    return result.stdout


def validate_process_inventory(raw: str, *, owner_pid: int) -> int:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        raise _fail()
    qemu_count = 0
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise _fail()
        pid_raw, command = parts
        try:
            pid = int(pid_raw, 10)
        except ValueError:
            raise _fail() from None
        if pid <= 0 or not command:
            raise _fail()
        if pid == owner_pid:
            raise _fail()
        if Path(command).name == QEMU_NAME:
            qemu_count += 1
    if qemu_count:
        raise _fail()
    return qemu_count


def inspect_stale_state(path: Path = PROVIDER_STATE) -> StaleProviderState | None:
    try:
        exists = path.exists() or path.is_symlink()
    except OSError:
        raise _fail() from None
    if not exists:
        return None
    uid = os.getuid()
    state = load_stale_state(path, expected_uid=uid)
    inventory = _read_process_inventory(uid=uid)
    validate_process_inventory(inventory, owner_pid=state.owner_pid)
    return state


def clear_stale_state(
    path: Path,
    state: StaleProviderState,
    *,
    expected_target: str,
    expected_owner_pid: int,
) -> None:
    if expected_target != state.target or expected_owner_pid != state.owner_pid:
        raise _fail()
    try:
        before_inventory = os.lstat(path)
    except OSError:
        raise _fail() from None
    _validate_marker_stat(before_inventory, expected_uid=os.getuid())
    if before_inventory.st_dev != state.device or before_inventory.st_ino != state.inode:
        raise _fail()

    inventory = _read_process_inventory(uid=os.getuid())
    validate_process_inventory(inventory, owner_pid=state.owner_pid)

    try:
        before_unlink = os.lstat(path)
    except OSError:
        raise _fail() from None
    _validate_marker_stat(before_unlink, expected_uid=os.getuid())
    if (
        before_unlink.st_dev != state.device
        or before_unlink.st_ino != state.inode
        or before_unlink.st_dev != before_inventory.st_dev
        or before_unlink.st_ino != before_inventory.st_ino
    ):
        raise _fail()
    try:
        path.unlink()
    except OSError:
        raise _fail() from None
    if path.exists() or path.is_symlink():
        raise _fail()


def _validated_cli_context() -> None:
    if os.geteuid() == 0:
        raise _fail()
    if Path.home() != ORCHESTRATOR_HOME:
        raise _fail()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise _fail()
    if os.environ.get("GITHUB_REPOSITORY") != "zhangyuz/ssh-over-mcp":
        raise _fail()
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise _fail()
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise _fail()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect or clear stale Live Local E2E provider state"
    )
    parser.add_argument("action", choices=("inspect", "clear"))
    parser.add_argument("--expected-target", default="")
    parser.add_argument("--expected-owner-pid", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _validated_cli_context()
    state = inspect_stale_state(PROVIDER_STATE)
    if state is None:
        print("live E2E provider marker is absent")
        return 0
    print(f"stale provider marker target={state.target} owner_pid={state.owner_pid}; qemu_count=0")
    if args.action == "inspect":
        return 0
    try:
        expected_owner_pid = int(args.expected_owner_pid, 10)
    except ValueError:
        raise _fail() from None
    clear_stale_state(
        PROVIDER_STATE,
        state,
        expected_target=args.expected_target,
        expected_owner_pid=expected_owner_pid,
    )
    print("confirmed stale provider marker cleared")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(f"live E2E provider recovery failed: {exc}", file=sys.stderr)
        raise SystemExit(70) from None
