from __future__ import annotations

import grp
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

EXPECTED_REPOSITORY = "zhangyuz/ssh-over-mcp"
ORCHESTRATOR_USER = "gha-e2e-orchestrator"
ORCHESTRATOR_HOME = Path("/Users/gha-e2e-orchestrator")
CACHE_DIR = ORCHESTRATOR_HOME / "Library" / "Caches" / "ssh-over-mcp-e2e"
PROVIDER_STATE = CACHE_DIR / "active-run.json"
TEMP_PREFIX = "ssh-over-mcp-e2e-"
MAX_STATE_BYTES = 4_096
QEMU_NAME = "qemu-system-x86_64"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class RecoveryError(RuntimeError):
    """Raised when provider-state recovery cannot be proven safe."""


@dataclass(frozen=True, slots=True)
class ProviderState:
    target: str
    owner_pid: int


@dataclass(frozen=True, slots=True)
class RecoveryInspection:
    state: ProviderState
    temp_dirs: tuple[Path, ...]


def _validate_context(env: Mapping[str, str]) -> None:
    if env.get("GITHUB_ACTIONS") != "true":
        raise RecoveryError("recovery requires GitHub Actions")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise RecoveryError("recovery requires workflow_dispatch")
    if env.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise RecoveryError("unexpected GitHub repository")
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise RecoveryError("recovery requires trusted main")
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        raise RecoveryError("recovery requires Intel macOS")
    if os.geteuid() == 0:
        raise RecoveryError("recovery must not run as root")
    account = pwd.getpwuid(os.geteuid())
    if account.pw_name != ORCHESTRATOR_USER or Path(account.pw_dir) != ORCHESTRATOR_HOME:
        raise RecoveryError("unexpected recovery account")
    admin_gid = grp.getgrnam("admin").gr_gid
    if admin_gid in os.getgroups():
        raise RecoveryError("recovery account must be non-admin")


def _parse_expected_target(value: str) -> str:
    normalized = value.lower()
    if _HEX40.fullmatch(normalized) is None:
        raise RecoveryError("expected target must be exact 40-hex")
    return normalized


def _parse_expected_pid(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise RecoveryError("expected owner PID must be decimal")
    pid = int(value, 10)
    if pid < 0 or str(pid) != value:
        raise RecoveryError("expected owner PID must be canonical decimal")
    return pid


def _load_state(path: Path, uid: int) -> ProviderState:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise RecoveryError("provider state is absent") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
        raise RecoveryError("provider state ownership/type mismatch")
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_STATE_BYTES:
        raise RecoveryError("provider state mode/size mismatch")
    raw = path.read_bytes()
    if len(raw) > MAX_STATE_BYTES:
        raise RecoveryError("provider state exceeds size bound")
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise RecoveryError("provider state is malformed") from None
    if not isinstance(payload, dict) or set(payload) != {"target", "owner_pid"}:
        raise RecoveryError("provider state schema mismatch")
    target = payload["target"]
    owner_pid = payload["owner_pid"]
    if not isinstance(target, str) or _HEX40.fullmatch(target) is None:
        raise RecoveryError("provider state target mismatch")
    if type(owner_pid) is not int or owner_pid <= 1:
        raise RecoveryError("provider state owner PID mismatch")
    return ProviderState(target=target, owner_pid=owner_pid)


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _qemu_pids(uid: int) -> tuple[int, ...]:
    completed = subprocess.run(
        ["/bin/ps", "-ww", "-U", str(uid), "-o", "pid=,comm="],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result: list[int] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2:
            continue
        pid_raw, command = fields
        if Path(command).name == QEMU_NAME:
            result.append(int(pid_raw, 10))
    return tuple(result)


def _temp_dirs(root: Path, uid: int) -> tuple[Path, ...]:
    candidates: list[Path] = []
    for path in root.glob(f"{TEMP_PREFIX}*"):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
            raise RecoveryError("unexpected E2E temp path ownership/type")
        candidates.append(path)
    return tuple(sorted(candidates))


def _verify_tree_owned(root: Path, uid: int) -> None:
    for directory, names, files in os.walk(root, topdown=False, followlinks=False):
        base = Path(directory)
        for name in (*names, *files):
            path = base / name
            info = path.lstat()
            if info.st_uid != uid:
                raise RecoveryError("E2E temp tree contains foreign ownership")
        if base.lstat().st_uid != uid:
            raise RecoveryError("E2E temp directory ownership changed")


def inspect_recovery(
    expected_target: str,
    *,
    state_path: Path = PROVIDER_STATE,
    temp_root: Path | None = None,
    uid: int | None = None,
) -> RecoveryInspection:
    trusted_target = _parse_expected_target(expected_target)
    effective_uid = os.geteuid() if uid is None else uid
    state = _load_state(state_path, effective_uid)
    if state.target != trusted_target:
        raise RecoveryError("stale provider target does not match operator input")
    root = Path(tempfile.gettempdir()) if temp_root is None else temp_root
    return RecoveryInspection(state=state, temp_dirs=_temp_dirs(root, effective_uid))


def recover(
    expected_target: str,
    expected_owner_pid: int,
    *,
    state_path: Path = PROVIDER_STATE,
    temp_root: Path | None = None,
    uid: int | None = None,
) -> RecoveryInspection:
    inspection = inspect_recovery(
        expected_target,
        state_path=state_path,
        temp_root=temp_root,
        uid=uid,
    )
    if expected_owner_pid <= 1 or inspection.state.owner_pid != expected_owner_pid:
        raise RecoveryError("stale provider owner PID does not match operator input")
    effective_uid = os.geteuid() if uid is None else uid
    if _process_exists(expected_owner_pid):
        raise RecoveryError("stale provider owner process is still alive")
    if _qemu_pids(effective_uid):
        raise RecoveryError("QEMU process is still alive")

    for path in inspection.temp_dirs:
        _verify_tree_owned(path, effective_uid)
    for path in inspection.temp_dirs:
        shutil.rmtree(path)
    state_path.unlink()

    if state_path.exists() or state_path.is_symlink():
        raise RecoveryError("provider state cleanup did not complete")
    root = Path(tempfile.gettempdir()) if temp_root is None else temp_root
    if _temp_dirs(root, effective_uid):
        raise RecoveryError("E2E temp cleanup did not complete")
    return inspection


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        raise RecoveryError("usage: recover_provider.py <expected-target> <expected-owner-pid>")
    _validate_context(os.environ)
    target = _parse_expected_target(args[0])
    expected_pid = _parse_expected_pid(args[1])
    inspection = inspect_recovery(target)
    print(
        "RECOVERY_INSPECT "
        f"target={inspection.state.target} owner_pid={inspection.state.owner_pid} "
        f"temp_dirs={len(inspection.temp_dirs)}"
    )
    if expected_pid == 0:
        print("RECOVERY_MODE=inspect-only")
        return 0
    recovered = recover(target, expected_pid)
    print(
        "RECOVERY_APPLIED "
        f"target={recovered.state.target} owner_pid={recovered.state.owner_pid} "
        f"temp_dirs={len(recovered.temp_dirs)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(f"live local E2E provider recovery failed: {exc}", file=sys.stderr)
        raise SystemExit(70) from None
