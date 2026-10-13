from __future__ import annotations

import grp
import json
import os
import platform
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

EXPECTED_REPOSITORY = "zhangyuz/ssh-over-mcp"
ORCHESTRATOR_USER = "gha-e2e-orchestrator"
ORCHESTRATOR_HOME = Path("/Users/gha-e2e-orchestrator")
PROVIDER_STATE = ORCHESTRATOR_HOME / "Library/Caches/ssh-over-mcp-e2e/active-run.json"
TEMP_PREFIX = "ssh-over-mcp-e2e-"
MAX_STATE_BYTES = 4_096
MAX_TEMP_DIRS = 16
MAX_TEMP_MATCHES = 64
MAX_TEMP_CHILDREN = 32
QEMU_NAME = "qemu-system-x86_64"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class RecoveryError(RuntimeError):
    """Raised when provider-state recovery cannot be proven safe."""


@dataclass(frozen=True, slots=True)
class ProviderState:
    target: str
    owner_pid: int


@dataclass(frozen=True, slots=True)
class StateIdentity:
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class RecoveryInspection:
    state: ProviderState
    identity: StateIdentity
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
    if _HEX40.fullmatch(value) is None:
        raise RecoveryError("expected target must be canonical lowercase 40-hex")
    return value


def _parse_expected_pid(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise RecoveryError("expected owner PID must be decimal")
    pid = int(value, 10)
    if str(pid) != value:
        raise RecoveryError("expected owner PID must be canonical decimal")
    return pid


def _load_state(path: Path, uid: int) -> tuple[ProviderState, StateIdentity]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise RecoveryError("provider state is absent") from None
    except OSError:
        raise RecoveryError("provider state cannot be inspected safely") from None
    if not stat.S_ISREG(before.st_mode) or before.st_uid != uid:
        raise RecoveryError("provider state ownership/type mismatch")
    if stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > MAX_STATE_BYTES:
        raise RecoveryError("provider state mode/size mismatch")
    # A regular marker can be replaced by a FIFO before open; never await a writer.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise RecoveryError("provider state is absent") from None
    except OSError as exc:
        raise RecoveryError("provider state cannot be opened safely") from exc

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
            raise RecoveryError("provider state ownership/type mismatch")
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_STATE_BYTES:
            raise RecoveryError("provider state mode/size mismatch")
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise RecoveryError("provider state identity changed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)

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
    return (
        ProviderState(target=target, owner_pid=owner_pid),
        StateIdentity(device=info.st_dev, inode=info.st_ino),
    )


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _qemu_pids(uid: int) -> tuple[int, ...]:
    try:
        completed = subprocess.run(
            ["/bin/ps", "-ww", "-U", str(uid), "-o", "pid=,comm="],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RecoveryError("provider process inventory is unavailable") from exc
    result: list[int] = []
    saw_process = False
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        saw_process = True
        fields = line.strip().split(None, 1)
        if len(fields) != 2:
            raise RecoveryError("provider process inventory is malformed")
        pid_raw, command = fields
        try:
            pid = int(pid_raw, 10)
        except ValueError:
            raise RecoveryError("provider process inventory is malformed") from None
        if pid <= 0:
            raise RecoveryError("provider process inventory is malformed")
        if Path(command).name == QEMU_NAME:
            result.append(pid)
    if not saw_process:
        raise RecoveryError("provider process inventory is unavailable")
    return tuple(result)


def _temp_dirs(root: Path, uid: int) -> tuple[Path, ...]:
    candidates: list[Path] = []
    match_count = 0
    for path in root.glob(f"{TEMP_PREFIX}*"):
        match_count += 1
        if match_count > MAX_TEMP_MATCHES:
            raise RecoveryError("too many matching E2E temp paths")
        info = path.lstat()
        if info.st_uid != uid:
            continue
        if not stat.S_ISDIR(info.st_mode):
            if stat.S_ISREG(info.st_mode):
                kind = "regular"
            elif stat.S_ISLNK(info.st_mode):
                kind = "symlink"
            else:
                kind = "special"
            mode = stat.S_IMODE(info.st_mode)
            raise RecoveryError(
                "unexpected E2E temp path ownership/type "
                f"name={path.name!r} kind={kind} uid={info.st_uid} mode={mode:04o}"
            )
        candidates.append(path)
        if len(candidates) > MAX_TEMP_DIRS:
            raise RecoveryError("too many E2E temp directories")
    return tuple(sorted(candidates))


def _read_expected_commit(directory_fd: int, uid: int) -> str | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        payload_fd = os.open("payload-content", flags | os.O_DIRECTORY, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        raise RecoveryError("E2E expected commit directory cannot be opened safely") from None
    try:
        payload_info = os.fstat(payload_fd)
        if not stat.S_ISDIR(payload_info.st_mode) or payload_info.st_uid != uid:
            raise RecoveryError("E2E expected commit directory ownership/type mismatch")
        try:
            before = os.stat("expected_commit", dir_fd=payload_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            raise RecoveryError("E2E expected commit cannot be inspected safely") from None
        if stat.S_ISLNK(before.st_mode):
            raise RecoveryError("E2E expected commit cannot be opened safely")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_size != 41
        ):
            raise RecoveryError("E2E expected commit ownership/type/size mismatch")
        try:
            # Reject a FIFO at fstat without waiting for an untrusted writer.
            expected_fd = os.open("expected_commit", flags | os.O_NONBLOCK, dir_fd=payload_fd)
        except FileNotFoundError:
            return None
        except OSError:
            raise RecoveryError("E2E expected commit cannot be opened safely") from None
        try:
            expected_info = os.fstat(expected_fd)
            if (
                not stat.S_ISREG(expected_info.st_mode)
                or expected_info.st_uid != uid
                or expected_info.st_size != 41
            ):
                raise RecoveryError("E2E expected commit ownership/type/size mismatch")
            if (expected_info.st_dev, expected_info.st_ino) != (before.st_dev, before.st_ino):
                raise RecoveryError("E2E expected commit identity changed")
            raw = os.read(expected_fd, 42)
        finally:
            os.close(expected_fd)
    finally:
        os.close(payload_fd)

    if len(raw) != 41 or raw[-1:] != b"\n":
        raise RecoveryError("E2E expected commit payload is malformed")
    try:
        value = raw[:-1].decode("ascii")
    except UnicodeError:
        raise RecoveryError("E2E expected commit payload is malformed") from None
    if _HEX40.fullmatch(value) is None:
        raise RecoveryError("E2E expected commit payload is malformed")
    return value


def _temp_diagnostics(paths: Sequence[Path], uid: int) -> tuple[str, ...]:
    records: list[str] = []
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise RecoveryError("safe temp directory inspection is unavailable")
    for path in paths:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise RecoveryError("E2E temp directory cannot be opened safely") from None
        try:
            root_info = os.fstat(descriptor)
            if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != uid:
                raise RecoveryError("E2E temp directory identity changed")
            entries: list[dict[str, object]] = []
            try:
                with os.scandir(descriptor) as stream:
                    for entry in stream:
                        if len(entries) >= MAX_TEMP_CHILDREN:
                            raise RecoveryError("too many direct entries in E2E temp directory")
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            kind = "directory"
                        elif stat.S_ISREG(info.st_mode):
                            kind = "regular"
                        elif stat.S_ISLNK(info.st_mode):
                            kind = "symlink"
                        else:
                            kind = "special"
                        entries.append(
                            {
                                "kind": kind,
                                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                                "name": entry.name,
                                "size": info.st_size if kind == "regular" else None,
                                "uid": info.st_uid,
                            }
                        )
            except OSError:
                raise RecoveryError("E2E temp directory inventory is unavailable") from None
            entries.sort(key=lambda item: str(item["name"]))
            records.append(
                json.dumps(
                    {
                        "device": root_info.st_dev,
                        "entries": entries,
                        "expected_commit": _read_expected_commit(descriptor, uid),
                        "inode": root_info.st_ino,
                        "mode": f"{stat.S_IMODE(root_info.st_mode):04o}",
                        "name": path.name,
                        "uid": root_info.st_uid,
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        finally:
            os.close(descriptor)
    return tuple(records)


def inspect_recovery(
    expected_target: str,
    *,
    state_path: Path = PROVIDER_STATE,
    temp_root: Path | None = None,
    uid: int | None = None,
) -> RecoveryInspection:
    trusted_target = _parse_expected_target(expected_target)
    effective_uid = os.geteuid() if uid is None else uid
    state, identity = _load_state(state_path, effective_uid)
    if state.target != trusted_target:
        raise RecoveryError("stale provider target does not match operator input")
    root = Path(tempfile.gettempdir()) if temp_root is None else temp_root
    return RecoveryInspection(
        state=state,
        identity=identity,
        temp_dirs=_temp_dirs(root, effective_uid),
    )


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
    if inspection.temp_dirs:
        raise RecoveryError("orphan E2E temp state remains; marker recovery refused")

    effective_uid = os.geteuid() if uid is None else uid
    if _process_exists(expected_owner_pid):
        raise RecoveryError("stale provider owner process is still alive")
    if _qemu_pids(effective_uid):
        raise RecoveryError("QEMU process is still alive")

    current = inspect_recovery(
        expected_target,
        state_path=state_path,
        temp_root=temp_root,
        uid=effective_uid,
    )
    if current != inspection:
        raise RecoveryError("provider state changed during recovery")
    if _process_exists(expected_owner_pid) or _qemu_pids(effective_uid):
        raise RecoveryError("provider process state changed during recovery")

    state_path.unlink()
    if state_path.exists() or state_path.is_symlink():
        raise RecoveryError("provider state cleanup did not complete")
    return inspection


def _inspect_temp_parent_relation() -> str:
    """Inspect-only, non-authorizing root comparison; log a fixed label only.

    The recovery caller has already selected/cached its tempfile root before
    this runs. OS getconf is fixed, and neither pathname nor child payload is
    emitted. No result authorizes recovering the marker or temp contents.
    """
    try:
        result = subprocess.run(
            ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"),
            check=True, capture_output=True, timeout=5,
            env={"LC_ALL": "C"},
        )
        if (
            not isinstance(result.stdout, bytes)
            or re.fullmatch(rb"/var/folders/[a-z0-9]{2}/[a-z0-9_]+/T/\n", result.stdout)
            is None
        ):
            return "unavailable"
        native = result.stdout[:-1].decode("ascii")
        python_root = tempfile.gettempdir()
        if type(python_root) is not str:
            return "unavailable"
        return "same" if os.path.realpath(native) == os.path.realpath(python_root) else "different"
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, TypeError, OverflowError):
        return "unavailable"


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        raise RecoveryError("usage: recover_provider.py <expected-target> <expected-owner-pid>")
    _validate_context(os.environ)
    target = _parse_expected_target(args[0])
    expected_pid = _parse_expected_pid(args[1])
    inspection = inspect_recovery(target)
    names = ",".join(path.name for path in inspection.temp_dirs) or "<none>"
    print(
        "RECOVERY_INSPECT "
        f"target={inspection.state.target} owner_pid={inspection.state.owner_pid} "
        f"temp_dirs={len(inspection.temp_dirs)} names={names}"
    )
    for record in _temp_diagnostics(inspection.temp_dirs, os.geteuid()):
        print(f"RECOVERY_TEMP {record}")
    if expected_pid == 0:
        print(f"RECOVERY_TEMP_PARENT_RELATION={_inspect_temp_parent_relation()}")
        print("RECOVERY_MODE=inspect-only")
        return 0
    recovered = recover(target, expected_pid)
    print(
        "RECOVERY_APPLIED "
        f"target={recovered.state.target} owner_pid={recovered.state.owner_pid}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(f"live local E2E provider recovery failed: {exc}", file=sys.stderr)
        raise SystemExit(70) from None
