#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import json
import os
import platform
import pwd
import re
import selectors
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

QEMU_VERSION = "11.1.2"
QEMU_SYSTEM = Path("/usr/local/bin/qemu-system-x86_64")
QEMU_IMG = Path("/usr/local/bin/qemu-img")
HDIUTIL = Path("/usr/bin/hdiutil")

EXPECTED_REPOSITORY = "zhangyuz/ssh-over-mcp"
REPOSITORY_URL = "https://github.com/zhangyuz/ssh-over-mcp.git"
ORCHESTRATOR_USER = "gha-e2e-orchestrator"
ORCHESTRATOR_HOME = Path("/Users/gha-e2e-orchestrator")
ORCHESTRATOR_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/resolute/release-20260720/"
    "ubuntu-26.04-server-cloudimg-amd64.img"
)
IMAGE_DIGEST = (
    "sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477"
)
PYTHON_VERSION = "3.14"
PYTHON_ABI = "cp314"
GUEST_DISK_GIB = 8
HOST_MIN_FREE_BYTES = 16 * 1024**3
TARGET_BUNDLE_MAX_BYTES = 256 * 1024**2
RESULT_PREFIX = "SSH_OVER_MCP_E2E_RESULT="
SERIAL_MAX_BYTES = 2 * 1024 * 1024
TRUSTED_HARNESS_FILES = (
    "ops/live-e2e/ssh-over-mcp-live-e2e-gate",
    "ops/live-e2e/ledger_guest_preflight.py",
)

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_CONFIG = ROOT / "ops" / "live-e2e" / "qemu-ubuntu-26.04.json"
TRUSTED_RUNTIME_LOCK = ROOT / "requirements" / "runtime.lock"
BOOTSTRAP_LOCK = ROOT / "requirements" / "e2e-bootstrap.lock"
CACHE_DIR = ORCHESTRATOR_HOME / "Library" / "Caches" / "ssh-over-mcp-e2e"
BASE_IMAGE = CACHE_DIR / "ubuntu-26.04-server-cloudimg-amd64.img"
PROVIDER_STATE = CACHE_DIR / "active-run.json"

HOST_TOKEN_ENV = "SSH_OVER_MCP_E2E_GITHUB_TOKEN"
_COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}\Z")
_RESULT_RE = re.compile(
    r"^SSH_OVER_MCP_E2E_RESULT=([0-9a-f]{40}):(PASS|FAIL)(?::([0-9]+))?$"
)
_SSHD_STAGE_RE = re.compile(
    r"^local E2E sshd stage: "
    r"(NO_SSH_ACTIVITY|TCP_CONNECTED|AUTH_REJECTED|AUTH_ACCEPTED|FORCECOMMAND_STARTED)$"
)


class OrchestratorError(RuntimeError):
    """Trusted host orchestration cannot proceed safely."""


class _Lifecycle(Protocol):
    def verify_host(self) -> None: ...

    def provider_state_exists(self) -> bool: ...

    def create_bundle(self, target: str) -> Path: ...

    def prepare_guest(self, target: str, bundle: Path) -> None: ...

    def start_guest(self) -> None: ...

    def wait_guest(self) -> int: ...

    def verify_result(self, target: str) -> None: ...

    def cleanup_guest(self) -> None: ...

    def cleanup_host(self) -> None: ...


def _validated_target_commit(value: str) -> str:
    if _COMMIT_RE.fullmatch(value) is None:
        raise OrchestratorError("target commit must be exact 40-hex")
    return value.lower()


def _validated_workflow_context(env: Mapping[str, str]) -> str:
    if env.get("GITHUB_ACTIONS") != "true":
        raise OrchestratorError("E2E orchestrator requires GitHub Actions")
    if env.get("GITHUB_EVENT_NAME") not in {"workflow_dispatch", "workflow_run"}:
        raise OrchestratorError("unexpected E2E workflow trigger")
    if env.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise OrchestratorError("unexpected GitHub repository")
    if env.get("SSH_OVER_MCP_E2E_SOURCE_REPOSITORY") != EXPECTED_REPOSITORY:
        raise OrchestratorError("unexpected E2E source repository")
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise OrchestratorError("E2E orchestrator requires trusted main")
    workflow_sha = env.get("GITHUB_SHA", "")
    if _COMMIT_RE.fullmatch(workflow_sha) is None:
        raise OrchestratorError("trusted workflow SHA must be exact 40-hex")
    return workflow_sha.lower()


def _provider_environment(env: Mapping[str, str]) -> dict[str, str]:
    del env
    return {
        "HOME": str(ORCHESTRATOR_HOME),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": ORCHESTRATOR_PATH,
    }


def _target_fetch_commands(bare: Path, target: str) -> list[list[str]]:
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
    ]


def _host_git_commands(
    bare: Path,
    bundle: Path,
    target: str,
) -> list[list[str]]:
    return [
        *_target_fetch_commands(bare, target),
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


def _fetch_target_into_bare(
    bare: Path,
    target: str,
    env: Mapping[str, str],
) -> None:
    commands = _target_fetch_commands(bare, target)
    for attempt in range(2):
        if bare.exists():
            shutil.rmtree(bare)
        _run(commands[0], env=env, timeout=30)
        try:
            _run(commands[1], env=env, timeout=120)
            return
        except subprocess.TimeoutExpired as exc:
            if attempt == 0:
                continue
            raise OrchestratorError("target fetch timed out after retry") from exc
    raise AssertionError("unreachable")


def _wheel_download_command(lock: Path, wheelhouse: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "--platform",
        "manylinux_2_17_x86_64",
        "--platform",
        "manylinux2014_x86_64",
        "--implementation",
        "cp",
        "--python-version",
        PYTHON_VERSION,
        "--abi",
        PYTHON_ABI,
        "-r",
        str(lock),
        "-d",
        str(wheelhouse),
    ]


def _bootstrap_wheel_download_command(lock: Path, wheelhouse: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "-r",
        str(lock),
        "-d",
        str(wheelhouse),
    ]


def _overlay_command(base: Path, overlay: Path) -> list[str]:
    return [
        str(QEMU_IMG),
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        str(base),
        str(overlay),
        f"{GUEST_DISK_GIB}G",
    ]


def _iso_command(source: Path, output: Path, label: str) -> list[str]:
    return [
        str(HDIUTIL),
        "makehybrid",
        "-o",
        str(output),
        str(source),
        "-iso",
        "-joliet",
        "-iso-volume-name",
        label,
        "-joliet-volume-name",
        label,
    ]


def _qemu_command(
    overlay: Path,
    seed: Path,
    payload: Path,
) -> list[str]:
    return [
        str(QEMU_SYSTEM),
        "-machine",
        "q35",
        "-accel",
        "hvf",
        "-cpu",
        "host",
        "-smp",
        "4",
        "-m",
        "6144",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-nic",
        "none",
        "-no-reboot",
        "-drive",
        f"file={overlay},if=virtio,format=qcow2,cache=none",
        "-drive",
        f"file={seed},format=raw,media=cdrom,readonly=on",
        "-drive",
        f"file={payload},format=raw,media=cdrom,readonly=on",
    ]


def _bootstrap_script(target: str, payload_archive_digest: str) -> str:
    target = _validated_target_commit(target)
    if re.fullmatch(r"[0-9a-f]{64}", payload_archive_digest) is None:
        raise OrchestratorError("payload archive digest must be exact lowercase sha256")
    return f"""#!/bin/bash
set -u
EXPECTED_COMMIT='{target}'
PAYLOAD='/mnt/som-payload'
ARCHIVE="$PAYLOAD/payload.tar"
ARCHIVE_SHA='{payload_archive_digest}'
EXTRACTED="/opt/ssh-over-mcp-e2e/payload"
TRUSTED_HARNESS="/mnt/som-trusted-harness"
WORKSPACE='/opt/ssh-over-mcp-e2e/workspace'
VENV='/opt/ssh-over-mcp-e2e/venv'
PIP_WHEEL="$EXTRACTED/bootstrap-wheels/pip-26.2.1-py3-none-any.whl"
RESULT='/dev/ttyS0'

emit_result() {{
  status="$1"
  code="$2"
  if [ "$status" = PASS ]; then
    printf 'SSH_OVER_MCP_E2E_RESULT=%s:PASS\\n' "$EXPECTED_COMMIT" > "$RESULT"
  else
    printf 'SSH_OVER_MCP_E2E_RESULT=%s:FAIL:%s\\n' "$EXPECTED_COMMIT" "$code" > "$RESULT"
  fi
  sync
}}

finish() {{
  rc="$1"
  trap - EXIT
  if [ "$rc" -eq 0 ]; then
    emit_result PASS 0
  else
    emit_result FAIL "$rc"
  fi
  /sbin/poweroff -f || true
  exit "$rc"
}}

trap 'finish $?' EXIT
set -e

mountpoint -q "$PAYLOAD"
test -f "$ARCHIVE"
rm -rf "$VENV" "$WORKSPACE" "$EXTRACTED"
mkdir -p "$EXTRACTED"

python3 - "$ARCHIVE" "$ARCHIVE_SHA" "$EXTRACTED" <<'PYARCHIVE'
import hashlib
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive = Path(sys.argv[1])
expected = sys.argv[2]
root = Path(sys.argv[3])
digest = hashlib.sha256()
with archive.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != expected:
    raise SystemExit("payload archive digest mismatch")
with tarfile.open(archive, mode="r:") as stream:
    members = stream.getmembers()
    for member in members:
        relative = PurePosixPath(member.name)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SystemExit("payload archive path is unsafe")
        if not (member.isfile() or member.isdir()):
            raise SystemExit("payload archive member type is unsafe")
    stream.extractall(root, members=members, filter="data")
PYARCHIVE

python3 - "$EXTRACTED" <<'PYVERIFY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
for relative, expected in sorted(manifest.items()):
    path = root / relative
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise SystemExit(f"payload digest mismatch: {{relative}}")
PYVERIFY

mkdir -p "$TRUSTED_HARNESS"
mount -t tmpfs -o size=1m,mode=0755,nosuid,nodev,noexec tmpfs "$TRUSTED_HARNESS"
install -D -o root -g root -m 0444 \
  "$EXTRACTED/trusted-harness/ops/live-e2e/ssh-over-mcp-live-e2e-gate" \
  "$TRUSTED_HARNESS/ops/live-e2e/ssh-over-mcp-live-e2e-gate"
install -D -o root -g root -m 0444 \
  "$EXTRACTED/trusted-harness/ops/live-e2e/ledger_guest_preflight.py" \
  "$TRUSTED_HARNESS/ops/live-e2e/ledger_guest_preflight.py"
chmod 0555 "$TRUSTED_HARNESS" "$TRUSTED_HARNESS/ops" "$TRUSTED_HARNESS/ops/live-e2e"
mount -o remount,ro,nosuid,nodev,noexec "$TRUSTED_HARNESS"
mountpoint -q "$TRUSTED_HARNESS"

test -f "$PIP_WHEEL"
python3 -m venv --without-pip "$VENV"
PYTHONPATH="$PIP_WHEEL" "$VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-index \
  --find-links="$EXTRACTED/bootstrap-wheels" \
  --require-hashes \
  -r "$EXTRACTED/e2e-bootstrap.lock"
"$VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-index \
  --find-links="$EXTRACTED/wheels" \
  --require-hashes \
  -r "$EXTRACTED/runtime.lock"

mkdir -p /opt/ssh-over-mcp-e2e "$WORKSPACE"
git -C "$WORKSPACE" init
git -C "$WORKSPACE" fetch "$EXTRACTED/target.bundle" refs/e2e/target
git -C "$WORKSPACE" checkout --detach FETCH_HEAD
test "$(git -C "$WORKSPACE" rev-parse HEAD)" = "$EXPECTED_COMMIT"
test -z "$(git -C "$WORKSPACE" status --porcelain=v1)"

mkdir -p /etc/ssh-over-mcp
printf 'EXPECTED_COMMIT=%s\\n' "$EXPECTED_COMMIT" > /etc/ssh-over-mcp/live-e2e-gate.conf
chmod 0600 /etc/ssh-over-mcp/live-e2e-gate.conf
chown root:root /etc/ssh-over-mcp/live-e2e-gate.conf

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$TRUSTED_HARNESS/ops/live-e2e/ssh-over-mcp-live-e2e-gate"
"""


def _seed_user_data() -> str:
    return """#cloud-config
bootcmd:
  - [ systemctl, mask, --runtime, systemd-networkd-wait-online.service ]
runcmd:
  - [ mkdir, -p, /mnt/som-payload ]
  - [ mount, -o, ro, LABEL=SOM_E2E_PAYLOAD, /mnt/som-payload ]
  - [ /bin/bash, /mnt/som-payload/bootstrap.sh ]
"""


def _parse_serial_result(raw: str, target: str) -> bool:
    target = _validated_target_commit(target)
    records = []
    for line in raw.splitlines():
        match = _RESULT_RE.fullmatch(line.strip())
        if match is not None:
            records.append(match)
    if len(records) != 1:
        raise OrchestratorError("serial result must contain exactly one result record")
    commit, status, code = records[0].groups()
    if commit != target:
        raise OrchestratorError("serial result commit mismatch")
    if status != "PASS" or code is not None:
        sshd_stage = "UNKNOWN"
        for line in raw.splitlines():
            stage_match = _SSHD_STAGE_RE.fullmatch(line.strip())
            if stage_match is not None:
                sshd_stage = stage_match.group(1)
        raise OrchestratorError(
            "guest E2E reported failure: "
            f"code={code or 'none'} sshd_stage={sshd_stage}"
        )
    return True


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


def _require_bounded_file(path: Path, *, max_bytes: int, label: str) -> None:
    try:
        info = path.stat()
    except OSError as exc:
        raise OrchestratorError(f"{label} is unavailable") from exc
    if not path.is_file():
        raise OrchestratorError(f"{label} is not a regular file")
    if info.st_size > max_bytes:
        raise OrchestratorError(f"{label} exceeds size limit")


def _require_host_free_space(path: Path) -> None:
    try:
        free = shutil.disk_usage(path).free
    except OSError as exc:
        raise OrchestratorError("cannot determine host free space") from exc
    if free < HOST_MIN_FREE_BYTES:
        raise OrchestratorError("insufficient host free space for isolated E2E guest")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
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


def _write_payload_archive(source: Path, archive: Path) -> None:
    source_root = source.resolve(strict=True)
    with tarfile.open(archive, mode="w") as stream:
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise OrchestratorError("payload archive source contains unsafe entry")
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(source_root)
            except ValueError as exc:
                raise OrchestratorError("payload archive source escapes root") from exc

            def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.mode = 0o755 if info.isdir() else 0o644
                return info

            stream.add(
                path,
                arcname=path.relative_to(source).as_posix(),
                recursive=False,
                filter=normalize,
            )


def _write_manifest(payload: Path) -> None:
    entries: dict[str, str] = {}
    for path in sorted(payload.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        entries[path.relative_to(payload).as_posix()] = _sha256(path)
    (payload / "manifest.json").write_text(
        json.dumps(entries, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _provider_document() -> dict[str, object]:
    try:
        document = json.loads(PROVIDER_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OrchestratorError("trusted QEMU provider metadata is unavailable") from exc
    if not isinstance(document, dict):
        raise OrchestratorError("trusted QEMU provider metadata is invalid")
    return document


class _SystemLifecycle:
    def __init__(self, env: Mapping[str, str]) -> None:
        self._host_env = dict(env)
        self._provider_env = _provider_environment(env)
        self._temp: tempfile.TemporaryDirectory[str] | None = None
        self._root: Path | None = None
        self._serial_output: bytes | None = None
        self._qemu: subprocess.Popen[bytes] | None = None
        self._state_created = False

    def verify_host(self) -> None:
        workflow_sha = _validated_workflow_context(self._host_env)
        observed_head = _run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            env=self._provider_env,
            timeout=10,
        ).stdout.strip().lower()
        if observed_head != workflow_sha:
            raise OrchestratorError("trusted orchestrator checkout mismatch")
        dirty = _run(
            ["git", "-C", str(ROOT), "status", "--porcelain=v1"],
            env=self._provider_env,
            timeout=10,
        ).stdout
        if dirty:
            raise OrchestratorError("trusted orchestrator checkout is dirty")
        if platform.system() != "Darwin" or platform.machine() != "x86_64":
            raise OrchestratorError("E2E orchestrator requires Intel macOS")
        if os.geteuid() == 0:
            raise OrchestratorError("E2E orchestrator must be non-root")
        _require_host_free_space(ORCHESTRATOR_HOME)
        _require_host_free_space(Path(tempfile.gettempdir()))
        try:
            account = pwd.getpwuid(os.geteuid())
        except KeyError as exc:
            raise OrchestratorError("E2E orchestrator account is unavailable") from exc
        if account.pw_name != ORCHESTRATOR_USER or Path(account.pw_dir) != ORCHESTRATOR_HOME:
            raise OrchestratorError("unexpected E2E orchestrator account")
        try:
            admin_gid = grp.getgrnam("admin").gr_gid
        except KeyError as exc:
            raise OrchestratorError("macOS admin group is unavailable") from exc
        if admin_gid in os.getgroups():
            raise OrchestratorError("E2E orchestrator account must be non-admin")

        expected_provider = {
            "qemu_version": QEMU_VERSION,
            "arch": "x86_64",
            "accelerator": "hvf",
            "image_url": IMAGE_URL,
            "image_digest": IMAGE_DIGEST,
            "cpus": 4,
            "memory_mib": 6144,
            "disk_gib": GUEST_DISK_GIB,
            "python_version": PYTHON_VERSION,
            "python_abi": PYTHON_ABI,
            "network": False,
            "host_shares": False,
            "serial_result_prefix": RESULT_PREFIX,
        }
        if _provider_document() != expected_provider:
            raise OrchestratorError("trusted QEMU provider metadata mismatch")
        if not TRUSTED_RUNTIME_LOCK.is_file():
            raise OrchestratorError("trusted runtime lock is unavailable")
        if not BOOTSTRAP_LOCK.is_file():
            raise OrchestratorError("trusted bootstrap lock is unavailable")
        if not BASE_IMAGE.is_file():
            raise OrchestratorError("pinned Ubuntu base image is unavailable")
        if f"sha256:{_sha256(BASE_IMAGE)}" != IMAGE_DIGEST:
            raise OrchestratorError("pinned Ubuntu base image digest mismatch")

        qemu_version = _run(
            [str(QEMU_SYSTEM), "--version"],
            env=self._provider_env,
            timeout=10,
        ).stdout.splitlines()[0]
        if not qemu_version.startswith(f"QEMU emulator version {QEMU_VERSION}"):
            raise OrchestratorError("unexpected QEMU version")
        qemu_img_version = _run(
            [str(QEMU_IMG), "--version"],
            env=self._provider_env,
            timeout=10,
        ).stdout.splitlines()[0]
        if QEMU_VERSION not in qemu_img_version:
            raise OrchestratorError("unexpected qemu-img version")
        hv = _run(
            ["sysctl", "-n", "kern.hv_support"],
            env=self._provider_env,
            timeout=10,
        ).stdout.strip()
        if hv != "1":
            raise OrchestratorError("macOS Hypervisor support is unavailable")

    def provider_state_exists(self) -> bool:
        if PROVIDER_STATE.exists() or PROVIDER_STATE.is_symlink():
            return True
        inventory = _run(
            ["/bin/ps", "-ww", "-U", str(os.getuid()), "-o", "comm="],
            env=self._provider_env,
            timeout=10,
        ).stdout.splitlines()
        commands = [line.strip() for line in inventory if line.strip()]
        if not commands:
            raise OrchestratorError("provider process inventory is unavailable")
        return any(Path(command).name == QEMU_SYSTEM.name for command in commands)

    def _ensure_temp(self) -> Path:
        if self._temp is None:
            self._temp = tempfile.TemporaryDirectory(prefix="ssh-over-mcp-e2e-")
            self._root = Path(self._temp.name)
            self._root.chmod(0o700)
        assert self._root is not None
        return self._root

    def create_bundle(self, target: str) -> Path:
        CACHE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        state_fd = os.open(
            PROVIDER_STATE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(state_fd, "w", encoding="ascii") as stream:
            stream.write(json.dumps({"target": target, "owner_pid": os.getpid()}) + "\n")
        self._state_created = True

        root = self._ensure_temp()
        bare = root / "target.git"
        bundle = root / "target.bundle"
        askpass = root / "git-askpass"
        _write_askpass(askpass)
        git_env = _git_environment(self._host_env, askpass=askpass)
        commands = _host_git_commands(bare, bundle, target)
        try:
            _fetch_target_into_bare(bare, target, git_env)
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
            _require_bounded_file(
                bundle,
                max_bytes=TARGET_BUNDLE_MAX_BYTES,
                label="target bundle",
            )
            return bundle
        finally:
            git_env.pop(HOST_TOKEN_ENV, None)
            self._host_env.pop(HOST_TOKEN_ENV, None)

    def prepare_guest(self, target: str, bundle: Path) -> None:
        root = self._ensure_temp()
        wheelhouse = root / "wheels"
        wheelhouse.mkdir(mode=0o700)
        _run(
            _wheel_download_command(TRUSTED_RUNTIME_LOCK, wheelhouse),
            env=self._provider_env,
            timeout=300,
        )
        wheels = sorted(wheelhouse.glob("*.whl"))
        if not wheels or any(path.suffix != ".whl" for path in wheelhouse.iterdir()):
            raise OrchestratorError("runtime wheelhouse is incomplete")

        bootstrap_wheelhouse = root / "bootstrap-wheels"
        bootstrap_wheelhouse.mkdir(mode=0o700)
        _run(
            _bootstrap_wheel_download_command(BOOTSTRAP_LOCK, bootstrap_wheelhouse),
            env=self._provider_env,
            timeout=120,
        )
        bootstrap_wheels = sorted(bootstrap_wheelhouse.glob("*.whl"))
        if [path.name for path in bootstrap_wheels] != [
            "pip-26.2.1-py3-none-any.whl"
        ]:
            raise OrchestratorError("bootstrap wheelhouse is not exact")

        payload_content = root / "payload-content"
        payload_iso = root / "payload-iso"
        seed_dir = root / "seed"
        payload_content.mkdir(mode=0o700)
        payload_iso.mkdir(mode=0o700)
        seed_dir.mkdir(mode=0o700)

        shutil.copy2(bundle, payload_content / "target.bundle")
        shutil.copy2(TRUSTED_RUNTIME_LOCK, payload_content / "runtime.lock")
        shutil.copy2(BOOTSTRAP_LOCK, payload_content / "e2e-bootstrap.lock")
        shutil.copytree(wheelhouse, payload_content / "wheels")
        shutil.copytree(bootstrap_wheelhouse, payload_content / "bootstrap-wheels")
        harness_root = payload_content / "trusted-harness"
        trusted_root = ROOT.resolve(strict=True)
        for relative in TRUSTED_HARNESS_FILES:
            candidate = ROOT / relative
            if candidate.is_symlink() or not candidate.is_file():
                raise OrchestratorError("trusted harness source is not a regular file")
            source = candidate.resolve(strict=True)
            try:
                source.relative_to(trusted_root)
            except ValueError as exc:
                raise OrchestratorError("trusted harness path escapes repository") from exc
            destination = harness_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        (payload_content / "expected_commit").write_text(
            target + "\n",
            encoding="ascii",
        )
        _write_manifest(payload_content)

        payload_archive = payload_iso / "payload.tar"
        _write_payload_archive(payload_content, payload_archive)
        payload_archive_digest = _sha256(payload_archive)
        bootstrap = payload_iso / "bootstrap.sh"
        bootstrap.write_text(
            _bootstrap_script(target, payload_archive_digest),
            encoding="utf-8",
        )
        bootstrap.chmod(0o700)

        (seed_dir / "meta-data").write_text(
            f"instance-id: ssh-over-mcp-e2e-{target}\n"
            "local-hostname: ssh-over-mcp-e2e\n",
            encoding="utf-8",
        )
        (seed_dir / "network-config").write_text(
            "version: 2\nethernets: {}\n",
            encoding="utf-8",
        )
        (seed_dir / "user-data").write_text(_seed_user_data(), encoding="utf-8")

        seed_iso = root / "seed.iso"
        payload_iso_path = root / "payload.iso"
        overlay = root / "overlay.qcow2"
        _run(
            _iso_command(seed_dir, seed_iso, "cidata"),
            env=self._provider_env,
            timeout=120,
        )
        _run(
            _iso_command(payload_iso, payload_iso_path, "SOM_E2E_PAYLOAD"),
            env=self._provider_env,
            timeout=120,
        )
        _run(
            _overlay_command(BASE_IMAGE, overlay),
            env=self._provider_env,
            timeout=60,
        )

        self._serial_output = None

    def start_guest(self) -> None:
        root = self._ensure_temp()
        command = _qemu_command(
            root / "overlay.qcow2",
            root / "seed.iso",
            root / "payload.iso",
        )
        self._qemu = subprocess.Popen(
            command,
            env=self._provider_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
            bufsize=0,
        )

    def wait_guest(self) -> int:
        if self._qemu is None or self._qemu.stdout is None:
            raise OrchestratorError("QEMU guest was not started")

        stream = self._qemu.stdout
        fd = stream.fileno()
        os.set_blocking(fd, False)
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + 1200.0
        try:
            while True:
                status = self._qemu.poll()
                for _key, _events in selector.select(timeout=0.1):
                    while True:
                        try:
                            chunk = os.read(fd, 65536)
                        except BlockingIOError:
                            break
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > SERIAL_MAX_BYTES:
                            raise OrchestratorError("serial output exceeded limit")
                if status is not None:
                    while True:
                        try:
                            chunk = os.read(fd, 65536)
                        except BlockingIOError:
                            break
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > SERIAL_MAX_BYTES:
                            raise OrchestratorError("serial output exceeded limit")
                    self._serial_output = bytes(output)
                    return int(status)
                if time.monotonic() >= deadline:
                    raise OrchestratorError("QEMU guest timed out")
        finally:
            selector.close()

    def verify_result(self, target: str) -> None:
        if self._serial_output is None:
            raise OrchestratorError("guest serial result is unavailable")
        _parse_serial_result(
            self._serial_output.decode("utf-8", errors="replace"),
            target,
        )

    def cleanup_guest(self) -> None:
        if self._qemu is not None and self._qemu.poll() is None:
            self._qemu.terminate()
            try:
                self._qemu.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._qemu.kill()
                self._qemu.wait(timeout=15)
        self._qemu = None

    def cleanup_host(self) -> None:
        cleanup_error: BaseException | None = None
        try:
            if self._temp is not None:
                self._temp.cleanup()
                self._temp = None
                self._root = None
                self._serial_output = None
        except OSError as exc:
            cleanup_error = exc

        if cleanup_error is None and self._state_created:
            try:
                PROVIDER_STATE.unlink()
                self._state_created = False
            except OSError as exc:
                cleanup_error = exc

        if cleanup_error is not None:
            raise OrchestratorError("host E2E cleanup failed") from cleanup_error


def _orchestrate(target: str, ops: _Lifecycle) -> int:
    started = False
    try:
        ops.verify_host()
        if ops.provider_state_exists():
            raise OrchestratorError("stale E2E provider state detected")
        bundle = ops.create_bundle(target)
        ops.prepare_guest(target, bundle)
        ops.start_guest()
        started = True
        status = ops.wait_guest()
        if status != 0:
            raise OrchestratorError(f"QEMU guest exited with status {status}")
        ops.verify_result(target)
        return 0
    finally:
        try:
            if started:
                ops.cleanup_guest()
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
