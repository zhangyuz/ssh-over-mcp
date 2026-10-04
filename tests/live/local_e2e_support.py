from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Self

import httpx2
import uvicorn
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from ssh_over_mcp.api.app import build_application
from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings
from ssh_over_mcp.approvals.service import SecurityLedgerService
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.ssh.connection import SSHConnectionManager
from ssh_over_mcp.ssh.credentials import FileCredentialProvider
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits, encode_request
from ssh_over_mcp.ssh.transport import SSHExecutionResult, StructuredSSHTransport

_EXPECTED_VALUES = {
    "SSH_OVER_MCP_LIVE_E2E_HOST": "127.0.0.1",
    "SSH_OVER_MCP_LIVE_E2E_PORT": "22222",
    "SSH_OVER_MCP_LIVE_E2E_SSH_USER": "ssh-over-mcp-e2e-host",
    "SSH_OVER_MCP_LIVE_E2E_PRIVATE_KEY": (
        "/opt/ssh-over-mcp-e2e/runtime/client_ed25519"
    ),
    "SSH_OVER_MCP_LIVE_E2E_HOST_KEY_PUBLIC": (
        "/opt/ssh-over-mcp-e2e/runtime/sshd_host_ed25519.pub"
    ),
    "SSH_OVER_MCP_LIVE_E2E_MANAGER_ENDPOINT": (
        "/opt/ssh-over-mcp-e2e/runtime/manager/containment.sock"
    ),
    "SSH_OVER_MCP_LIVE_E2E_CGROUP_ROOT": "/sys/fs/cgroup/ssh-over-mcp-e2e",
    "SSH_OVER_MCP_LIVE_E2E_HOST_SOURCE_CGROUP": (
        "/sys/fs/cgroup/ssh-over-mcp-e2e/host-agent-source"
    ),
    "SSH_OVER_MCP_LIVE_E2E_STATE_SCRIPT": (
        "/opt/ssh-over-mcp-e2e/runtime/workload_state.py"
    ),
    "SSH_OVER_MCP_LIVE_E2E_WORK_DIR": "/opt/ssh-over-mcp-e2e/runtime/work",
    "SSH_OVER_MCP_LIVE_E2E_MANAGER_UID": "2201",
    "SSH_OVER_MCP_LIVE_E2E_MANAGER_GID": "3201",
    "SSH_OVER_MCP_LIVE_E2E_HOST_UID": "2202",
    "SSH_OVER_MCP_LIVE_E2E_HOST_GID": "3202",
    "SSH_OVER_MCP_LIVE_E2E_WORKLOAD_UID": "2203",
    "SSH_OVER_MCP_LIVE_E2E_WORKLOAD_GID": "3203",
    "SSH_OVER_MCP_LIVE_E2E_PROBE_UID": "2204",
    "SSH_OVER_MCP_LIVE_E2E_PROBE_GID": "3204",
    "SSH_OVER_MCP_LIVE_E2E_MANAGER_CLIENT_GID": "3299",
}
_EXPECTED_KEYS = frozenset(_EXPECTED_VALUES) | {"SSH_OVER_MCP_LIVE_EXPECTED_COMMIT"}
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REQUEST_ID = "req_0000000000000000000000000000e2e1"
FS_DATA_ROOT = Path("/opt/ssh-over-mcp-e2e/fs-data")
FS_SEED_FILE = FS_DATA_ROOT / "seed.txt"
FS_CREATE_ROOT = FS_DATA_ROOT / "create"
FS_MKDIR_TARGET = FS_CREATE_ROOT / "created-dir"
FS_WRITE_TARGET = FS_CREATE_ROOT / "created.txt"
FS_SEED_BYTES = b"ssh-over-mcp-e2e-seed\n"
FS_WRITE_BYTES = b"ssh-over-mcp-e2e-sensitive-write-body-v1\n"
SSHD_LOG = Path("/opt/ssh-over-mcp-e2e/runtime/sshd.log")
WORKLOAD_DATA_ROOT = Path("/opt/ssh-over-mcp-e2e/workload-data")
EXEC_MARKER = WORKLOAD_DATA_ROOT / "exec-marker"
MARKER_SCRIPT = Path("/opt/ssh-over-mcp-e2e/runtime/workload_marker.py")
APPROVAL_MARKER = WORKLOAD_DATA_ROOT / "approval-marker"
APPROVAL_SCRIPT = Path("/opt/ssh-over-mcp-e2e/runtime/approval_marker.py")
CONTROL_FD_ENV = "SSH_OVER_MCP_LIVE_E2E_CONTROL_FD"
_APPROVAL_ID_RE = re.compile(rb"approval_id=(apr_[0-9a-f]{32})")
WRONG_HOST_KEY_PUBLIC = Path(
    "/opt/ssh-over-mcp-e2e/runtime/wrong_host_ed25519.pub"
)


class LocalE2EFixtureError(RuntimeError):
    """The operator-provided local E2E fixture metadata is invalid."""


class LocalE2ELauncherError(LocalE2EFixtureError):
    """The fixed capability launcher failed closed."""


class LocalE2ERemoteExecutionError(LocalE2EFixtureError):
    """The remote E2E execution failed without exposing remote stderr."""


def _require_successful_remote_result(result: SSHExecutionResult) -> None:
    if (
        result.exit_status == 0
        and result.exit_signal is None
        and not result.timed_out
        and not result.truncated
        and not result.stderr
    ):
        return

    if (
        result.exit_status == 70
        and result.exit_signal is None
        and not result.timed_out
        and not result.truncated
        and result.stderr == b"ssh-over-mcp host-agent launcher failed\n"
    ):
        raise LocalE2ELauncherError("fixed host-agent capability launcher failed closed")

    raise LocalE2ERemoteExecutionError("real structured SSH fixture failed remotely")


@dataclass(frozen=True, slots=True)
class LocalE2EFixture:
    expected_commit: str
    host: str
    port: int
    ssh_user: str
    private_key: Path
    host_key_public: Path
    manager_endpoint: Path
    cgroup_root: Path
    host_source_cgroup: Path
    state_script: Path
    work_dir: Path
    manager_uid: int
    manager_gid: int
    host_uid: int
    host_gid: int
    workload_uid: int
    workload_gid: int
    probe_uid: int
    probe_gid: int
    manager_client_gid: int

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, str]) -> LocalE2EFixture:
        if frozenset(mapping) != _EXPECTED_KEYS:
            raise LocalE2EFixtureError("local E2E metadata keys are not exact")

        commit = mapping["SSH_OVER_MCP_LIVE_EXPECTED_COMMIT"].lower()
        if _COMMIT_RE.fullmatch(commit) is None:
            raise LocalE2EFixtureError("expected commit is invalid")

        for name, expected in _EXPECTED_VALUES.items():
            if mapping.get(name) != expected:
                raise LocalE2EFixtureError(f"local E2E metadata mismatch: {name}")

        return cls(
            expected_commit=commit,
            host="127.0.0.1",
            port=22222,
            ssh_user="ssh-over-mcp-e2e-host",
            private_key=Path(_EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_PRIVATE_KEY"]),
            host_key_public=Path(
                _EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_HOST_KEY_PUBLIC"]
            ),
            manager_endpoint=Path(
                _EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_MANAGER_ENDPOINT"]
            ),
            cgroup_root=Path(_EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_CGROUP_ROOT"]),
            host_source_cgroup=Path(
                _EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_HOST_SOURCE_CGROUP"]
            ),
            state_script=Path(_EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_STATE_SCRIPT"]),
            work_dir=Path(_EXPECTED_VALUES["SSH_OVER_MCP_LIVE_E2E_WORK_DIR"]),
            manager_uid=2201,
            manager_gid=3201,
            host_uid=2202,
            host_gid=3202,
            workload_uid=2203,
            workload_gid=3203,
            probe_uid=2204,
            probe_gid=3204,
            manager_client_gid=3299,
        )

    @classmethod
    def from_env(cls) -> LocalE2EFixture:
        values: dict[str, str] = {}
        for name in _EXPECTED_KEYS:
            value = os.environ.get(name)
            if value is None:
                raise LocalE2EFixtureError(f"required local E2E metadata is absent: {name}")
            values[name] = value
        return cls.from_mapping(values)

    @staticmethod
    def _require_file(
        path: Path,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise LocalE2EFixtureError(f"required fixture file is absent: {path}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise LocalE2EFixtureError(f"fixture file is not regular: {path}")
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
            raise LocalE2EFixtureError(f"fixture file identity/mode mismatch: {path}")

    @staticmethod
    def _require_dir(
        path: Path,
        *,
        uid: int,
        mode: int | None = None,
    ) -> None:
        try:
            resolved = path.resolve(strict=True)
            info = path.lstat()
        except OSError as exc:
            raise LocalE2EFixtureError(f"required fixture directory is absent: {path}") from exc
        if resolved != path or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise LocalE2EFixtureError(f"fixture directory is not canonical: {path}")
        if info.st_uid != uid:
            raise LocalE2EFixtureError(f"fixture directory owner mismatch: {path}")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise LocalE2EFixtureError(f"fixture directory mode mismatch: {path}")

    def verify_filesystem_contract(self) -> None:
        self._require_file(
            self.private_key,
            uid=self.probe_uid,
            gid=self.probe_gid,
            mode=0o600,
        )
        self._require_file(
            self.host_key_public,
            uid=0,
            gid=0,
            mode=0o644,
        )
        self._require_file(
            self.state_script,
            uid=0,
            gid=0,
            mode=0o555,
        )
        self._require_file(
            SSHD_LOG,
            uid=0,
            gid=self.probe_gid,
            mode=0o640,
        )
        self._require_file(
            EXEC_MARKER,
            uid=self.workload_uid,
            gid=self.workload_gid,
            mode=0o644,
        )
        self._require_file(
            MARKER_SCRIPT,
            uid=0,
            gid=0,
            mode=0o555,
        )
        self._require_file(
            APPROVAL_MARKER,
            uid=self.workload_uid,
            gid=self.workload_gid,
            mode=0o644,
        )
        self._require_file(
            APPROVAL_SCRIPT,
            uid=0,
            gid=0,
            mode=0o555,
        )
        self._require_file(
            WRONG_HOST_KEY_PUBLIC,
            uid=0,
            gid=0,
            mode=0o644,
        )
        self._require_dir(self.work_dir, uid=0, mode=0o755)
        self._require_dir(WORKLOAD_DATA_ROOT, uid=0, mode=0o755)
        self._require_dir(self.cgroup_root, uid=self.manager_uid)
        # The host-source cgroup and manager socket are intentionally not
        # traversable by the zero-supplementary-group probe. The trusted root
        # gate verifies those privileged surfaces immediately before dropping
        # to the probe identity.

    def host_key_line(self) -> str:
        return _host_key_line(self.host_key_public)


def _host_key_line(path: Path) -> str:
    raw = path.read_text(encoding="ascii").strip()
    parts = raw.split()
    if len(parts) < 2:
        raise LocalE2EFixtureError("host public key is malformed")
    return f"{parts[0]} {parts[1]}"


def _validate_workload_state(
    state: object,
    fixture: LocalE2EFixture,
    *,
    expected_request_id: str,
) -> dict[str, object]:
    if not isinstance(state, dict):
        raise LocalE2EFixtureError("workload state is not an object")

    expected = {
        "uids": [fixture.workload_uid] * 3,
        "gids": [fixture.workload_gid] * 3,
        "groups": [],
        "cap_inheritable": 0,
        "cap_permitted": 0,
        "cap_effective": 0,
        "cap_ambient": 0,
        "no_new_privs": 1,
        "manager_socket_fd_present": False,
    }
    for key, value in expected.items():
        if state.get(key) != value:
            raise LocalE2EFixtureError(f"workload security state mismatch: {key}")

    if re.fullmatch(r"req_[0-9a-f]{32}", expected_request_id) is None:
        raise LocalE2EFixtureError("expected request id is invalid")
    cgroup = state.get("cgroup")
    expected_cgroup = (
        f"/ssh-over-mcp-e2e/ssh-over-mcp-{expected_request_id}"
    )
    if cgroup != expected_cgroup:
        raise LocalE2EFixtureError("workload request cgroup mismatch")
    return state


async def run_real_ssh_fixture() -> dict[str, object]:
    fixture = LocalE2EFixture.from_env()
    fixture.verify_filesystem_contract()

    alias = "e2e-host"
    inventory = Inventory(
        hosts={
            alias: Host(
                address=fixture.host,
                port=fixture.port,
                ssh_user=fixture.ssh_user,
                credential_ref="e2e-client",
                host_key=fixture.host_key_line(),
                labels=frozenset({"e2e"}),
                allowed_roles=frozenset({"developer"}),
            )
        }
    )
    credentials = FileCredentialProvider({"e2e-client": fixture.private_key})
    connections = SSHConnectionManager(
        inventory=inventory,
        credentials=credentials,
        connect_timeout_seconds=5.0,
        login_timeout_seconds=5.0,
        keepalive_interval_seconds=0.0,
        max_connection_age_seconds=30.0,
        max_sessions_per_host=1,
    )
    transport = StructuredSSHTransport(
        connections=connections,
        cleanup_timeout_seconds=2.0,
    )
    envelope = ExecEnvelope(
        request_id=_REQUEST_ID,
        profile="developer",
        executable="/usr/bin/python3",
        argv=("-I", "-S", str(fixture.state_script)),
        cwd=str(fixture.work_dir),
        env={},
        limits=ExecutionLimits(
            timeout_seconds=10.0,
            max_output_bytes=65536,
            max_stdin_bytes=0,
        ),
    )

    try:
        result = await transport.run(
            host=alias,
            payload=encode_request(envelope),
            request_id=envelope.request_id,
            timeout_seconds=12.0,
            max_output_bytes=65536,
        )
    finally:
        await connections.close()

    _require_successful_remote_result(result)

    try:
        state = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LocalE2EFixtureError("workload state output is invalid") from exc
    return _validate_workload_state(
        state,
        fixture,
        expected_request_id=_REQUEST_ID,
    )

class LocalMCPHarness:
    """Test-local production-component harness for MCP, Ledger, and real SSH."""

    def __init__(self, fixture: LocalE2EFixture) -> None:
        self.fixture = fixture
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._root: Path | None = None
        self._ledger_settings: SecurityLedgerRuntimeSettings | None = None
        self._ledger_service: SecurityLedgerService | None = None
        self._ledger_stop: threading.Event | None = None
        self._ledger_thread: threading.Thread | None = None
        self._ledger_errors: list[BaseException] = []
        self._origin_token: bytes | None = None
        self._origin_token_file: Path | None = None
        self._mcp_url: str | None = None
        self._server: uvicorn.Server | None = None
        self._server_task: asyncio.Task[None] | None = None
        self._server_socket: socket.socket | None = None
        self._log_stream: io.StringIO | None = None
        self._log_handler: logging.Handler | None = None

    @property
    def mcp_url(self) -> str:
        if self._mcp_url is None:
            raise LocalE2EFixtureError("local MCP server is not active")
        return self._mcp_url

    @property
    def ledger_db_path(self) -> Path:
        settings = self._require_ledger_settings()
        return settings.db_path

    def _require_root(self) -> Path:
        if self._root is None:
            raise LocalE2EFixtureError("local MCP harness is not active")
        return self._root

    def _require_ledger_settings(self) -> SecurityLedgerRuntimeSettings:
        if self._ledger_settings is None:
            raise LocalE2EFixtureError("local Security Ledger is not active")
        return self._ledger_settings

    async def __aenter__(self) -> Self:
        if self._temporary is not None:
            raise LocalE2EFixtureError("local MCP harness is already active")
        self.fixture.verify_filesystem_contract()
        temporary = tempfile.TemporaryDirectory(prefix="ssh-over-mcp-live-mcp-")
        self._temporary = temporary
        self._root = Path(temporary.name)
        os.chmod(self._root, 0o700)
        self._log_stream = io.StringIO()
        self._log_handler = logging.StreamHandler(self._log_stream)
        logging.getLogger().addHandler(self._log_handler)

        uid = os.getuid()
        gid = os.getgid()
        if uid != self.fixture.probe_uid or gid != self.fixture.probe_gid:
            await self.__aexit__(None, None, None)
            raise LocalE2EFixtureError("local MCP harness must run as the probe identity")

        data_dir = self._root / "ledger-data"
        exec_dir = self._root / "ledger-exec"
        admin_dir = self._root / "ledger-admin"
        for directory in (data_dir, exec_dir, admin_dir):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)

        hmac_key = data_dir / "ledger.key"
        hmac_key.write_bytes(secrets.token_bytes(32))
        os.chmod(hmac_key, 0o600)

        self._ledger_settings = SecurityLedgerRuntimeSettings(
            db_path=data_dir / "ledger.db",
            hmac_key_path=hmac_key,
            service_uid=uid,
            service_gid=gid,
            execution_socket_path=exec_dir / "ledger.sock",
            execution_socket_gid=gid,
            execution_socket_mode=0o600,
            execution_peer_uid=uid,
            execution_peer_gid=gid,
            admin_socket_path=admin_dir / "ledger.sock",
            admin_socket_gid=gid,
            admin_socket_mode=0o600,
            admin_peer_uid=uid,
            admin_peer_gid=gid,
        )
        self._ledger_service = SecurityLedgerService.create(self._ledger_settings)
        self._ledger_stop = threading.Event()
        self._ledger_errors = []

        def run_ledger() -> None:
            assert self._ledger_service is not None
            assert self._ledger_stop is not None
            try:
                self._ledger_service.serve_forever(
                    stop_requested=self._ledger_stop.is_set,
                )
            except BaseException as exc:  # noqa: BLE001 - propagated after join
                self._ledger_errors.append(exc)

        self._ledger_thread = threading.Thread(
            target=run_ledger,
            name="ssh-over-mcp-live-ledger",
        )
        self._ledger_thread.start()

        self._origin_token = secrets.token_urlsafe(32).encode("ascii")
        self._origin_token_file = self._root / "origin-bearer"
        self._origin_token_file.write_bytes(self._origin_token)
        os.chmod(self._origin_token_file, 0o600)
        return self

    def stop_ledger(self) -> None:
        if (
            self._ledger_stop is None
            or self._ledger_thread is None
            or self._ledger_service is None
        ):
            raise LocalE2EFixtureError("local Security Ledger is not active")
        self._ledger_stop.set()
        self._ledger_thread.join(timeout=3)
        if self._ledger_thread.is_alive():
            raise LocalE2EFixtureError("local Security Ledger thread did not stop")
        self._ledger_service.close()
        if self._ledger_errors:
            raise LocalE2EFixtureError("local Security Ledger service failed")
        self._ledger_service = None
        self._ledger_stop = None
        self._ledger_thread = None

    async def __aexit__(self, exc_type, exc, tb) -> None:
        cleanup_error: BaseException | None = None
        try:
            await self._stop_server()
        except BaseException as stop_exc:  # noqa: BLE001 - preserve cleanup
            cleanup_error = stop_exc

        if self._ledger_stop is not None:
            self._ledger_stop.set()
        if self._ledger_thread is not None:
            self._ledger_thread.join(timeout=3)
            if self._ledger_thread.is_alive() and cleanup_error is None:
                cleanup_error = LocalE2EFixtureError(
                    "local Security Ledger thread did not stop"
                )
        if self._ledger_service is not None:
            try:
                self._ledger_service.close()
            except BaseException as ledger_exc:  # noqa: BLE001 - preserve cleanup
                if cleanup_error is None:
                    cleanup_error = ledger_exc
        if self._ledger_errors and cleanup_error is None:
            cleanup_error = LocalE2EFixtureError(
                "local Security Ledger service failed"
            )

        self._ledger_service = None
        self._ledger_stop = None
        self._ledger_thread = None
        self._ledger_settings = None
        self._origin_token = None
        self._origin_token_file = None
        if self._log_handler is not None:
            logging.getLogger().removeHandler(self._log_handler)
        self._log_handler = None
        self._log_stream = None
        self._mcp_url = None
        self._root = None
        temporary, self._temporary = self._temporary, None
        if temporary is not None:
            temporary.cleanup()
        if cleanup_error is not None and exc is None:
            raise cleanup_error

    def _config_document(self, profile: str, policy_variant: str) -> dict[str, object]:
        if profile not in {"developer", "readonly"}:
            raise LocalE2EFixtureError("unsupported local E2E profile")
        if policy_variant not in {
            "normal",
            "central_deny",
            "remote_deny",
            "wrong_host_key",
            "approval",
        }:
            raise LocalE2EFixtureError("unsupported local E2E policy variant")
        return {
            "inventory": {
                "hosts": {
                    "e2e-host": {
                        "address": self.fixture.host,
                        "port": self.fixture.port,
                        "ssh_user": self.fixture.ssh_user,
                        "credential_ref": "e2e-client",
                        "host_key": (
                            _host_key_line(WRONG_HOST_KEY_PUBLIC)
                            if policy_variant == "wrong_host_key"
                            else self.fixture.host_key_line()
                        ),
                        "labels": ["e2e"],
                        "allowed_roles": ["developer", "readonly"],
                    }
                }
            },
            "policy": {
                "version": 1,
                "default": "deny",
                "roles": {
                    "developer": (
                        {"env_allow": ["E2E_SECRET"]}
                        if policy_variant == "approval"
                        else {}
                    ),
                    "readonly": {},
                },
                "risk": {
                    "approval_required": (
                        ["medium", "high", "critical"]
                        if policy_variant == "approval"
                        else ["high", "critical"]
                    )
                },
                "rules": [
                    *(
                        [
                            {
                                "id": "e2e.developer.marker.deny",
                                "effect": "deny",
                                "roles": ["developer"],
                                "hosts": ["e2e-host"],
                                "tools": ["ssh_exec"],
                                "executables": ["/usr/bin/python3"],
                                "argv_prefix": [
                                    "-I",
                                    "-S",
                                    str(MARKER_SCRIPT),
                                ],
                                "cwd": [str(self.fixture.work_dir)],
                            }
                        ]
                        if policy_variant == "central_deny"
                        else []
                    ),
                    {
                        "id": "e2e.developer.state",
                        "effect": "allow",
                        "roles": ["developer"],
                        "hosts": ["e2e-host"],
                        "tools": ["ssh_exec"],
                        "executables": ["/usr/bin/python3"],
                        "argv_prefix": [
                            "-I",
                            "-S",
                            str(self.fixture.state_script),
                        ],
                        "cwd": [str(self.fixture.work_dir)],
                    },
                    *(
                        [
                            {
                                "id": "e2e.developer.approval-marker",
                                "effect": "allow",
                                "roles": ["developer"],
                                "hosts": ["e2e-host"],
                                "tools": ["ssh_exec"],
                                "executables": ["/usr/bin/python3"],
                                "argv_prefix": [
                                    "-I",
                                    "-S",
                                    str(APPROVAL_SCRIPT),
                                ],
                                "cwd": [str(self.fixture.work_dir)],
                            }
                        ]
                        if policy_variant == "approval"
                        else []
                    ),
                    *(
                        [
                            {
                                "id": "e2e.developer.marker",
                                "effect": "allow",
                                "roles": ["developer"],
                                "hosts": ["e2e-host"],
                                "tools": ["ssh_exec"],
                                "executables": ["/usr/bin/python3"],
                                "argv_prefix": [
                                    "-I",
                                    "-S",
                                    str(MARKER_SCRIPT),
                                ],
                                "cwd": [str(self.fixture.work_dir)],
                            }
                        ]
                        if policy_variant in {"central_deny", "wrong_host_key"}
                        else []
                    ),
                    *(
                        [
                            {
                                "id": "e2e.developer.remote-deny",
                                "effect": "allow",
                                "roles": ["developer"],
                                "hosts": ["e2e-host"],
                                "tools": ["ssh_exec"],
                                "executables": ["/usr/bin/false"],
                                "argv_prefix": [],
                                "cwd": [str(self.fixture.work_dir)],
                            }
                        ]
                        if policy_variant == "remote_deny"
                        else []
                    ),
                    {
                        "id": "e2e.developer.files.read",
                        "effect": "allow",
                        "roles": ["developer"],
                        "hosts": ["e2e-host"],
                        "tools": ["fs_stat", "fs_read"],
                        "paths": [str(FS_SEED_FILE), str(FS_WRITE_TARGET)],
                    },
                    {
                        "id": "e2e.developer.files.mkdir",
                        "effect": "allow",
                        "roles": ["developer"],
                        "hosts": ["e2e-host"],
                        "tools": ["fs_mkdir"],
                        "paths": [str(FS_MKDIR_TARGET)],
                    },
                    {
                        "id": "e2e.developer.files.write",
                        "effect": "allow",
                        "roles": ["developer"],
                        "hosts": ["e2e-host"],
                        "tools": ["fs_write"],
                        "paths": [str(FS_WRITE_TARGET)],
                    },
                    {
                        "id": "e2e.readonly.files.read",
                        "effect": "allow",
                        "roles": ["readonly"],
                        "hosts": ["e2e-host"],
                        "tools": ["fs_stat", "fs_read"],
                        "paths": [str(FS_SEED_FILE)],
                    },
                ],
            },
        }

    def _write_app_files(self, profile: str, policy_variant: str) -> tuple[Path, Path]:
        root = self._require_root()
        config_path = root / f"config-{profile}-{policy_variant}.yaml"
        config_path.write_text(
            yaml.safe_dump(
                self._config_document(profile, policy_variant),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.chmod(config_path, 0o600)
        credential_map_path = root / "credentials.yaml"
        credential_map_path.write_text(
            yaml.safe_dump(
                {"credentials": {"e2e-client": str(self.fixture.private_key)}},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.chmod(credential_map_path, 0o600)
        return config_path, credential_map_path

    async def _start_server(self, profile: str, policy_variant: str) -> None:
        if self._server_task is not None:
            raise LocalE2EFixtureError("local MCP server is already active")
        settings = self._require_ledger_settings()
        if self._origin_token_file is None:
            raise LocalE2EFixtureError("origin bearer file is unavailable")
        config_path, credential_map_path = self._write_app_files(
            profile,
            policy_variant,
        )
        app = build_application(
            MCPRuntimeSettings(
                config_path=config_path,
                credential_map_path=credential_map_path,
                profile=profile,
                ledger_socket_path=settings.execution_socket_path,
                ledger_server_uid=settings.service_uid,
                ledger_server_gid=settings.service_gid,
                bind_host="127.0.0.1",
                origin_bearer_token_file=self._origin_token_file,
                port=8000,
            )
        )
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("127.0.0.1", 0))
        server_socket.listen(128)
        port = int(server_socket.getsockname()[1])
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="critical",
                access_log=False,
            )
        )
        task = asyncio.create_task(server.serve(sockets=[server_socket]))
        self._server = server
        self._server_task = task
        self._server_socket = server_socket
        self._mcp_url = f"http://127.0.0.1:{port}/mcp"
        for _ in range(500):
            if server.started:
                return
            if task.done():
                try:
                    await task
                except BaseException as server_exc:
                    raise LocalE2EFixtureError("local MCP server failed to start") from server_exc
                raise LocalE2EFixtureError("local MCP server stopped during startup")
            await asyncio.sleep(0.01)
        raise LocalE2EFixtureError("local MCP server did not start")

    async def _stop_server(self) -> None:
        server, task, server_socket = self._server, self._server_task, self._server_socket
        self._server = None
        self._server_task = None
        self._server_socket = None
        self._mcp_url = None
        if server is not None:
            server.should_exit = True
        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=5)
            except TimeoutError as exc:
                raise LocalE2EFixtureError("local MCP server did not stop") from exc
        if server_socket is not None:
            server_socket.close()

    @asynccontextmanager
    async def client(
        self,
        profile: str,
        policy_variant: str = "normal",
    ) -> AsyncIterator[Client]:
        await self._start_server(profile, policy_variant)
        if self._origin_token is None:
            await self._stop_server()
            raise LocalE2EFixtureError("origin bearer is unavailable")
        http_client = httpx2.AsyncClient(
            headers={
                "Authorization": "Bearer " + self._origin_token.decode("ascii"),
            },
            trust_env=False,
        )
        transport = streamable_http_client(
            self.mcp_url,
            http_client=http_client,
            terminate_on_close=False,
        )
        try:
            async with http_client, Client(transport) as client:
                yield client
        finally:
            await self._stop_server()

    def audit_events(self, request_id: str) -> tuple[dict[str, object], ...]:
        connection = sqlite3.connect(
            f"file:{self.ledger_db_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT event_type,request_id,principal_id,profile,host,tool,"
                "exit_status,duration_ms,stdout_bytes,stderr_bytes,timed_out,truncated "
                "FROM audit_events WHERE request_id=? ORDER BY rowid",
                (request_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(dict(row) for row in rows)

    def audit_rows(self) -> tuple[dict[str, object], ...]:
        connection = sqlite3.connect(
            f"file:{self.ledger_db_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT rowid,event_type,request_id,principal_id,profile,host,tool,"
                "exit_status,duration_ms,stdout_bytes,stderr_bytes,timed_out,truncated "
                "FROM audit_events ORDER BY rowid"
            ).fetchall()
        finally:
            connection.close()
        return tuple(dict(row) for row in rows)

    def captured_logs(self) -> bytes:
        if self._log_stream is None:
            raise LocalE2EFixtureError("local application log capture is unavailable")
        return self._log_stream.getvalue().encode("utf-8", errors="replace")

    def ledger_storage_bytes(self) -> bytes:
        db_path = self.ledger_db_path
        observed = bytearray()
        for path in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")):
            if path.is_file():
                observed.extend(path.read_bytes())
        return bytes(observed)

    def secret_sentinels(self) -> tuple[bytes, ...]:
        if self._origin_token is None:
            raise LocalE2EFixtureError("origin bearer is unavailable")
        private_key = self.fixture.private_key.read_bytes()
        key_fragment = next(
            (
                line
                for line in private_key.splitlines()
                if len(line) >= 24 and not line.startswith(b"-----")
            ),
            None,
        )
        if key_fragment is None:
            raise LocalE2EFixtureError("SSH private-key sentinel is unavailable")
        hmac_key = self._require_ledger_settings().hmac_key_path.read_bytes()
        return (
            self._origin_token,
            str(self.fixture.private_key).encode("utf-8"),
            private_key,
            key_fragment,
            hmac_key,
        )


def _tool_result_bytes(result: object) -> bytes:
    pieces: list[bytes] = []
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        pieces.append(
            json.dumps(structured, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    for block in getattr(result, "content", ()):
        text = getattr(block, "text", None)
        if isinstance(text, str):
            pieces.append(text.encode("utf-8"))
    return b"\n".join(pieces)


def _require_tool_success(result: object, label: str) -> dict[str, object]:
    if getattr(result, "is_error", True):
        raise LocalE2EFixtureError(f"{label} failed")
    structured = getattr(result, "structured_content", None)
    if not isinstance(structured, dict):
        raise LocalE2EFixtureError(f"{label} returned no structured content")
    return structured


def _require_tool_error(result: object, label: str) -> bytes:
    if not getattr(result, "is_error", False):
        raise LocalE2EFixtureError(f"{label} unexpectedly succeeded")
    return _tool_result_bytes(result)


def _request_id(result: Mapping[str, object], label: str) -> str:
    request_id = result.get("request_id")
    if not isinstance(request_id, str) or re.fullmatch(r"req_[0-9a-f]{32}", request_id) is None:
        raise LocalE2EFixtureError(f"{label} request id is invalid")
    return request_id


def _require_audit_lifecycle(
    harness: LocalMCPHarness,
    *,
    request_id: str,
    profile: str,
    tool: str,
) -> None:
    events = harness.audit_events(request_id)
    event_types = tuple(str(event["event_type"]) for event in events)
    required = (
        "request_received",
        "policy_allowed",
        "execution_started",
        "execution_completed",
    )
    positions: list[int] = []
    for event_type in required:
        try:
            positions.append(event_types.index(event_type))
        except ValueError as exc:
            raise LocalE2EFixtureError(f"{tool} audit lifecycle is incomplete") from exc
    if positions != sorted(positions):
        raise LocalE2EFixtureError(f"{tool} audit lifecycle ordering is invalid")
    for event in events:
        if event["event_type"] in required and (
            event["profile"] != profile
            or event["host"] != "e2e-host"
            or event["tool"] != tool
        ):
            raise LocalE2EFixtureError(f"{tool} audit identity metadata mismatch")


async def run_real_mcp_fixture() -> dict[str, object]:
    fixture = LocalE2EFixture.from_env()
    fixture.verify_filesystem_contract()

    async with LocalMCPHarness(fixture) as harness:
        async with harness.client("developer") as client:
            async with httpx2.AsyncClient(trust_env=False) as raw_client:
                missing = await raw_client.post(harness.mcp_url, json={})
                wrong = await raw_client.post(
                    harness.mcp_url,
                    json={},
                    headers={"Authorization": "Bearer definitely-wrong"},
                )
            if missing.status_code != 401 or wrong.status_code != 401:
                raise LocalE2EFixtureError("origin bearer did not fail closed")

            tools_result = await client.list_tools()
            tool_names = tuple(sorted(tool.name for tool in tools_result.tools))
            for required in ("hosts_list", "host_info", "ssh_exec"):
                if required not in tool_names:
                    raise LocalE2EFixtureError("required MCP tool is unavailable")

            listed = await client.call_tool("hosts_list", {})
            if listed.is_error or listed.structured_content is None:
                raise LocalE2EFixtureError("MCP host discovery failed")
            hosts = listed.structured_content.get("hosts")
            if not isinstance(hosts, list) or len(hosts) != 1:
                raise LocalE2EFixtureError("MCP host discovery returned unexpected inventory")
            host_summary = hosts[0]
            if not isinstance(host_summary, dict) or host_summary.get("alias") != "e2e-host":
                raise LocalE2EFixtureError("MCP host discovery alias mismatch")
            if set(host_summary) != {"alias", "labels", "capabilities"}:
                raise LocalE2EFixtureError("MCP host discovery exposed hidden metadata")

            info = await client.call_tool("host_info", {"alias": "e2e-host"})
            if info.is_error or info.structured_content is None:
                raise LocalE2EFixtureError("MCP host info failed")
            if set(info.structured_content) != {"alias", "labels", "capabilities"}:
                raise LocalE2EFixtureError("MCP host info exposed hidden metadata")
            if info.structured_content.get("alias") != "e2e-host":
                raise LocalE2EFixtureError("MCP host info alias mismatch")

            executed = await client.call_tool(
                "ssh_exec",
                {
                    "host": "e2e-host",
                    "executable": "/usr/bin/python3",
                    "args": ["-I", "-S", str(fixture.state_script)],
                    "cwd": str(fixture.work_dir),
                    "env": {},
                    "stdin": "",
                    "timeout_seconds": 10.0,
                },
            )
            if executed.is_error or executed.structured_content is None:
                raise LocalE2EFixtureError("MCP ssh_exec failed")
            result = executed.structured_content
            if result.get("host") != "e2e-host" or result.get("exit_status") != 0:
                raise LocalE2EFixtureError("MCP ssh_exec returned an unexpected outcome")
            request_id = result.get("request_id")
            if not isinstance(request_id, str) or re.fullmatch(r"req_[0-9a-f]{32}", request_id) is None:
                raise LocalE2EFixtureError("MCP request id is invalid")
            stdout_base64 = result.get("stdout_base64")
            if not isinstance(stdout_base64, str):
                raise LocalE2EFixtureError("MCP ssh_exec stdout is invalid")
            try:
                state = json.loads(base64.b64decode(stdout_base64, validate=True).decode("utf-8"))
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                raise LocalE2EFixtureError("MCP workload state output is invalid") from exc
            workload_state = _validate_workload_state(
                state,
                fixture,
                expected_request_id=request_id,
            )

        events = harness.audit_events(request_id)
        event_types = tuple(str(event["event_type"]) for event in events)
        required_events = (
            "request_received",
            "policy_allowed",
            "execution_started",
            "execution_completed",
        )
        positions: list[int] = []
        for event_type in required_events:
            try:
                positions.append(event_types.index(event_type))
            except ValueError as exc:
                raise LocalE2EFixtureError("MCP audit lifecycle is incomplete") from exc
        if positions != sorted(positions):
            raise LocalE2EFixtureError("MCP audit lifecycle ordering is invalid")
        for event in events:
            if (
                event["event_type"] in required_events
                and (
                    event["profile"] != "developer"
                    or event["host"] != "e2e-host"
                    or event["tool"] != "ssh_exec"
                )
            ):
                raise LocalE2EFixtureError("MCP audit identity metadata mismatch")

        return {
            "missing_bearer_status": missing.status_code,
            "wrong_bearer_status": wrong.status_code,
            "tools": list(tool_names),
            "hosts": [str(host_summary["alias"])],
            "host_alias": str(info.structured_content["alias"]),
            "request_id": request_id,
            "workload_state": workload_state,
            "audit_event_types": list(event_types),
        }


async def run_real_filesystem_profile_fixture() -> dict[str, object]:
    fixture = LocalE2EFixture.from_env()
    fixture.verify_filesystem_contract()

    transcript_parts: list[bytes] = []
    audit_checks: list[tuple[str, str, str]] = []

    async with LocalMCPHarness(fixture) as harness:
        async with harness.client("developer") as client:
            tools = await client.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            for required in ("fs_stat", "fs_read", "fs_mkdir", "fs_write"):
                if required not in tool_names:
                    raise LocalE2EFixtureError("filesystem MCP tool is unavailable")

            stat_result = await client.call_tool(
                "fs_stat",
                {"host": "e2e-host", "path": str(FS_SEED_FILE)},
            )
            transcript_parts.append(_tool_result_bytes(stat_result))
            stat_data = _require_tool_success(stat_result, "developer fs_stat")
            if (
                stat_data.get("path") != str(FS_SEED_FILE)
                or stat_data.get("kind") != "regular"
                or stat_data.get("size") != len(FS_SEED_BYTES)
                or stat_data.get("uid") != fixture.host_uid
                or stat_data.get("gid") != fixture.host_gid
            ):
                raise LocalE2EFixtureError("developer fs_stat metadata mismatch")
            stat_request_id = _request_id(stat_data, "developer fs_stat")
            audit_checks.append((stat_request_id, "developer", "fs_stat"))

            seed_read_result = await client.call_tool(
                "fs_read",
                {
                    "host": "e2e-host",
                    "path": str(FS_SEED_FILE),
                    "max_bytes": 4096,
                },
            )
            transcript_parts.append(_tool_result_bytes(seed_read_result))
            seed_read = _require_tool_success(seed_read_result, "developer fs_read")
            seed_encoded = seed_read.get("data_base64")
            if not isinstance(seed_encoded, str):
                raise LocalE2EFixtureError("developer fs_read data is invalid")
            try:
                seed_bytes = base64.b64decode(seed_encoded, validate=True)
            except (ValueError, UnicodeError) as exc:
                raise LocalE2EFixtureError("developer fs_read data is malformed") from exc
            if seed_bytes != FS_SEED_BYTES:
                raise LocalE2EFixtureError("developer fs_read data mismatch")
            seed_request_id = _request_id(seed_read, "developer fs_read")
            audit_checks.append((seed_request_id, "developer", "fs_read"))

            mkdir_result = await client.call_tool(
                "fs_mkdir",
                {"host": "e2e-host", "path": str(FS_MKDIR_TARGET)},
            )
            transcript_parts.append(_tool_result_bytes(mkdir_result))
            mkdir_data = _require_tool_success(mkdir_result, "developer fs_mkdir")
            if mkdir_data.get("path") != str(FS_MKDIR_TARGET):
                raise LocalE2EFixtureError("developer fs_mkdir path mismatch")
            mkdir_request_id = _request_id(mkdir_data, "developer fs_mkdir")
            audit_checks.append((mkdir_request_id, "developer", "fs_mkdir"))

            mkdir_replay = await client.call_tool(
                "fs_mkdir",
                {"host": "e2e-host", "path": str(FS_MKDIR_TARGET)},
            )
            transcript_parts.append(_require_tool_error(mkdir_replay, "fs_mkdir replay"))

            write_result = await client.call_tool(
                "fs_write",
                {
                    "host": "e2e-host",
                    "path": str(FS_WRITE_TARGET),
                    "data_base64": base64.b64encode(FS_WRITE_BYTES).decode("ascii"),
                },
            )
            transcript_parts.append(_tool_result_bytes(write_result))
            write_data = _require_tool_success(write_result, "developer fs_write")
            if write_data.get("path") != str(FS_WRITE_TARGET):
                raise LocalE2EFixtureError("developer fs_write path mismatch")
            write_request_id = _request_id(write_data, "developer fs_write")
            audit_checks.append((write_request_id, "developer", "fs_write"))

            created_read_result = await client.call_tool(
                "fs_read",
                {
                    "host": "e2e-host",
                    "path": str(FS_WRITE_TARGET),
                    "max_bytes": 4096,
                },
            )
            transcript_parts.append(_tool_result_bytes(created_read_result))
            created_read = _require_tool_success(created_read_result, "created file fs_read")
            created_encoded = created_read.get("data_base64")
            if not isinstance(created_encoded, str):
                raise LocalE2EFixtureError("created file data is invalid")
            write_bytes = base64.b64decode(created_encoded, validate=True)
            if write_bytes != FS_WRITE_BYTES:
                raise LocalE2EFixtureError("created file data mismatch")
            created_read_request_id = _request_id(created_read, "created file fs_read")
            audit_checks.append((created_read_request_id, "developer", "fs_read"))

            write_replay = await client.call_tool(
                "fs_write",
                {
                    "host": "e2e-host",
                    "path": str(FS_WRITE_TARGET),
                    "data_base64": base64.b64encode(b"replacement-must-not-commit\n").decode("ascii"),
                },
            )
            transcript_parts.append(_require_tool_error(write_replay, "fs_write replay"))

            unchanged_result = await client.call_tool(
                "fs_read",
                {
                    "host": "e2e-host",
                    "path": str(FS_WRITE_TARGET),
                    "max_bytes": 4096,
                },
            )
            transcript_parts.append(_tool_result_bytes(unchanged_result))
            unchanged = _require_tool_success(unchanged_result, "post-replay fs_read")
            unchanged_encoded = unchanged.get("data_base64")
            if not isinstance(unchanged_encoded, str):
                raise LocalE2EFixtureError("post-replay data is invalid")
            if base64.b64decode(unchanged_encoded, validate=True) != FS_WRITE_BYTES:
                raise LocalE2EFixtureError("fs_write replay changed existing content")

        async with harness.client("readonly") as client:
            readonly_read_result = await client.call_tool(
                "fs_read",
                {
                    "host": "e2e-host",
                    "path": str(FS_SEED_FILE),
                    "max_bytes": 4096,
                },
            )
            transcript_parts.append(_tool_result_bytes(readonly_read_result))
            readonly_read = _require_tool_success(readonly_read_result, "readonly fs_read")
            readonly_encoded = readonly_read.get("data_base64")
            if not isinstance(readonly_encoded, str):
                raise LocalE2EFixtureError("readonly fs_read data is invalid")
            readonly_bytes = base64.b64decode(readonly_encoded, validate=True)
            if readonly_bytes != FS_SEED_BYTES:
                raise LocalE2EFixtureError("readonly fs_read data mismatch")
            readonly_request_id = _request_id(readonly_read, "readonly fs_read")
            audit_checks.append((readonly_request_id, "readonly", "fs_read"))

            readonly_mutation = await client.call_tool(
                "fs_write",
                {
                    "host": "e2e-host",
                    "path": str(FS_WRITE_TARGET),
                    "data_base64": base64.b64encode(b"readonly-must-not-write\n").decode("ascii"),
                },
            )
            readonly_error = _require_tool_error(
                readonly_mutation,
                "readonly fs_write",
            )
            transcript_parts.append(readonly_error)
            if b"request denied by central policy" not in readonly_error:
                raise LocalE2EFixtureError("readonly mutation was not centrally denied")

            profile_override = await client.call_tool(
                "fs_read",
                {
                    "host": "e2e-host",
                    "path": str(FS_SEED_FILE),
                    "max_bytes": 4096,
                    "profile": "developer",
                },
            )
            profile_override_error = _require_tool_error(
                profile_override,
                "filesystem profile override",
            )
            transcript_parts.append(profile_override_error)

        async with harness.client("developer") as client:
            final_read_result = await client.call_tool(
                "fs_read",
                {
                    "host": "e2e-host",
                    "path": str(FS_WRITE_TARGET),
                    "max_bytes": 4096,
                },
            )
            transcript_parts.append(_tool_result_bytes(final_read_result))
            final_read = _require_tool_success(final_read_result, "final developer fs_read")
            final_encoded = final_read.get("data_base64")
            if not isinstance(final_encoded, str):
                raise LocalE2EFixtureError("final developer fs_read data is invalid")
            if base64.b64decode(final_encoded, validate=True) != FS_WRITE_BYTES:
                raise LocalE2EFixtureError("readonly deployment affected developer data")

        for request_id, profile, tool in audit_checks:
            _require_audit_lifecycle(
                harness,
                request_id=request_id,
                profile=profile,
                tool=tool,
            )

        transcript_blob = b"\n".join(transcript_parts)
        ledger_blob = harness.ledger_storage_bytes()
        log_blob = harness.captured_logs()
        for secret in harness.secret_sentinels():
            if secret in transcript_blob or secret in ledger_blob or secret in log_blob:
                raise LocalE2EFixtureError("secret retention scan failed")
        if FS_WRITE_BYTES in ledger_blob or FS_WRITE_BYTES in log_blob:
            raise LocalE2EFixtureError("filesystem body leaked into audit or logs")

        return {
            "seed_bytes": seed_bytes,
            "mkdir_created": True,
            "mkdir_replay_denied": True,
            "write_bytes": write_bytes,
            "write_replay_denied": True,
            "readonly_read": readonly_bytes,
            "readonly_mutation_denied": True,
            "profile_override_rejected": True,
            "profile_evidence": {
                "developer": {"profile": "developer"},
                "readonly": {"profile": "readonly"},
            },
            "audit_verified": True,
            "secret_retention_clean": True,
        }


def _last_audit_rowid(harness: LocalMCPHarness) -> int:
    rows = harness.audit_rows()
    if not rows:
        return 0
    rowid = rows[-1].get("rowid")
    if not isinstance(rowid, int):
        raise LocalE2EFixtureError("audit row id is invalid")
    return rowid


def _audit_events_since(
    harness: LocalMCPHarness,
    rowid: int,
) -> tuple[dict[str, object], ...]:
    return tuple(
        row
        for row in harness.audit_rows()
        if isinstance(row.get("rowid"), int) and int(row["rowid"]) > rowid
    )


def _single_request_event_types(
    rows: tuple[dict[str, object], ...],
    label: str,
) -> tuple[str, ...]:
    request_ids = {
        str(row["request_id"])
        for row in rows
        if row.get("tool") == "ssh_exec" and isinstance(row.get("request_id"), str)
    }
    if len(request_ids) != 1:
        raise LocalE2EFixtureError(f"{label} audit request identity is ambiguous")
    request_id = next(iter(request_ids))
    return tuple(
        str(row["event_type"])
        for row in rows
        if row.get("request_id") == request_id
    )


async def run_real_fail_closed_fixture() -> dict[str, object]:
    fixture = LocalE2EFixture.from_env()
    fixture.verify_filesystem_contract()

    marker_initial = EXEC_MARKER.read_bytes()
    if marker_initial:
        raise LocalE2EFixtureError("fail-closed execution marker is not empty")

    safe_blobs: list[bytes] = []
    async with LocalMCPHarness(fixture) as harness:
        # Origin bearer rejection must happen before any execution path.
        async with harness.client("developer") as client:
            del client
            ssh_before = SSHD_LOG.stat().st_size
            marker_before = EXEC_MARKER.read_bytes()
            audit_before = _last_audit_rowid(harness)
            wrong_origin = b"e2e-origin-wrong-secret"
            async with httpx2.AsyncClient(trust_env=False) as raw_client:
                missing = await raw_client.post(harness.mcp_url, json={})
                wrong = await raw_client.post(
                    harness.mcp_url,
                    json={},
                    headers={
                        "Authorization": "Bearer " + wrong_origin.decode("ascii")
                    },
                )
            safe_blobs.extend((missing.content, wrong.content))
            if missing.status_code != 401 or wrong.status_code != 401:
                raise LocalE2EFixtureError("origin authentication did not reject early")
            if wrong_origin in missing.content or wrong_origin in wrong.content:
                raise LocalE2EFixtureError("origin rejection echoed bearer material")
            if wrong_origin in harness.captured_logs():
                raise LocalE2EFixtureError("origin rejection logged bearer material")
            origin_rows = _audit_events_since(harness, audit_before)
            if any(
                row.get("event_type") == "execution_started"
                for row in origin_rows
            ):
                raise LocalE2EFixtureError("origin rejection reached execution audit")
            if SSHD_LOG.stat().st_size != ssh_before:
                raise LocalE2EFixtureError("origin rejection reached SSH")
            if EXEC_MARKER.read_bytes() != marker_before:
                raise LocalE2EFixtureError("origin rejection mutated workload marker")

        marker_args = {
            "host": "e2e-host",
            "executable": "/usr/bin/python3",
            "args": ["-I", "-S", str(MARKER_SCRIPT)],
            "cwd": str(fixture.work_dir),
            "env": {},
            "stdin": "",
            "timeout_seconds": 10.0,
        }

        # Central deny must stop before SSH and before execution_started.
        async with harness.client("developer", "central_deny") as client:
            ssh_before = SSHD_LOG.stat().st_size
            marker_before = EXEC_MARKER.read_bytes()
            audit_before = _last_audit_rowid(harness)
            denied = await client.call_tool("ssh_exec", marker_args)
            denied_error = _require_tool_error(denied, "central deny")
            safe_blobs.append(denied_error)
            if b"request denied by central policy" not in denied_error:
                raise LocalE2EFixtureError("central denial was not generic")
            central_rows = _audit_events_since(harness, audit_before)
            central_events = _single_request_event_types(
                central_rows,
                "central deny",
            )
            if "policy_denied" not in central_events:
                raise LocalE2EFixtureError("central denial audit is missing")
            if "execution_started" in central_events:
                raise LocalE2EFixtureError("central denial started execution")
            if SSHD_LOG.stat().st_size != ssh_before:
                raise LocalE2EFixtureError("central denial reached SSH")
            if EXEC_MARKER.read_bytes() != marker_before:
                raise LocalE2EFixtureError("central denial mutated workload marker")

        # Central policy allows /usr/bin/false, but host-local policy has no rule
        # for it. The SSH session must occur and return the fixed remote deny.
        async with harness.client("developer", "remote_deny") as client:
            ssh_before = SSHD_LOG.stat().st_size
            marker_before = EXEC_MARKER.read_bytes()
            audit_before = _last_audit_rowid(harness)
            remote = await client.call_tool(
                "ssh_exec",
                {
                    "host": "e2e-host",
                    "executable": "/usr/bin/false",
                    "args": [],
                    "cwd": str(fixture.work_dir),
                    "env": {},
                    "stdin": "",
                    "timeout_seconds": 10.0,
                },
            )
            remote_data = _require_tool_success(remote, "host-local deny")
            if remote_data.get("exit_status") != 77:
                raise LocalE2EFixtureError("host-local denial status mismatch")
            remote_stderr = remote_data.get("stderr_base64")
            if not isinstance(remote_stderr, str):
                raise LocalE2EFixtureError("host-local denial stderr is invalid")
            try:
                remote_error = base64.b64decode(remote_stderr, validate=True)
            except (ValueError, UnicodeError) as exc:
                raise LocalE2EFixtureError(
                    "host-local denial stderr is malformed"
                ) from exc
            safe_blobs.append(remote_error)
            if b"ssh-over-mcp-host-agent: denied:" not in remote_error:
                raise LocalE2EFixtureError("host-local denial was not generic")
            remote_rows = _audit_events_since(harness, audit_before)
            remote_events = _single_request_event_types(
                remote_rows,
                "host-local deny",
            )
            if "execution_started" not in remote_events:
                raise LocalE2EFixtureError("host-local denial never reached SSH execution")
            if "remote_policy_denied" not in remote_events:
                raise LocalE2EFixtureError("host-local denial audit is missing")
            if SSHD_LOG.stat().st_size <= ssh_before:
                raise LocalE2EFixtureError("host-local denial did not reach SSH")
            if EXEC_MARKER.read_bytes() != marker_before:
                raise LocalE2EFixtureError("host-local denial mutated workload marker")

        # A server-owned but wrong pinned key must fail before ForceCommand.
        async with harness.client("developer", "wrong_host_key") as client:
            ssh_before = SSHD_LOG.stat().st_size
            marker_before = EXEC_MARKER.read_bytes()
            audit_before = _last_audit_rowid(harness)
            mismatch = await client.call_tool("ssh_exec", marker_args)
            mismatch_error = _require_tool_error(
                mismatch,
                "wrong host key",
            )
            safe_blobs.append(mismatch_error)
            if b"SSH host key verification failed" not in mismatch_error:
                raise LocalE2EFixtureError("host-key failure was not generic")
            host_key_rows = _audit_events_since(harness, audit_before)
            host_key_events = _single_request_event_types(
                host_key_rows,
                "wrong host key",
            )
            if "execution_started" not in host_key_events:
                raise LocalE2EFixtureError("host-key failure audit ordering is invalid")
            if "host_key_failure" not in host_key_events:
                raise LocalE2EFixtureError("host-key failure audit is missing")
            ssh_delta = SSHD_LOG.read_bytes()[ssh_before:]
            if b"Starting session: forced-command" in ssh_delta:
                raise LocalE2EFixtureError("host-key mismatch reached ForceCommand")
            if EXEC_MARKER.read_bytes() != marker_before:
                raise LocalE2EFixtureError("host-key mismatch mutated workload marker")

        true_key = fixture.host_key_line().encode("ascii")
        wrong_key = _host_key_line(WRONG_HOST_KEY_PUBLIC).encode("ascii")
        safe_blobs.append(harness.captured_logs())
        for blob in safe_blobs:
            if true_key in blob or wrong_key in blob:
                raise LocalE2EFixtureError("raw host-key material leaked to client")
        if EXEC_MARKER.read_bytes() != marker_initial:
            raise LocalE2EFixtureError("fail-closed scenarios mutated workload marker")

        return {
            "origin_auth_rejected_early": True,
            "central_deny_before_ssh": True,
            "host_local_deny_after_ssh": True,
            "wrong_host_key_before_forcecommand": True,
            "marker_unchanged": True,
            "safe_errors": True,
        }


def _approval_id_from_error(error: bytes, label: str) -> str:
    match = _APPROVAL_ID_RE.search(error)
    if match is None:
        raise LocalE2EFixtureError(f"{label} approval id is missing")
    return match.group(1).decode("ascii")


def _control_fd() -> int:
    raw = os.environ.get(CONTROL_FD_ENV, "")
    try:
        value = int(raw, 10)
    except ValueError:
        raise LocalE2EFixtureError("Task 7 control fd is invalid") from None
    if value <= 2:
        raise LocalE2EFixtureError("Task 7 control fd is invalid")
    return value


async def _grant_approval_via_cli(
    approvalctl: Path,
    approval_id: str,
    admin_env: Mapping[str, str],
) -> tuple[bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        str(approvalctl),
        "grant",
        approval_id,
        env=dict(admin_env),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise LocalE2EFixtureError("approvalctl grant timed out") from exc
    if process.returncode != 0:
        raise LocalE2EFixtureError("approvalctl grant failed")
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LocalE2EFixtureError("approvalctl output is invalid") from exc
    if payload.get("state") != "granted":
        raise LocalE2EFixtureError("approval CLI did not grant request")
    return stdout, stderr


async def run_real_approval_outage_containment_fixture() -> dict[str, object]:
    fixture = LocalE2EFixture.from_env()
    fixture.verify_filesystem_contract()
    if APPROVAL_MARKER.read_bytes() != b"":
        raise LocalE2EFixtureError("approval marker is not empty")
    if EXEC_MARKER.read_bytes() != b"":
        raise LocalE2EFixtureError("execution marker is not empty")

    approval_request = {
        "host": "e2e-host",
        "executable": "/usr/bin/python3",
        "args": ["-I", "-S", str(APPROVAL_SCRIPT)],
        "cwd": str(fixture.work_dir),
        "env": {},
        "stdin": "task7-stdin-sensitive-v1",
        "timeout_seconds": 10.0,
    }
    state_request = {
        "host": "e2e-host",
        "executable": "/usr/bin/python3",
        "args": ["-I", "-S", str(fixture.state_script)],
        "cwd": str(fixture.work_dir),
        "env": {},
        "stdin": "",
        "timeout_seconds": 10.0,
    }
    task7_secrets = (
        b"task7-stdin-sensitive-v1",
        b"task7-env-sensitive-v1",
        b"task7-argv-sensitive-v1",
    )
    safe_blobs: list[bytes] = []

    async with LocalMCPHarness(fixture) as harness:
        async with harness.client("developer", "approval") as client:
            tool_names = {tool.name for tool in (await client.list_tools()).tools}
            if "approval_status" not in tool_names:
                raise LocalE2EFixtureError("approval status tool is unavailable")
            if tool_names.intersection(
                {"approval_grant", "approval_deny", "grant", "deny"}
            ):
                raise LocalE2EFixtureError("MCP surface exposes approval mutation")

            ssh_before = SSHD_LOG.stat().st_size
            pending = await client.call_tool("ssh_exec", approval_request)
            pending_error = _require_tool_error(pending, "approval pending")
            safe_blobs.append(pending_error)
            approval_id = _approval_id_from_error(pending_error, "approval pending")
            if b"approval required" not in pending_error or b"state=pending" not in pending_error:
                raise LocalE2EFixtureError("approval request did not become pending")
            if APPROVAL_MARKER.read_bytes() != b"" or SSHD_LOG.stat().st_size != ssh_before:
                raise LocalE2EFixtureError("pending approval reached SSH or workload")

            pending_status = await client.call_tool(
                "approval_status",
                {"approval_id": approval_id},
            )
            pending_data = _require_tool_success(pending_status, "approval_status pending")
            if pending_data.get("state") != "pending":
                raise LocalE2EFixtureError("approval state is not pending")

            settings = harness._require_ledger_settings()
            approvalctl = Path(sys.executable).with_name("ssh-over-mcp-approvalctl")
            admin_env = {
                "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": str(
                    settings.admin_socket_path
                ),
                "SSH_OVER_MCP_LEDGER_SERVICE_UID": str(settings.service_uid),
                "SSH_OVER_MCP_LEDGER_SERVICE_GID": str(settings.service_gid),
            }
            granted_stdout, granted_stderr = await _grant_approval_via_cli(
                approvalctl,
                approval_id,
                admin_env,
            )
            safe_blobs.extend((granted_stdout, granted_stderr))

            exact_retry = dict(approval_request)
            exact_retry["approval_id"] = approval_id
            executed = await client.call_tool("ssh_exec", exact_retry)
            safe_blobs.append(_tool_result_bytes(executed))
            executed_data = _require_tool_success(executed, "approved execution")
            if executed_data.get("exit_status") != 0:
                raise LocalE2EFixtureError("approved execution did not succeed")
            if APPROVAL_MARKER.read_bytes() != b"1":
                raise LocalE2EFixtureError("approved marker side effect mismatch")

            consumed = await client.call_tool(
                "approval_status",
                {"approval_id": approval_id},
            )
            consumed_data = _require_tool_success(consumed, "approval_status consumed")
            if consumed_data.get("state") != "consumed":
                raise LocalE2EFixtureError("approval was not consumed")

            replay = await client.call_tool("ssh_exec", exact_retry)
            replay_error = _require_tool_error(replay, "approval replay")
            safe_blobs.append(replay_error)
            replacement_id = _approval_id_from_error(replay_error, "approval replay")
            if replacement_id == approval_id or APPROVAL_MARKER.read_bytes() != b"1":
                raise LocalE2EFixtureError("approval replay was not single-use")

            replay_stdout, replay_stderr = await _grant_approval_via_cli(
                approvalctl,
                replacement_id,
                admin_env,
            )
            safe_blobs.extend((replay_stdout, replay_stderr))

            mutation = dict(approval_request)
            mutation["args"] = [
                "-I",
                "-S",
                str(APPROVAL_SCRIPT),
                "task7-argv-sensitive-v1",
            ]
            mutation["env"] = {"E2E_SECRET": "task7-env-sensitive-v1"}
            mutation["approval_id"] = replacement_id
            mutation_ssh_before = SSHD_LOG.stat().st_size
            mismatch = await client.call_tool("ssh_exec", mutation)
            mismatch_error = _require_tool_error(mismatch, "approval binding mismatch")
            safe_blobs.append(mismatch_error)
            mismatch_id = _approval_id_from_error(
                mismatch_error,
                "approval binding mismatch",
            )
            if mismatch_id == replacement_id:
                raise LocalE2EFixtureError("approval binding mismatch reused old approval")
            if APPROVAL_MARKER.read_bytes() != b"1":
                raise LocalE2EFixtureError("approval binding mismatch executed workload")
            if SSHD_LOG.stat().st_size != mutation_ssh_before:
                raise LocalE2EFixtureError("approval binding mismatch reached SSH")
            old_status = await client.call_tool(
                "approval_status",
                {"approval_id": replacement_id},
            )
            old_status_data = _require_tool_success(
                old_status,
                "approval_status binding base",
            )
            if old_status_data.get("state") != "granted":
                raise LocalE2EFixtureError("binding mismatch consumed old approval")

        async with harness.client("developer") as client:
            base_url = harness.mcp_url.removesuffix("/mcp")
            ssh_before = SSHD_LOG.stat().st_size
            approval_before = APPROVAL_MARKER.read_bytes()
            exec_before = EXEC_MARKER.read_bytes()
            harness.stop_ledger()
            async with httpx2.AsyncClient(trust_env=False) as raw_client:
                health = await raw_client.get(base_url + "/healthz")
                ready = await raw_client.get(base_url + "/readyz")
            safe_blobs.extend((health.content, ready.content))
            if health.status_code != 200 or health.json() != {"status": "ok"}:
                raise LocalE2EFixtureError("/healthz failed during Ledger outage")
            if ready.status_code != 503 or ready.json() != {"status": "not_ready"}:
                raise LocalE2EFixtureError("/readyz did not fail closed")
            outage = await client.call_tool("ssh_exec", state_request)
            outage_error = _require_tool_error(outage, "Ledger outage execution")
            safe_blobs.append(outage_error)
            if b"audit persistence failed" not in outage_error:
                raise LocalE2EFixtureError("Ledger outage error was not generic")
            if SSHD_LOG.stat().st_size != ssh_before:
                raise LocalE2EFixtureError("Ledger outage reached SSH")
            if (
                APPROVAL_MARKER.read_bytes() != approval_before
                or EXEC_MARKER.read_bytes() != exec_before
            ):
                raise LocalE2EFixtureError("Ledger outage mutated workload state")

        safe_blobs.extend(
            (
                harness.ledger_storage_bytes(),
                harness.captured_logs(),
                SSHD_LOG.read_bytes(),
            )
        )
        for secret in (*harness.secret_sentinels(), *task7_secrets):
            if any(secret in blob for blob in safe_blobs):
                raise LocalE2EFixtureError("Task 7 secret retention scan failed")

    async with LocalMCPHarness(fixture) as harness:
        async with harness.client("developer") as client:
            # STOP_MANAGER is deliberately the final execution fault in the probe.
            control_fd = _control_fd()
            with socket.socket(fileno=os.dup(control_fd)) as control:
                control.settimeout(3.0)
                control.sendall(b"STOP_MANAGER\n")
                response = control.recv(16)
            if response != b"OK\n":
                raise LocalE2EFixtureError("Task 7 manager-stop response is invalid")

            marker_before = APPROVAL_MARKER.read_bytes()
            exec_before = EXEC_MARKER.read_bytes()
            audit_before = _last_audit_rowid(harness)
            unavailable = await client.call_tool("ssh_exec", state_request)
            unavailable_blob = _tool_result_bytes(unavailable)
            safe_blobs = [unavailable_blob]
            unavailable_data = _require_tool_success(
                unavailable,
                "containment unavailable execution",
            )
            if unavailable_data.get("exit_status") != 69:
                raise LocalE2EFixtureError("containment failure status mismatch")
            if unavailable_data.get("stdout_base64") not in {"", None}:
                raise LocalE2EFixtureError("containment failure exposed stdout")
            stderr_base64 = unavailable_data.get("stderr_base64")
            if not isinstance(stderr_base64, str):
                raise LocalE2EFixtureError("containment failure stderr is invalid")
            try:
                stderr = base64.b64decode(stderr_base64, validate=True)
            except (ValueError, UnicodeError) as exc:
                raise LocalE2EFixtureError("containment failure stderr is malformed") from exc
            if stderr != b"ssh-over-mcp-host-agent: execution failed\n":
                raise LocalE2EFixtureError("containment failure was not generic")
            if b"containment.sock" in unavailable_blob or b"manager" in stderr.lower():
                raise LocalE2EFixtureError("containment internals leaked through MCP")

            rows = _audit_events_since(harness, audit_before)
            request_ids = {
                str(row["request_id"])
                for row in rows
                if row.get("tool") == "ssh_exec"
                and isinstance(row.get("request_id"), str)
            }
            if len(request_ids) != 1:
                raise LocalE2EFixtureError("containment failure request id is ambiguous")
            request_id = next(iter(request_ids))
            cgroup = fixture.cgroup_root / f"ssh-over-mcp-{request_id}"
            if cgroup.exists():
                raise LocalE2EFixtureError("containment failure leaked request cgroup")
            if (
                APPROVAL_MARKER.read_bytes() != marker_before
                or EXEC_MARKER.read_bytes() != exec_before
            ):
                raise LocalE2EFixtureError("containment failure executed workload")

        safe_blobs.extend(
            (
                harness.ledger_storage_bytes(),
                harness.captured_logs(),
                SSHD_LOG.read_bytes(),
            )
        )
        for secret in (*harness.secret_sentinels(), *task7_secrets):
            if any(secret in blob for blob in safe_blobs):
                raise LocalE2EFixtureError("final Task 7 secret retention scan failed")

    return {
        "approval_required_before_ssh": True,
        "approval_granted_via_cli": True,
        "approval_consumed": True,
        "approval_replay_denied": True,
        "approval_binding_mismatch_denied": True,
        "ledger_outage_not_ready": True,
        "ledger_outage_no_side_effect": True,
        "containment_unavailable_fail_closed": True,
        "request_cgroup_clean": True,
        "secret_retention_clean": True,
    }
