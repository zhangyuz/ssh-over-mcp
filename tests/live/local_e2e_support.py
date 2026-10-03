from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
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
        self._require_dir(self.work_dir, uid=0, mode=0o755)
        self._require_dir(self.cgroup_root, uid=self.manager_uid)
        # The host-source cgroup and manager socket are intentionally not
        # traversable by the zero-supplementary-group probe. The trusted root
        # gate verifies those privileged surfaces immediately before dropping
        # to the probe identity.

    def host_key_line(self) -> str:
        raw = self.host_key_public.read_text(encoding="ascii").strip()
        parts = raw.split()
        if len(parts) < 2:
            raise LocalE2EFixtureError("host public key is malformed")
        return f"{parts[0]} {parts[1]}"


def _validate_workload_state(
    state: object,
    fixture: LocalE2EFixture,
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

    cgroup = state.get("cgroup")
    expected_cgroup = (
        f"/ssh-over-mcp-e2e/ssh-over-mcp-{_REQUEST_ID}"
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
    return _validate_workload_state(state, fixture)

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
        if policy_variant != "normal":
            raise LocalE2EFixtureError("unsupported local E2E policy variant")
        return {
            "inventory": {
                "hosts": {
                    "e2e-host": {
                        "address": self.fixture.host,
                        "port": self.fixture.port,
                        "ssh_user": self.fixture.ssh_user,
                        "credential_ref": "e2e-client",
                        "host_key": self.fixture.host_key_line(),
                        "labels": ["e2e"],
                        "allowed_roles": ["developer", "readonly"],
                    }
                }
            },
            "policy": {
                "version": 1,
                "default": "deny",
                "roles": {
                    "developer": {},
                    "readonly": {},
                },
                "rules": [
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
                    }
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
            workload_state = _validate_workload_state(state, fixture)

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
