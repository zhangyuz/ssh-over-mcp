from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.ssh.connection import SSHConnectionManager
from ssh_over_mcp.ssh.credentials import FileCredentialProvider
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits, encode_request
from ssh_over_mcp.ssh.transport import StructuredSSHTransport

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
        self._require_dir(self.host_source_cgroup, uid=self.manager_uid)

        try:
            info = self.manager_endpoint.lstat()
        except OSError as exc:
            raise LocalE2EFixtureError("manager endpoint is absent") from exc
        if not stat.S_ISSOCK(info.st_mode):
            raise LocalE2EFixtureError("manager endpoint is not a Unix socket")
        if (
            info.st_uid != self.manager_uid
            or info.st_gid != self.manager_client_gid
            or stat.S_IMODE(info.st_mode) != 0o660
        ):
            raise LocalE2EFixtureError("manager endpoint identity/mode mismatch")

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

    if (
        result.exit_status != 0
        or result.exit_signal is not None
        or result.timed_out
        or result.truncated
        or result.stderr
    ):
        raise LocalE2EFixtureError(
            "real structured SSH fixture did not complete successfully"
        )

    try:
        state = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LocalE2EFixtureError("workload state output is invalid") from exc
    return _validate_workload_state(state, fixture)
