from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _REPO_ROOT / "deploy" / "compose" / "compose.yaml"
_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_COMPOSE") == "1"
_IMAGE = os.environ.get("SSH_OVER_MCP_COMPOSE_IMAGE", "")

pytestmark = pytest.mark.skipif(
    not _RUN_LIVE,
    reason="set SSH_OVER_MCP_RUN_LIVE_COMPOSE=1 for the live Compose probe",
)


@dataclass(frozen=True)
class ComposeFixture:
    project: str
    env_file: Path
    config_file: Path
    credential_map_file: Path
    ssh_secrets_dir: Path
    origin_bearer_file: Path

    def command(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--project-name",
            self.project,
            "--env-file",
            str(self.env_file),
            "-f",
            str(_COMPOSE_FILE),
            *args,
        ]


def _run(
    args: list[str],
    *,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
    )


def _require_success(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 0, (
        f"command failed ({result.returncode}): {' '.join(result.args)}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    return result.stdout


@pytest.fixture(scope="module")
def compose_fixture(
    tmp_path_factory: pytest.TempPathFactory,
    request: pytest.FixtureRequest,
) -> ComposeFixture:
    assert _IMAGE, "SSH_OVER_MCP_COMPOSE_IMAGE is required for live Compose probe"
    root = tmp_path_factory.mktemp("phase6b-compose")
    config_file = root / "config.yaml"
    credential_map_file = root / "credentials.yaml"
    ssh_secrets_dir = root / "ssh"
    ssh_secrets_dir.mkdir()
    ssh_key = ssh_secrets_dir / "dev01.key"
    origin_bearer_file = root / "origin-bearer"
    env_file = root / "compose.env"

    config_file.write_text(
        """
inventory:
  hosts:
    dev01:
      address: 192.0.2.10
      port: 22
      ssh_user: test-user
      credential_ref: secret://dev01
      host_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly
      allowed_roles: [developer]
policy:
  version: 1
  default: deny
  roles:
    developer: {}
  rules: []
""".lstrip(),
        encoding="utf-8",
    )
    credential_map_file.write_text(
        'credentials:\n  "secret://dev01": "/run/secrets/ssh/dev01.key"\n',
        encoding="utf-8",
    )
    ssh_key.write_text("test-private-key-placeholder", encoding="utf-8")
    origin_bearer_file.write_bytes(b"compose-origin-token-phase6b")
    env_file.write_text(
        "\n".join(
            [
                f"SSH_OVER_MCP_IMAGE={_IMAGE}",
                "SSH_OVER_MCP_PROFILE=developer",
                f"SSH_OVER_MCP_CONFIG_FILE={config_file}",
                f"SSH_OVER_MCP_CREDENTIAL_MAP_FILE={credential_map_file}",
                f"SSH_OVER_MCP_SSH_SECRETS_DIR={ssh_secrets_dir}",
                f"SSH_OVER_MCP_ORIGIN_BEARER_FILE={origin_bearer_file}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    fixture = ComposeFixture(
        project=f"som6b{os.getpid()}",
        env_file=env_file,
        config_file=config_file,
        credential_map_file=credential_map_file,
        ssh_secrets_dir=ssh_secrets_dir,
        origin_bearer_file=origin_bearer_file,
    )

    def cleanup() -> None:
        _run(
            fixture.command(
                "--profile",
                "admin",
                "down",
                "-v",
                "--remove-orphans",
            )
        )

    request.addfinalizer(cleanup)
    return fixture


def test_resolved_compose_preserves_security_contract(
    compose_fixture: ComposeFixture,
) -> None:
    rendered = _require_success(
        _run(compose_fixture.command("--profile", "admin", "config", "--format", "json"))
    )
    document = json.loads(rendered)
    services = document["services"]

    assert set(services) == {"ledger-init", "ledger", "mcp", "approvalctl"}
    for service in services.values():
        assert not service.get("ports")
        assert service.get("privileged") is not True
        assert service.get("read_only") is True
        assert service.get("cap_drop") == ["ALL"]
        assert service.get("security_opt") == ["no-new-privileges:true"]
        environment = service.get("environment", {})
        rendered_environment = json.dumps(environment, sort_keys=True)
        assert "CF-Access-Client-Secret" not in rendered_environment
        assert "TUNNEL_TOKEN" not in rendered_environment

    assert services["ledger-init"]["user"] == "0:0"
    assert services["ledger-init"]["network_mode"] == "none"
    assert services["ledger-init"]["cap_add"] == ["CHOWN", "DAC_OVERRIDE"]
    assert services["ledger"]["user"] == "10002:10002"
    assert services["ledger"]["group_add"] == ["10003", "10005"]
    assert services["ledger"]["network_mode"] == "none"
    assert services["mcp"]["user"] == "10001:10003"
    assert set(services["mcp"]["networks"]) == {"origin_internal", "ssh_egress"}
    assert services["approvalctl"]["user"] == "10004:10005"
    assert services["approvalctl"]["network_mode"] == "none"
    assert services["approvalctl"]["profiles"] == ["admin"]

    mcp_mounts = {item["target"]: item for item in services["mcp"]["volumes"]}
    assert set(mcp_mounts) == {
        "/etc/ssh-over-mcp/config.yaml",
        "/etc/ssh-over-mcp/credentials.yaml",
        "/run/secrets/ssh",
        "/run/secrets/origin-bearer",
        "/run/ssh-over-mcp-exec",
    }
    assert all(item["read_only"] is True for item in mcp_mounts.values())

    admin_mounts = {
        item["target"]: item for item in services["approvalctl"]["volumes"]
    }
    assert set(admin_mounts) == {"/run/ssh-over-mcp-admin"}
    assert admin_mounts["/run/ssh-over-mcp-admin"]["read_only"] is True


def _container_id(context: ComposeFixture, service: str, *, all_states: bool = False) -> str:
    args = ["ps"]
    if all_states:
        args.append("-a")
    args.extend(["-q", service])
    return _require_success(_run(context.command(*args))).strip()


def _inspect_container(container_id: str) -> dict:
    output = _require_success(_run(["docker", "inspect", container_id]))
    return json.loads(output)[0]


def _identity_snapshot(container_id: str) -> dict:
    code = r"""
import json
import os
from pathlib import Path

status = {}
for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        status[key] = value.strip()
print(json.dumps({
    "uid": os.getuid(),
    "gid": os.getgid(),
    "groups": os.getgroups(),
    "cap_eff": status["CapEff"],
    "no_new_privs": status["NoNewPrivs"],
}, sort_keys=True))
"""
    output = _require_success(
        _run(["docker", "exec", container_id, "python", "-c", code])
    )
    return json.loads(output)


@pytest.fixture(scope="module")
def started_compose(compose_fixture: ComposeFixture):
    result = _run(compose_fixture.command("up", "-d", "--wait", "mcp"))
    _require_success(result)
    try:
        yield compose_fixture
    finally:
        _run(compose_fixture.command("down", "-v", "--remove-orphans"))


def test_live_stack_bootstrap_and_runtime_security(
    started_compose: ComposeFixture,
) -> None:
    context = started_compose
    init_id = _container_id(context, "ledger-init", all_states=True)
    ledger_id = _container_id(context, "ledger")
    mcp_id = _container_id(context, "mcp")

    init = _inspect_container(init_id)
    ledger = _inspect_container(ledger_id)
    mcp = _inspect_container(mcp_id)

    assert init["State"]["Status"] == "exited"
    assert init["State"]["ExitCode"] == 0
    assert mcp["State"]["Health"]["Status"] == "healthy"

    ledger_identity = _identity_snapshot(ledger_id)
    mcp_identity = _identity_snapshot(mcp_id)
    assert (ledger_identity["uid"], ledger_identity["gid"]) == (10002, 10002)
    assert set(ledger_identity["groups"]) - {10002} == {10003, 10005}
    assert (mcp_identity["uid"], mcp_identity["gid"]) == (10001, 10003)
    assert ledger_identity["cap_eff"] == "0000000000000000"
    assert mcp_identity["cap_eff"] == "0000000000000000"
    assert ledger_identity["no_new_privs"] == "1"
    assert mcp_identity["no_new_privs"] == "1"

    host_config = init["HostConfig"]
    assert host_config["NetworkMode"] == "none"
    assert host_config["ReadonlyRootfs"] is True
    assert host_config["CapDrop"] == ["ALL"]
    assert {value.removeprefix("CAP_") for value in host_config["CapAdd"]} == {
        "CHOWN",
        "DAC_OVERRIDE",
    }

    data_mount = next(
        mount
        for mount in ledger["Mounts"]
        if mount["Destination"] == "/var/lib/ssh-over-mcp"
    )
    volume = data_mount["Name"]
    probe = r"""
import json
import os
import stat
from pathlib import Path

key = Path("/data/ledger/ledger.key")
db = Path("/data/ledger/ledger.db")
key_info = key.lstat()
db_info = db.lstat()
print(json.dumps({
    "key_len": len(key.read_bytes()),
    "key_uid": key_info.st_uid,
    "key_gid": key_info.st_gid,
    "key_mode": stat.S_IMODE(key_info.st_mode),
    "db_uid": db_info.st_uid,
    "db_gid": db_info.st_gid,
    "db_mode": stat.S_IMODE(db_info.st_mode),
}, sort_keys=True))
"""
    metadata = json.loads(
        _require_success(
            _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--user",
                    "0:0",
                    "-v",
                    f"{volume}:/data:ro",
                    _IMAGE,
                    "python",
                    "-c",
                    probe,
                ]
            )
        )
    )
    assert metadata == {
        "key_len": 32,
        "key_uid": 10002,
        "key_gid": 10002,
        "key_mode": 0o600,
        "db_uid": 10002,
        "db_gid": 10002,
        "db_mode": 0o600,
    }


_EXEC_PING = r"""
import asyncio
from pathlib import Path
from ssh_over_mcp.approvals.client import SecurityLedgerClient
from ssh_over_mcp.approvals.transport import UnixLedgerTransport
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy

client = SecurityLedgerClient(
    UnixLedgerTransport(
        Path("/run/ssh-over-mcp-exec/ledger/ledger.sock"),
        LinuxPeerCredentialPolicy(expected_uid=10002, expected_gid=10002),
    )
)
asyncio.run(client.ping())
"""


def _compose_run(
    context: ComposeFixture,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    return _run(context.command(*args))


def test_live_mount_network_and_socket_isolation(
    started_compose: ComposeFixture,
) -> None:
    context = started_compose
    ledger_id = _container_id(context, "ledger")
    mcp_id = _container_id(context, "mcp")
    ledger = _inspect_container(ledger_id)
    mcp = _inspect_container(mcp_id)

    mcp_mounts = {item["Destination"]: item for item in mcp["Mounts"]}
    assert "/var/lib/ssh-over-mcp" not in mcp_mounts
    assert "/run/ssh-over-mcp-admin" not in mcp_mounts
    assert mcp_mounts["/run/ssh-over-mcp-exec"]["RW"] is False

    assert ledger["HostConfig"]["NetworkMode"] == "none"
    assert set(mcp["NetworkSettings"]["Networks"]) == {
        f"{context.project}_origin_internal",
        f"{context.project}_ssh_egress",
    }
    assert not mcp["HostConfig"].get("PortBindings")

    port = _compose_run(context, "port", "mcp", "8000")
    assert port.stdout.strip() in {"", "invalid IP:0"}

    ping = _run(
        ["docker", "exec", mcp_id, "python", "-c", _EXEC_PING]
    )
    _require_success(ping)

    exec_write = _run(
        [
            "docker",
            "exec",
            mcp_id,
            "python",
            "-c",
            (
                "from pathlib import Path;"
                "Path('/run/ssh-over-mcp-exec/probe').write_text('x')"
            ),
        ]
    )
    assert exec_write.returncode != 0

    admin_list = _compose_run(
        context,
        "--profile",
        "admin",
        "run",
        "--rm",
        "approvalctl",
        "list",
    )
    _require_success(admin_list)
    json.loads(admin_list.stdout)

    admin_write = _compose_run(
        context,
        "--profile",
        "admin",
        "run",
        "--rm",
        "--entrypoint",
        "python",
        "approvalctl",
        "-c",
        (
            "from pathlib import Path;"
            "Path('/run/ssh-over-mcp-admin/probe').write_text('x')"
        ),
    )
    assert admin_write.returncode != 0


def test_live_ledger_rejects_wrong_peer_uid_with_allowed_socket_gid(
    started_compose: ComposeFixture,
) -> None:
    context = started_compose

    wrong_exec = _compose_run(
        context,
        "run",
        "--rm",
        "--no-deps",
        "--user",
        "10004:10003",
        "--entrypoint",
        "python",
        "mcp",
        "-c",
        _EXEC_PING,
    )
    assert wrong_exec.returncode != 0

    wrong_admin = _compose_run(
        context,
        "--profile",
        "admin",
        "run",
        "--rm",
        "--no-deps",
        "--user",
        "10001:10005",
        "approvalctl",
        "list",
    )
    assert wrong_admin.returncode != 0
    assert "Security Ledger approval command failed" in wrong_admin.stderr

    normal_exec = _compose_run(
        context,
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "python",
        "mcp",
        "-c",
        _EXEC_PING,
    )
    _require_success(normal_exec)

    normal_admin = _compose_run(
        context,
        "--profile",
        "admin",
        "run",
        "--rm",
        "--no-deps",
        "approvalctl",
        "list",
    )
    _require_success(normal_admin)


_CREATE_APPROVAL_AND_AUDIT = r"""
import asyncio
import json
from pathlib import Path

from ssh_over_mcp.approvals.binding import fingerprint_argv
from ssh_over_mcp.approvals.client import SecurityLedgerClient
from ssh_over_mcp.approvals.models import ApprovalBindingInput
from ssh_over_mcp.approvals.transport import UnixLedgerTransport
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy
from ssh_over_mcp.policy.models import RiskLevel

client = SecurityLedgerClient(
    UnixLedgerTransport(
        Path("/run/ssh-over-mcp-exec/ledger/ledger.sock"),
        LinuxPeerCredentialPolicy(expected_uid=10002, expected_gid=10002),
    )
)
binding = ApprovalBindingInput(
    principal_id="static:developer",
    profile="developer",
    host="dev01",
    tool="fs_mkdir",
    privilege="user",
    policy_version="sha256:compose-live",
    normalized_path="/srv/app/new",
    argv_count=0,
    argv_fingerprint=fingerprint_argv(()),
    effective_timeout_seconds=60.0,
    effective_max_output_bytes=4096,
)

async def main():
    status = await client.ensure_approval(
        binding=binding,
        risk=RiskLevel.HIGH,
        request_id="req_" + ("1" * 32),
    )
    event_id = await client.append_audit(
        AuditEventInput(
            event_type=AuditEventType.REQUEST_RECEIVED,
            request_id="req_" + ("2" * 32),
            principal_id="static:developer",
            profile="developer",
            host="dev01",
            tool="fs_mkdir",
            policy_version="sha256:compose-live",
            risk=RiskLevel.HIGH,
        )
    )
    print(json.dumps({"approval_id": status.approval_id, "event_id": event_id}))

asyncio.run(main())
"""


def _volume_name(
    context: ComposeFixture,
    service: str,
    destination: str,
    *,
    all_states: bool = False,
) -> str:
    container_id = _container_id(context, service, all_states=all_states)
    inspected = _inspect_container(container_id)
    mount = next(
        item
        for item in inspected["Mounts"]
        if item["Destination"] == destination
    )
    return str(mount["Name"])


def _ledger_data_metadata(context: ComposeFixture) -> dict:
    volume = _volume_name(
        context,
        "ledger",
        "/var/lib/ssh-over-mcp",
        all_states=True,
    )
    code = r"""
import hashlib
import json
import sqlite3
from pathlib import Path

root = Path("/data/ledger")
key = root / "ledger.key"
db = root / "ledger.db"
connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
try:
    audit_count = connection.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0]
    approval_count = connection.execute(
        "SELECT COUNT(*) FROM approvals"
    ).fetchone()[0]
finally:
    connection.close()
print(json.dumps({
    "key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
    "audit_count": audit_count,
    "approval_count": approval_count,
}, sort_keys=True))
"""
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "-v",
            f"{volume}:/data:ro",
            _IMAGE,
            "python",
            "-c",
            code,
        ]
    )
    return json.loads(_require_success(result))


def _readiness_status(mcp_id: str) -> int:
    code = r"""
import urllib.error
import urllib.request

try:
    response = urllib.request.urlopen(
        "http://127.0.0.1:8000/readyz",
        timeout=2,
    )
except urllib.error.HTTPError as exc:
    print(exc.code)
else:
    print(response.status)
"""
    result = _run(["docker", "exec", mcp_id, "python", "-c", code])
    return int(_require_success(result).strip())


def _wait_readiness(
    context: ComposeFixture,
    expected: int,
    *,
    timeout_seconds: float = 20.0,
) -> None:
    mcp_id = _container_id(context, "mcp")
    deadline = time.monotonic() + timeout_seconds
    last: int | None = None
    while time.monotonic() < deadline:
        try:
            last = _readiness_status(mcp_id)
        except (AssertionError, ValueError):
            last = None
        if last == expected:
            return
        time.sleep(0.25)
    raise AssertionError(
        f"MCP readiness did not become {expected}; last={last}"
    )


def test_live_restart_preserves_approval_and_audit_state(
    started_compose: ComposeFixture,
) -> None:
    context = started_compose
    mcp_id = _container_id(context, "mcp")
    created = json.loads(
        _require_success(
            _run(
                [
                    "docker",
                    "exec",
                    mcp_id,
                    "python",
                    "-c",
                    _CREATE_APPROVAL_AND_AUDIT,
                ]
            )
        )
    )
    approval_id = created["approval_id"]
    before = _ledger_data_metadata(context)

    listed_before = json.loads(
        _require_success(
            _compose_run(
                context,
                "--profile",
                "admin",
                "run",
                "--rm",
                "--no-deps",
                "approvalctl",
                "list",
            )
        )
    )
    assert [item["approval_id"] for item in listed_before].count(approval_id) == 1

    _require_success(_compose_run(context, "restart", "ledger"))
    _wait_readiness(context, 200)

    after = _ledger_data_metadata(context)
    assert after == before

    listed_after = json.loads(
        _require_success(
            _compose_run(
                context,
                "--profile",
                "admin",
                "run",
                "--rm",
                "--no-deps",
                "approvalctl",
                "list",
            )
        )
    )
    assert [item["approval_id"] for item in listed_after].count(approval_id) == 1

    shown = json.loads(
        _require_success(
            _compose_run(
                context,
                "--profile",
                "admin",
                "run",
                "--rm",
                "--no-deps",
                "approvalctl",
                "show",
                approval_id,
            )
        )
    )
    assert shown["approval_id"] == approval_id
    assert shown["state"] == "pending"


def _wait_container_stopped(
    context: ComposeFixture,
    service: str,
    *,
    timeout_seconds: float = 10.0,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last: dict | None = None
    while time.monotonic() < deadline:
        container_id = _container_id(context, service, all_states=True)
        last = _inspect_container(container_id)
        if not last["State"]["Running"]:
            return last
        time.sleep(0.2)
    raise AssertionError(f"{service} did not stop; last={last}")


def _write_stale_execution_endpoint(
    context: ComposeFixture,
    *,
    content: str,
) -> None:
    volume = _volume_name(
        context,
        "ledger",
        "/run/ssh-over-mcp-exec",
        all_states=True,
    )
    code = (
        "from pathlib import Path;"
        "p=Path('/data/ledger/ledger.sock');"
        "assert not p.exists();"
        f"p.write_text({content!r}, encoding='utf-8')"
    )
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "DAC_OVERRIDE",
            "-v",
            f"{volume}:/data",
            _IMAGE,
            "python",
            "-c",
            code,
        ]
    )
    _require_success(result)


def _read_stale_execution_endpoint(context: ComposeFixture) -> str:
    volume = _volume_name(
        context,
        "ledger",
        "/run/ssh-over-mcp-exec",
        all_states=True,
    )
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "-v",
            f"{volume}:/data:ro",
            _IMAGE,
            "python",
            "-c",
            (
                "from pathlib import Path;"
                "print(Path('/data/ledger/ledger.sock').read_text(encoding='utf-8'))"
            ),
        ]
    )
    return _require_success(result).strip()


def _remove_stale_execution_endpoint(context: ComposeFixture) -> None:
    volume = _volume_name(
        context,
        "ledger",
        "/run/ssh-over-mcp-exec",
        all_states=True,
    )
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "DAC_OVERRIDE",
            "-v",
            f"{volume}:/data",
            _IMAGE,
            "python",
            "-c",
            (
                "from pathlib import Path;"
                "Path('/data/ledger/ledger.sock').unlink()"
            ),
        ]
    )
    _require_success(result)


def test_live_ledger_outage_and_stale_endpoint_fail_closed(
    started_compose: ComposeFixture,
) -> None:
    context = started_compose
    mcp_id = _container_id(context, "mcp")

    _require_success(_compose_run(context, "stop", "ledger"))
    _wait_readiness(context, 503)

    failed_ping = _run(
        ["docker", "exec", mcp_id, "python", "-c", _EXEC_PING]
    )
    assert failed_ping.returncode != 0
    assert not _inspect_container(mcp_id)["HostConfig"].get("PortBindings")

    _require_success(_compose_run(context, "start", "ledger"))
    _wait_readiness(context, 200)

    _require_success(_compose_run(context, "stop", "ledger"))
    stale_marker = "stale-endpoint-phase6b"
    _write_stale_execution_endpoint(context, content=stale_marker)

    _require_success(_compose_run(context, "start", "ledger"))
    stopped = _wait_container_stopped(context, "ledger")
    assert stopped["State"]["ExitCode"] != 0
    assert _read_stale_execution_endpoint(context) == stale_marker

    _remove_stale_execution_endpoint(context)
    _require_success(_compose_run(context, "start", "ledger"))
    _wait_readiness(context, 200)
