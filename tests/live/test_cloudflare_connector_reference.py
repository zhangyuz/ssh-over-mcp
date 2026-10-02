from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _REPO_ROOT / "deploy" / "compose" / "compose.yaml"
_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_CLOUDFLARE_REFERENCE") == "1"
_IMAGE = os.environ.get("SSH_OVER_MCP_COMPOSE_IMAGE", "")

_CLOUDFLARED_IMAGE = (
    "cloudflare/cloudflared:2026.9.3@"
    "sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c"
)
_CLOUDFLARED_DIGEST = (
    "cloudflare/cloudflared@"
    "sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c"
)
_PRIVATE_HOSTNAME = "mcp.internal.example"
_FAKE_TOKEN = "FAKE_TUNNEL_TOKEN_PHASE6C_DO_NOT_LOG_0123456789"

pytestmark = pytest.mark.skipif(
    not _RUN_LIVE,
    reason=(
        "set SSH_OVER_MCP_RUN_LIVE_CLOUDFLARE_REFERENCE=1 "
        "for the Cloudflare connector reference probe"
    ),
)
@dataclass(frozen=True)
class ConnectorFixture:
    project: str
    env_file: Path
    token_file: Path

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


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=False,
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


def _inspect(container_id: str) -> dict:
    output = _require_success(_run(["docker", "inspect", container_id]))
    return json.loads(output)[0]


def _container_id(
    context: ConnectorFixture,
    service: str,
    *,
    all_states: bool = False,
) -> str:
    args = ["ps"]
    if all_states:
        args.append("-a")
    args.extend(["-q", service])
    return _require_success(_run(context.command(*args))).strip()


def _host_port_8000_listening() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        return probe.connect_ex(("127.0.0.1", 8000)) == 0
@pytest.fixture(scope="module")
def connector_fixture(
    tmp_path_factory: pytest.TempPathFactory,
    request: pytest.FixtureRequest,
) -> ConnectorFixture:
    assert _IMAGE, "SSH_OVER_MCP_COMPOSE_IMAGE is required for live connector probe"
    root = tmp_path_factory.mktemp("phase6c-cloudflare")
    config_file = root / "config.yaml"
    credential_map_file = root / "credentials.yaml"
    ssh_secrets_dir = root / "ssh"
    ssh_secrets_dir.mkdir()
    ssh_key = ssh_secrets_dir / "dev01.key"
    origin_bearer_file = root / "origin-bearer"
    token_file = root / "cloudflare-tunnel-token"
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
    origin_bearer_file.write_bytes(b"compose-origin-token-phase6c")
    token_file.write_text(_FAKE_TOKEN, encoding="utf-8")
    token_file.chmod(0o600)

    env_file.write_text(
        "\n".join(
            [
                f"SSH_OVER_MCP_IMAGE={_IMAGE}",
                "SSH_OVER_MCP_PROFILE=developer",
                f"SSH_OVER_MCP_CONFIG_FILE={config_file}",
                f"SSH_OVER_MCP_CREDENTIAL_MAP_FILE={credential_map_file}",
                f"SSH_OVER_MCP_SSH_SECRETS_DIR={ssh_secrets_dir}",
                f"SSH_OVER_MCP_ORIGIN_BEARER_FILE={origin_bearer_file}",
                f"SSH_OVER_MCP_PRIVATE_HOSTNAME={_PRIVATE_HOSTNAME}",
                f"SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE={token_file}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    fixture = ConnectorFixture(
        project=f"som6c{os.getpid()}",
        env_file=env_file,
        token_file=token_file,
    )

    def cleanup() -> None:
        _run(
            fixture.command(
                "--profile",
                "cloudflare",
                "--profile",
                "admin",
                "down",
                "-v",
                "--remove-orphans",
            )
        )

    request.addfinalizer(cleanup)
    return fixture
def test_resolved_cloudflare_profile_preserves_private_contract(
    connector_fixture: ConnectorFixture,
) -> None:
    rendered = _require_success(
        _run(
            connector_fixture.command(
                "--profile",
                "cloudflare",
                "--profile",
                "admin",
                "config",
                "--format",
                "json",
            )
        )
    )
    document = json.loads(rendered)
    services = document["services"]

    assert set(services) == {
        "ledger-init",
        "ledger",
        "mcp",
        "approvalctl",
        "cloudflared",
    }
    connector = services["cloudflared"]
    assert connector["image"] == _CLOUDFLARED_IMAGE
    assert connector["user"] == "65532:65532"
    assert connector["command"] == [
        "tunnel",
        "run",
        "--token-file",
        "/run/secrets/cloudflare-tunnel-token",
    ]
    assert connector["read_only"] is True
    assert connector["cap_drop"] == ["ALL"]
    assert connector["security_opt"] == ["no-new-privileges:true"]
    assert connector.get("cap_add") in (None, [])
    assert not connector.get("ports")
    connector_mounts = {
        item["target"]: item for item in connector.get("volumes", [])
    }
    assert set(connector_mounts) == {"/run/secrets/cloudflare-tunnel-token"}
    assert connector_mounts["/run/secrets/cloudflare-tunnel-token"]["read_only"] is True
    assert set(connector["networks"]) == {"origin_internal", "cloudflare_egress"}
    assert connector["networks"]["cloudflare_egress"]["gw_priority"] == 1

    mcp = services["mcp"]
    assert "cloudflare_egress" not in mcp["networks"]
    assert _PRIVATE_HOSTNAME in mcp["networks"]["origin_internal"]["aliases"]

    for service in services.values():
        assert not service.get("ports")
        environment = json.dumps(service.get("environment", {}), sort_keys=True)
        for forbidden in (
            _FAKE_TOKEN,
            "TUNNEL_TOKEN",
            "CF-Access-Client-Secret",
            "CLOUDFLARE_API_TOKEN",
        ):
            assert forbidden not in environment


def test_pinned_cloudflared_image_identity() -> None:
    _require_success(_run(["docker", "pull", _CLOUDFLARED_IMAGE]))
    inspect = json.loads(
        _require_success(_run(["docker", "image", "inspect", _CLOUDFLARED_IMAGE]))
    )[0]

    assert _CLOUDFLARED_DIGEST in inspect["RepoDigests"]
    assert inspect["Config"]["User"] == "65532:65532"
    assert inspect["Config"]["Entrypoint"] == ["cloudflared", "--no-autoupdate"]

    version = _require_success(
        _run(["docker", "run", "--rm", _CLOUDFLARED_IMAGE, "version"])
    )
    assert "cloudflared version 2026.9.3" in version
@pytest.fixture(scope="module")
def started_private_origin(connector_fixture: ConnectorFixture):
    result = _run(connector_fixture.command("up", "-d", "--wait", "mcp"))
    _require_success(result)
    try:
        yield connector_fixture
    finally:
        _run(
            connector_fixture.command(
                "--profile",
                "cloudflare",
                "rm",
                "-f",
                "-s",
                "cloudflared",
            )
        )


def test_created_connector_has_only_connector_authority(
    started_private_origin: ConnectorFixture,
) -> None:
    context = started_private_origin
    create = _run(
        context.command(
            "--profile",
            "cloudflare",
            "create",
            "cloudflared",
        )
    )
    _require_success(create)

    connector_id = _container_id(context, "cloudflared", all_states=True)
    assert connector_id
    info = _inspect(connector_id)

    assert info["Config"]["User"] == "65532:65532"
    assert info["HostConfig"]["ReadonlyRootfs"] is True
    assert info["HostConfig"]["CapDrop"] == ["ALL"]
    assert not info["HostConfig"].get("CapAdd")
    assert info["HostConfig"]["SecurityOpt"] == ["no-new-privileges:true"]
    assert not info["HostConfig"].get("PortBindings")
    assert info["Config"]["Cmd"] == [
        "tunnel",
        "run",
        "--token-file",
        "/run/secrets/cloudflare-tunnel-token",
    ]
    mounts = {item["Destination"]: item for item in info["Mounts"]}
    assert set(mounts) == {"/run/secrets/cloudflare-tunnel-token"}
    assert mounts["/run/secrets/cloudflare-tunnel-token"]["RW"] is False
    assert Path(mounts["/run/secrets/cloudflare-tunnel-token"]["Source"]) == (
        context.token_file
    )
    assert stat.S_IMODE(context.token_file.stat().st_mode) == 0o600

    networks = info["NetworkSettings"]["Networks"]
    assert set(networks) == {
        f"{context.project}_origin_internal",
        f"{context.project}_cloudflare_egress",
    }
    assert networks[f"{context.project}_origin_internal"].get("GwPriority", 0) == 0
    assert networks[f"{context.project}_cloudflare_egress"]["GwPriority"] == 1

    serialized = json.dumps(info, sort_keys=True)
    assert _FAKE_TOKEN not in serialized
    assert "/run/secrets/origin-bearer" not in serialized
    assert "/run/secrets/ssh" not in serialized
    assert "/var/lib/ssh-over-mcp" not in serialized
    assert "/run/ssh-over-mcp-exec" not in serialized
    assert "/run/ssh-over-mcp-admin" not in serialized


def test_private_hostname_reaches_origin_without_bypassing_origin_auth(
    started_private_origin: ConnectorFixture,
) -> None:
    context = started_private_origin
    network = f"{context.project}_origin_internal"
    code = f"""
import json
import socket
import urllib.error
import urllib.request

hostname = {_PRIVATE_HOSTNAME!r}
result = {{"addresses": socket.gethostbyname_ex(hostname)[2]}}
result["health"] = urllib.request.urlopen(
    "http://" + hostname + ":8000/healthz", timeout=3
).status
try:
    urllib.request.urlopen("http://" + hostname + ":8000/mcp", timeout=3)
except urllib.error.HTTPError as exc:
    result["mcp"] = exc.code
else:
    result["mcp"] = 200
print(json.dumps(result, sort_keys=True))
"""
    probe = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            _IMAGE,
            "python",
            "-c",
            code,
        ]
    )
    payload = json.loads(_require_success(probe).strip())
    assert payload["addresses"]
    assert payload["health"] == 200
    assert payload["mcp"] == 401

    mcp_id = _container_id(context, "mcp")
    mcp_info = _inspect(mcp_id)
    assert not mcp_info["HostConfig"].get("PortBindings")


def test_connector_failure_does_not_expose_origin(
    started_private_origin: ConnectorFixture,
) -> None:
    context = started_private_origin
    baseline_listener = _host_port_8000_listening()

    start = _run(
        context.command(
            "--profile",
            "cloudflare",
            "up",
            "-d",
            "cloudflared",
        )
    )
    _require_success(start)

    deadline = time.monotonic() + 10.0
    connector_id = ""
    while time.monotonic() < deadline:
        connector_id = _container_id(context, "cloudflared", all_states=True)
        if connector_id:
            info = _inspect(connector_id)
            if info["State"]["Status"] in {"running", "exited", "restarting"}:
                break
        time.sleep(0.2)
    assert connector_id

    logs = _run(
        context.command(
            "--profile",
            "cloudflare",
            "logs",
            "--no-color",
            "cloudflared",
        )
    )
    assert _FAKE_TOKEN not in (logs.stdout + logs.stderr)
    mcp_id = _container_id(context, "mcp")
    mcp_info = _inspect(mcp_id)
    assert mcp_info["State"]["Health"]["Status"] == "healthy"
    assert not mcp_info["HostConfig"].get("PortBindings")
    assert _host_port_8000_listening() == baseline_listener

    assert set(mcp_info["NetworkSettings"]["Networks"]) == {
        f"{context.project}_origin_internal",
        f"{context.project}_ssh_egress",
    }
    mcp_mounts = {item["Destination"] for item in mcp_info["Mounts"]}
    assert "/run/ssh-over-mcp-admin" not in mcp_mounts
    assert "/var/lib/ssh-over-mcp" not in mcp_mounts

    ledger_id = _container_id(context, "ledger")
    ledger_info = _inspect(ledger_id)
    assert ledger_info["HostConfig"]["NetworkMode"] == "none"

    _require_success(
        _run(
            context.command(
                "--profile",
                "cloudflare",
                "rm",
                "-f",
                "-s",
                "cloudflared",
            )
        )
    )
    mcp_after = _inspect(_container_id(context, "mcp"))
    assert mcp_after["State"]["Health"]["Status"] == "healthy"
    assert _host_port_8000_listening() == baseline_listener
