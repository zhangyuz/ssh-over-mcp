from __future__ import annotations

from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _REPO_ROOT / "deploy" / "compose" / "compose.yaml"
_ENV_EXAMPLE = _REPO_ROOT / "deploy" / "compose" / "reference.env.example"

_SERVICES = {"ledger-init", "ledger", "mcp", "approvalctl", "cloudflared"}
_VOLUMES = {"ledger-data", "ledger-exec", "ledger-admin"}


def _document() -> dict:
    return yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))


def _mounts(service: dict) -> dict[str, dict]:
    return {item["target"]: item for item in service.get("volumes", [])}


def test_compose_has_exact_private_service_network_and_volume_surface() -> None:
    document = _document()
    services = document["services"]

    assert set(services) == _SERVICES
    assert set(document["volumes"]) == _VOLUMES
    assert set(document["networks"]) == {"origin_internal", "ssh_egress", "cloudflare_egress"}
    assert document["networks"]["origin_internal"]["internal"] is True

    for service in services.values():
        assert "ports" not in service
        assert service.get("privileged") is not True
        assert service.get("network_mode") != "host"
        assert service.get("pid") != "host"
        assert service.get("ipc") != "host"
        rendered = repr(service)
        assert "/var/run/docker.sock" not in rendered
        assert "ipv4_address" not in rendered
        assert "ipv6_address" not in rendered

    assert services["mcp"]["expose"] == ["8000"]
    assert services["ledger-init"]["network_mode"] == "none"
    assert services["ledger"]["network_mode"] == "none"
    assert services["approvalctl"]["network_mode"] == "none"
    assert set(services["mcp"]["networks"]) == {"origin_internal", "ssh_egress"}
    assert services["mcp"]["networks"]["origin_internal"]["aliases"] == [
        "ssh-over-mcp-origin",
        "${SSH_OVER_MCP_PRIVATE_HOSTNAME:?set SSH_OVER_MCP_PRIVATE_HOSTNAME}",
    ]


def test_compose_pins_exact_numeric_identities_and_capabilities() -> None:
    services = _document()["services"]

    assert services["mcp"]["user"] == "10001:10003"
    assert services["ledger"]["user"] == "10002:10002"
    assert services["ledger"]["group_add"] == ["10003", "10005"]
    assert services["approvalctl"]["user"] == "10004:10005"
    assert services["ledger-init"]["user"] == "0:0"

    for service in services.values():
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]

    assert services["ledger-init"]["cap_add"] == ["CHOWN", "DAC_OVERRIDE"]
    for name in ("ledger", "mcp", "approvalctl", "cloudflared"):
        assert "cap_add" not in services[name]

    assert services["approvalctl"]["profiles"] == ["admin"]


def test_compose_mount_visibility_preserves_ledger_authority_domains() -> None:
    services = _document()["services"]

    init_mounts = _mounts(services["ledger-init"])
    ledger_mounts = _mounts(services["ledger"])
    mcp_mounts = _mounts(services["mcp"])
    admin_mounts = _mounts(services["approvalctl"])

    ledger_targets = {
        "/var/lib/ssh-over-mcp",
        "/run/ssh-over-mcp-exec",
        "/run/ssh-over-mcp-admin",
    }
    assert set(init_mounts) == ledger_targets
    assert set(ledger_mounts) == ledger_targets
    assert all(not item.get("read_only", False) for item in init_mounts.values())
    assert all(not item.get("read_only", False) for item in ledger_mounts.values())

    assert set(mcp_mounts) == {
        "/etc/ssh-over-mcp/config.yaml",
        "/etc/ssh-over-mcp/credentials.yaml",
        "/run/secrets/ssh",
        "/run/secrets/origin-bearer",
        "/run/ssh-over-mcp-exec",
    }
    assert all(item["read_only"] is True for item in mcp_mounts.values())

    assert set(admin_mounts) == {"/run/ssh-over-mcp-admin"}
    assert admin_mounts["/run/ssh-over-mcp-admin"]["read_only"] is True

    assert "/var/lib/ssh-over-mcp" not in mcp_mounts
    assert "/run/ssh-over-mcp-admin" not in mcp_mounts
    assert "/var/lib/ssh-over-mcp" not in admin_mounts
    assert "/run/ssh-over-mcp-exec" not in admin_mounts


def test_compose_pins_exact_runtime_environment_and_entrypoints() -> None:
    services = _document()["services"]
    image = "${SSH_OVER_MCP_IMAGE:-ssh-over-mcp:phase6b}"
    app_names = ("ledger-init", "ledger", "mcp", "approvalctl")
    assert {services[name]["image"] for name in app_names} == {image}

    assert services["ledger-init"]["entrypoint"] == ["ssh-over-mcp-ledger-init"]
    assert services["ledger"]["entrypoint"] == ["ssh-over-mcp-ledger"]
    assert services["mcp"]["entrypoint"] == ["ssh-over-mcp-server"]
    assert services["approvalctl"]["entrypoint"] == ["ssh-over-mcp-approvalctl"]

    expected_ledger = {
        "SSH_OVER_MCP_LEDGER_DB_PATH": "/var/lib/ssh-over-mcp/ledger/ledger.db",
        "SSH_OVER_MCP_LEDGER_HMAC_KEY_PATH": "/var/lib/ssh-over-mcp/ledger/ledger.key",
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": "/run/ssh-over-mcp-exec/ledger/ledger.sock",
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_GID": "10003",
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_MODE": "0660",
        "SSH_OVER_MCP_LEDGER_EXEC_PEER_UID": "10001",
        "SSH_OVER_MCP_LEDGER_EXEC_PEER_GID": "10003",
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": "/run/ssh-over-mcp-admin/ledger/ledger.sock",
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_GID": "10005",
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_MODE": "0660",
        "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID": "10004",
        "SSH_OVER_MCP_LEDGER_ADMIN_PEER_GID": "10005",
    }
    assert services["ledger-init"]["environment"] == expected_ledger
    assert services["ledger"]["environment"] == expected_ledger

    assert services["mcp"]["environment"] == {
        "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
        "SSH_OVER_MCP_CREDENTIAL_MAP": "/etc/ssh-over-mcp/credentials.yaml",
        "SSH_OVER_MCP_PROFILE": "${SSH_OVER_MCP_PROFILE:?set SSH_OVER_MCP_PROFILE}",
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": "/run/ssh-over-mcp-exec/ledger/ledger.sock",
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
        "SSH_OVER_MCP_BIND_HOST": "0.0.0.0",
        "SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE": "/run/secrets/origin-bearer",
    }

    assert services["approvalctl"]["environment"] == {
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": "/run/ssh-over-mcp-admin/ledger/ledger.sock",
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
    }


def test_compose_pins_dependency_and_health_contract() -> None:
    services = _document()["services"]

    assert services["ledger"]["depends_on"] == {
        "ledger-init": {"condition": "service_completed_successfully"}
    }
    assert services["mcp"]["depends_on"] == {
        "ledger": {"condition": "service_started"}
    }
    assert services["mcp"]["healthcheck"] == {
        "test": [
            "CMD",
            "python",
            "-c",
            (
                "import urllib.request;"
                "urllib.request.urlopen('http://127.0.0.1:8000/readyz',timeout=2).read()"
            ),
        ],
        "interval": "5s",
        "timeout": "3s",
        "retries": 12,
        "start_period": "2s",
    }


def test_reference_env_example_contains_only_non_secret_inputs() -> None:
    lines = [
        line
        for line in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    keys = {line.split("=", 1)[0] for line in lines}
    assert keys == {
        "SSH_OVER_MCP_IMAGE",
        "SSH_OVER_MCP_PROFILE",
        "SSH_OVER_MCP_CONFIG_FILE",
        "SSH_OVER_MCP_CREDENTIAL_MAP_FILE",
        "SSH_OVER_MCP_SSH_SECRETS_DIR",
        "SSH_OVER_MCP_ORIGIN_BEARER_FILE",
        "SSH_OVER_MCP_PRIVATE_HOSTNAME",
        "SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE",
    }
    text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    for forbidden in (
        "CF-Access-Client-Secret",
        "TUNNEL_TOKEN",
        "HMAC",
        "PRIVATE KEY-----",
        "origin_bearer=",
    ):
        assert forbidden not in text
