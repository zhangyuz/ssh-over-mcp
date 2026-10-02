from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _REPO_ROOT / "deploy" / "compose" / "compose.yaml"
_ENV_EXAMPLE = _REPO_ROOT / "deploy" / "compose" / "reference.env.example"

_CLOUDFLARED_IMAGE = (
    "cloudflare/cloudflared:2026.9.3@"
    "sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c"
)
_TOKEN_TARGET = "/run/secrets/cloudflare-tunnel-token"
_PRIVATE_HOSTNAME_INTERPOLATION = (
    "${SSH_OVER_MCP_PRIVATE_HOSTNAME:-mcp.internal.example}"
)


def _document() -> dict:
    return yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))


def _mounts(service: dict) -> dict[str, dict]:
    return {item["target"]: item for item in service.get("volumes", [])}
def _env_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _is_valid_private_hostname(value: str) -> bool:
    if not 1 <= len(value) <= 253:
        return False
    if "://" in value or "/" in value or ":" in value:
        return False
    if value != value.lower():
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return False
    labels = value.split(".")
    label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    return all(label.fullmatch(item) is not None for item in labels)


def test_cloudflared_service_is_hardened_and_token_file_only() -> None:
    service = _document()["services"]["cloudflared"]

    assert service["profiles"] == ["cloudflare"]
    assert service["image"] == _CLOUDFLARED_IMAGE
    assert service["user"] == "65532:65532"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service.get("privileged") is not True
    assert "cap_add" not in service
    assert "environment" not in service
    assert service["command"] == [
        "tunnel",
        "run",
        "--token-file",
        _TOKEN_TARGET,
    ]
    assert "ports" not in service
    assert service.get("network_mode") != "host"
    assert service.get("pid") != "host"
    assert service.get("ipc") != "host"

    mounts = _mounts(service)
    assert set(mounts) == {_TOKEN_TARGET}
    assert mounts[_TOKEN_TARGET] == {
        "type": "bind",
        "source": (
            "${SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE:"
            "-/nonexistent/ssh-over-mcp-cloudflare-tunnel-token}"
        ),
        "target": _TOKEN_TARGET,
        "read_only": True,
        "bind": {"create_host_path": False},
    }

    rendered = repr(service)
    for forbidden in (
        "TUNNEL_TOKEN",
        "CF-Access-Client-Secret",
        "/run/secrets/origin-bearer",
        "/run/secrets/ssh",
        "/var/lib/ssh-over-mcp",
        "/run/ssh-over-mcp-exec",
        "/run/ssh-over-mcp-admin",
        "/etc/ssh-over-mcp",
        "/var/run/docker.sock",
    ):
        assert forbidden not in rendered
def test_cloudflared_has_only_private_origin_and_connector_egress_networks() -> None:
    document = _document()
    service = document["services"]["cloudflared"]

    assert set(document["networks"]) == {
        "origin_internal",
        "ssh_egress",
        "cloudflare_egress",
    }
    assert document["networks"]["origin_internal"]["internal"] is True
    assert document["networks"]["cloudflare_egress"] == {}
    assert service["networks"] == {
        "origin_internal": {},
        "cloudflare_egress": {"gw_priority": 1},
    }

    mcp_networks = document["services"]["mcp"]["networks"]
    assert "cloudflare_egress" not in mcp_networks
    for name in ("ledger", "ledger-init", "approvalctl"):
        assert document["services"][name]["network_mode"] == "none"


def test_mcp_private_hostname_alias_is_operator_owned() -> None:
    aliases = _document()["services"]["mcp"]["networks"]["origin_internal"]["aliases"]

    assert aliases == [
        "ssh-over-mcp-origin",
        _PRIVATE_HOSTNAME_INTERPOLATION,
    ]
def test_reference_env_adds_only_non_secret_cloudflare_inputs() -> None:
    values = _env_values()

    assert values["SSH_OVER_MCP_PRIVATE_HOSTNAME"] == "mcp.internal.example"
    assert values["SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE"] == (
        "/absolute/path/to/cloudflare-tunnel-token"
    )
    assert _is_valid_private_hostname(values["SSH_OVER_MCP_PRIVATE_HOSTNAME"])

    text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    for forbidden in (
        "eyJ",
        "TUNNEL_TOKEN=",
        "CF-Access-Client-Secret",
        "CLOUDFLARE_API_TOKEN",
        "origin_bearer=",
    ):
        assert forbidden not in text


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "MCP.internal.example",
        "mcp_internal.example",
        "-mcp.internal.example",
        "mcp-.internal.example",
        "mcp..internal.example",
        "https://mcp.internal.example",
        "mcp.internal.example:8000",
        "mcp.internal.example/path",
        "127.0.0.1",
        "::1",
        ("a" * 64) + ".internal.example",
        ("a." * 126) + "example",
    ],
)
def test_private_hostname_preflight_rejects_unsafe_values(hostname: str) -> None:
    assert _is_valid_private_hostname(hostname) is False


@pytest.mark.parametrize(
    "hostname",
    [
        "mcp.internal.example",
        "a.example",
        "a-b.c9.internal",
    ],
)
def test_private_hostname_preflight_accepts_lowercase_dns_names(hostname: str) -> None:
    assert _is_valid_private_hostname(hostname) is True


def test_phase6b_compose_contract_does_not_require_cloudflare_inputs() -> None:
    document = _document()
    aliases = document["services"]["mcp"]["networks"]["origin_internal"]["aliases"]
    connector_mount = document["services"]["cloudflared"]["volumes"][0]

    assert aliases == [
        "ssh-over-mcp-origin",
        "${SSH_OVER_MCP_PRIVATE_HOSTNAME:-mcp.internal.example}",
    ]
    assert connector_mount["source"] == (
        "${SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE:"
        "-/nonexistent/ssh-over-mcp-cloudflare-tunnel-token}"
    )
    assert connector_mount["bind"] == {"create_host_path": False}

    raw = _COMPOSE.read_text(encoding="utf-8")
    assert "${SSH_OVER_MCP_PRIVATE_HOSTNAME:?set" not in raw
    assert "${SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE:?set" not in raw
