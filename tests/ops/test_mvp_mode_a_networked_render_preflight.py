"""Real rendered offline Compose release-candidate inspection (not deployment)."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ops.mvp.mode_a_networked_render_preflight import Refused, inspect_rendered

ROOT = Path(__file__).resolve().parents[2]
COMP = ROOT / "deploy/compose"
HOLD = ["/usr/local/libexec/ssh-over-mcp-image-hold"]


def _test_render() -> dict:
    if not shutil.which("docker"):
        pytest.skip("Compose executable absent")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "COMPOSE_DISABLE_ENV_FILE": "1",
        "DOCKER_HOST": "unix:///nonexistent-som342-dry-render.sock",
        "SSH_OVER_MCP_IMAGE": "registry.invalid/control@sha256:" + "1" * 64,
        "SSH_OVER_MCP_NODE01_IMAGE": "registry.invalid/node01@sha256:" + "2" * 64,
        "SSH_OVER_MCP_NODE02_IMAGE": "registry.invalid/node02@sha256:" + "3" * 64,
        "SSH_OVER_MCP_PROFILE": "rw-operator",
        "SSH_OVER_MCP_MODE_A_ORIGIN_IPV4": "172.30.252.10",
        "SSH_OVER_MCP_MODE_A_ORIGIN_CIDR": "172.30.252.0/24",
    }
    for key in (
        "CONFIG_FILE",
        "CREDENTIAL_MAP_FILE",
        "SSH_SECRETS_DIR",
        "ORIGIN_BEARER_FILE",
        "NODE01_HOSTKEYS_DIR",
        "NODE01_AUTHORIZED_KEYS_DIR",
        "NODE02_HOSTKEYS_DIR",
        "NODE02_AUTHORIZED_KEYS_DIR",
    ):
        env["SSH_OVER_MCP_" + key] = "/tmp/som342-nonexistent-review/" + key.lower()
    args = [
        "docker",
        "compose",
        "--project-name",
        "som-mode-a-review",
        "-f",
        str(COMP / "compose.yaml"),
        "-f",
        str(COMP / "compose.dev-ssh.yaml"),
        "-f",
        str(COMP / "compose.mode-a-openssh-fs.review-candidate.yaml"),
        "--profile",
        "mvp-fs-review",
        "config",
        "--format",
        "json",
    ]
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=15, check=False)
    if "docker: 'compose' is not a docker command" in result.stderr:
        pytest.skip("Compose CLI plugin unavailable")
    assert result.returncode == 0, result.stderr[:450]
    return json.loads(result.stdout)


def test_real_render_accepts_inert_review_only_and_never_claims_deployment():
    result = inspect_rendered(_test_render())
    assert result["status"] == "REVIEW_ONLY_HOLD"
    assert result["network_shape"] == "THREE_ISOLATED_BRIDGES"
    assert result["origin_rfc1918_inside_subnet"] is True
    assert result["runtime_started"] is False
    assert result["network_acl_verified"] is False
    assert result["deployment_ready"] is False


@pytest.mark.parametrize(
    "kind",
    [
        "outside",
        "public",
        "gateway",
        "network",
        "broadcast",
        "unbound",
        "mcp_extra_network",
        "node_extra_network",
        "host_port",
        "cap_sys_admin",
        "no_nnp",
        "runtime_enabled",
        "auto_create_key_dir",
        "mutable_image",
        "origin_not_internal",
    ],
)
def test_real_render_refuses_privilege_or_network_regressions(kind):
    config = copy.deepcopy(_test_render())
    mcp = config["services"]["mcp"]
    node = config["services"]["node01"]
    subnet = config["networks"]["origin_internal"]
    if kind == "outside":
        mcp["networks"]["origin_internal"]["ipv4_address"] = "172.30.253.10"
    elif kind == "public":
        subnet["ipam"]["config"][0]["subnet"] = "8.8.8.0/24"
        mcp["networks"]["origin_internal"]["ipv4_address"] = "8.8.8.8"
        mcp["environment"]["SSH_OVER_MCP_BIND_HOST"] = "8.8.8.8"
    elif kind == "gateway":
        mcp["networks"]["origin_internal"]["ipv4_address"] = "172.30.252.1"
        mcp["environment"]["SSH_OVER_MCP_BIND_HOST"] = "172.30.252.1"
    elif kind == "network":
        mcp["networks"]["origin_internal"]["ipv4_address"] = "172.30.252.0"
        mcp["environment"]["SSH_OVER_MCP_BIND_HOST"] = "172.30.252.0"
    elif kind == "broadcast":
        mcp["networks"]["origin_internal"]["ipv4_address"] = "172.30.252.255"
        mcp["environment"]["SSH_OVER_MCP_BIND_HOST"] = "172.30.252.255"
    elif kind == "unbound":
        mcp["environment"]["SSH_OVER_MCP_BIND_HOST"] = "0.0.0.0"
    elif kind == "mcp_extra_network":
        mcp["networks"]["cloudflare_egress"] = {}
    elif kind == "node_extra_network":
        node["networks"]["node02_ssh"] = {}
    elif kind == "host_port":
        node["ports"] = ["2222:2222"]
    elif kind == "cap_sys_admin":
        node["cap_add"].append("SYS_ADMIN")
    elif kind == "no_nnp":
        node["security_opt"] = []
    elif kind == "runtime_enabled":
        node["entrypoint"] = ["/usr/sbin/sshd"]
    elif kind == "auto_create_key_dir":
        node["volumes"][0]["bind"]["create_host_path"] = True
    elif kind == "mutable_image":
        node["image"] = "ubuntu:latest"
    elif kind == "origin_not_internal":
        subnet["internal"] = False
    with pytest.raises(Refused):
        inspect_rendered(config)
