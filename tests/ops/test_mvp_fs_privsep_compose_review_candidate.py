"""Render-only alignment of Mode A Compose to proved OpenSSH FS admission.

Never executes docker up/build/run; no key provisioning or host network changes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/compose/compose.mode-a-openssh-fs.review-candidate.yaml"
CORE = ROOT / "deploy/compose/compose.yaml"
BASE = ROOT / "deploy/compose/compose.dev-ssh.yaml"
CAPS = {"SETUID", "SETGID", "SETPCAP", "SYS_CHROOT"}
HOLD = ["/usr/local/libexec/ssh-over-mcp-image-hold"]


class _ComposeTagLoader(yaml.SafeLoader):
    pass


def _override(loader: _ComposeTagLoader, node: yaml.SequenceNode):
    return loader.construct_sequence(node)


_ComposeTagLoader.add_constructor("!override", _override)


def test_inert_two_node_runtime_overlay_has_exactly_reviewed_admission():
    source = MANIFEST.read_text()
    document = yaml.load(source, Loader=_ComposeTagLoader)
    assert set(document) == {"services"}
    assert set(document["services"]) == {"node01", "node02"}
    assert "DO NOT copy test-only root sshd" in source
    assert "reviewed" in source

    for number in ("01", "02"):
        node = document["services"][f"node{number}"]
        assert node["profiles"] == ["mvp-fs-review"]
        assert node["user"] == "0:0"
        assert node["read_only"] is True
        assert node["entrypoint"] == HOLD
        assert node["cap_drop"] == ["ALL"]
        assert set(node["cap_add"]) == CAPS
        assert node["security_opt"] == ["no-new-privileges:false"]
        assert node["expose"] == ["2222"]
        assert "ports" not in node
        assert "privileged" not in node
        assert node["tmpfs"] == [
            "/run:rw,noexec,nosuid,nodev,mode=0755,size=8m",
            "/run/sshd:rw,noexec,nosuid,nodev,mode=0755,size=2m",
            "/tmp:rw,nosuid,nodev,mode=1777,size=8m",
        ]
        volume = node["volumes"]
        assert len(volume) == 3
        assert [mount["target"] for mount in volume] == [
            "/etc/ssh/hostkeys",
            "/etc/ssh/authorized_keys",
            "/srv/data",
        ]
        for mount, token in zip(volume[:2], ("HOSTKEYS_DIR", "AUTHORIZED_KEYS_DIR"), strict=True):
            assert mount["type"] == "bind"
            assert mount["read_only"] is True
            assert mount["bind"]["create_host_path"] is False
            assert f"NODE{number}_{token}" in mount["source"]
        assert volume[2] == {
            "type": "volume",
            "source": f"node{number}-data",
            "target": "/srv/data",
        }
    assert document["services"]["node01"]["volumes"] != document["services"]["node02"]["volumes"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI not installed")
def test_actual_compose_render_preserves_hard_stop_without_guest_boot():
    env = dict(os.environ)
    env.update(
        {
            "SSH_OVER_MCP_IMAGE": "registry.invalid/control@sha256:" + "1" * 64,
            "SSH_OVER_MCP_NODE01_IMAGE": "registry.invalid/node01@sha256:" + "2" * 64,
            "SSH_OVER_MCP_NODE02_IMAGE": "registry.invalid/node02@sha256:" + "3" * 64,
            "SSH_OVER_MCP_PROFILE": "rw-operator",
            "SSH_OVER_MCP_CONFIG_FILE": "/tmp/som-review-does-not-exist/config",
            "SSH_OVER_MCP_CREDENTIAL_MAP_FILE": "/tmp/som-review-does-not-exist/creds",
            "SSH_OVER_MCP_SSH_SECRETS_DIR": "/tmp/som-review-does-not-exist/secrets",
            "SSH_OVER_MCP_ORIGIN_BEARER_FILE": "/tmp/som-review-does-not-exist/token",
            "SSH_OVER_MCP_NODE01_HOSTKEYS_DIR": "/tmp/som-review-does-not-exist/node01/keys",
            "SSH_OVER_MCP_NODE02_HOSTKEYS_DIR": "/tmp/som-review-does-not-exist/node02/keys",
            "SSH_OVER_MCP_NODE01_AUTHORIZED_KEYS_DIR": "/tmp/som-review-does-not-exist/node01/auth",
            "SSH_OVER_MCP_NODE02_AUTHORIZED_KEYS_DIR": "/tmp/som-review-does-not-exist/node02/auth",
        }
    )
    args = [
        "docker",
        "compose",
        "-f",
        str(CORE),
        "-f",
        str(BASE),
        "-f",
        str(MANIFEST),
        "--profile",
        "mvp-fs-review",
        "config",
        "--format",
        "json",
    ]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False, env=env)
    if "docker: 'compose' is not a docker command" in proc.stderr:
        pytest.skip("Docker Compose plugin absent")
    assert proc.returncode == 0, proc.stderr[-1100:]
    data = json.loads(proc.stdout)
    services = data["services"]
    assert "mcp" in services
    for number in ("01", "02"):
        node = services[f"node{number}"]
        assert node["entrypoint"] == HOLD
        assert node["user"] == "0:0"
        assert node["read_only"] is True
        assert set(node["cap_add"]) == CAPS
        assert node["cap_drop"] == ["ALL"]
        assert node["security_opt"] == ["no-new-privileges:false"]
        assert node["expose"] == ["2222"]
        assert not node.get("ports")
        assert node["profiles"] == ["mvp-fs-review"]
        assert set(node["networks"]) == {f"node{number}_ssh"}
        mounts = {mount["target"]: mount for mount in node["volumes"]}
        assert mounts["/etc/ssh/hostkeys"]["bind"]["create_host_path"] is False
        assert mounts["/etc/ssh/authorized_keys"]["bind"]["create_host_path"] is False
    assert set(services["mcp"]["networks"]) == {"origin_internal", "node01_ssh", "node02_ssh"}
