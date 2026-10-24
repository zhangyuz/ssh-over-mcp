"""Mode A checked-in Compose overlay: STATIC declarations, not container admission."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "deploy/compose/compose.yaml"
OVERLAY = ROOT / "deploy/compose/compose.dev-ssh.yaml"
SAMPLE = ROOT / "deploy/compose/reference.mode-a.env.example"
CLI = ROOT / "ops/mvp/compose_config_preflight.py"
CONTROL_IMAGE = "registry.example.invalid/control@sha256:" + "a" * 64
NODE01_IMAGE = "registry.example.invalid/ssh@sha256:" + "b" * 64
NODE02_IMAGE = "registry.example.invalid/ssh@sha256:" + "c" * 64


class _ComposeLoader(yaml.SafeLoader):
    """Inspect the static YAML shape; Compose performs actual override merges."""


def _override(loader, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!override", _override)


def overlay() -> dict:
    return yaml.load(OVERLAY.read_text(), Loader=_ComposeLoader)


def synthetic_env() -> dict[str, str]:
    # Never inherit operator/project Compose settings. COMPOSE_ENV_FILES and
    # COMPOSE_PROFILES could silently replace missing digests or start a profile.
    # HOME/PATH are kept only so user-installed Docker CLI plugins can be found.
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT")
        if key in os.environ
    }
    return {
        **env,
        "COMPOSE_DISABLE_ENV_FILE": "1",
        "DOCKER_HOST": "unix:///nonexistent-som-mvp-mode-a-docker.sock",
        "SSH_OVER_MCP_IMAGE": CONTROL_IMAGE,
        "SSH_OVER_MCP_PROFILE": "rw-operator",
        "SSH_OVER_MCP_CONFIG_FILE": "/srv/som-operator/synthetic/config.yaml",
        "SSH_OVER_MCP_CREDENTIAL_MAP_FILE": "/srv/som-operator/synthetic/credentials.yaml",
        "SSH_OVER_MCP_SSH_SECRETS_DIR": "/srv/som-operator/synthetic/ssh-keys",
        "SSH_OVER_MCP_ORIGIN_BEARER_FILE": "/srv/som-operator/synthetic/origin-bearer",
        "SSH_OVER_MCP_NODE01_IMAGE": NODE01_IMAGE,
        "SSH_OVER_MCP_NODE02_IMAGE": NODE02_IMAGE,
    }


def _compose_command() -> list[str] | None:
    if shutil.which("docker"):
        try:
            # `docker compose version` is a local plugin-discovery command;
            # does not connect to any Docker Engine or require host privileges.
            result = subprocess.run(
                ["docker", "compose", "version"],
                env=synthetic_env(),
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                return ["docker", "compose"]
        except (subprocess.TimeoutExpired, OSError):
            pass
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def render(*, env=None, require_success=True):
    command = _compose_command()
    if command is None:
        pytest.skip("No Compose plugin or standalone CLI; static YAML tests still apply")
    proc = subprocess.run(
        [
            *command,
            "-f",
            str(BASE),
            "-f",
            str(OVERLAY),
            "--project-name",
            "som-mode-a-synthetic",
            "config",
            "--format",
            "json",
        ],
        env=synthetic_env() if env is None else env,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if require_success:
        assert proc.returncode == 0, proc.stderr[:400]
        return json.loads(proc.stdout)
    return proc


def test_overlay_has_two_distinct_ssh_targets_without_privileged_escape():
    doc = overlay()
    assert set(doc["services"]) == {
        "ledger-init",
        "ledger",
        "approvalctl",
        "cloudflared",
        "mcp",
        "node01",
        "node02",
    }
    assert set(doc["networks"]) == {
        "origin_internal",
        "cloudflare_egress",
        "node01_ssh",
        "node02_ssh",
    }
    assert doc["networks"]["origin_internal"]["internal"] is True
    for alias in ("node01", "node02"):
        role = doc["services"][alias]
        assert (
            role["image"]
            == "${SSH_OVER_MCP_"
            + alias.upper()
            + "_IMAGE:?set immutable "
            + alias
            + " SSH image digest}"
        )
        assert role["networks"] == [alias + "_ssh"]
        assert role["read_only"] is True
        assert role["cap_drop"] == ["ALL"]
        assert role["security_opt"] == ["no-new-privileges:true"]
        assert role.get("cap_add") in (None, [])
        for forbidden in (
            "ports",
            "privileged",
            "pid",
            "ipc",
            "network_mode",
            "devices",
            "cgroup",
            "cgroup_parent",
            "entrypoint",
            "command",
            "user",
            "group_add",
        ):
            assert forbidden not in role
        assert {v["target"] for v in role["volumes"]} == {"/srv/data", "/etc/ssh/hostkeys"}
        assert {v["source"] for v in role["volumes"]} == {alias + "-data", alias + "-hostkeys"}
        assert all(v["type"] == "volume" for v in role["volumes"])
        assert doc["networks"][alias + "_ssh"]["internal"] is True


def test_mcp_declares_explicit_network_and_host_bind_replacement():
    doc = overlay()
    mcp = doc["services"]["mcp"]
    assert set(mcp["networks"]) == {"origin_internal", "node01_ssh", "node02_ssh"}
    assert "ssh_egress" not in mcp["networks"]
    assert set(doc["volumes"]) == {
        "ledger-data",
        "ledger-exec",
        "ledger-admin",
        "node01-data",
        "node01-hostkeys",
        "node02-data",
        "node02-hostkeys",
    }
    for m in mcp["volumes"]:
        if m["type"] == "bind":
            assert m["read_only"] is True
            assert m["bind"] == {"create_host_path": False}
        else:
            assert m["source"] == "ledger-exec" and m["read_only"] is True


def test_actual_offline_compose_render_passes_static_checker(tmp_path):
    doc = render()
    assert set(doc["services"]) == {"ledger-init", "ledger", "mcp", "node01", "node02"}
    assert "ssh_egress" not in doc["networks"]
    assert set(doc["services"]["mcp"]["networks"]) == {
        "origin_internal",
        "node01_ssh",
        "node02_ssh",
    }
    assert set(doc["services"]["node01"]["networks"]) == {"node01_ssh"}
    assert set(doc["services"]["node02"]["networks"]) == {"node02_ssh"}
    assert doc["services"]["node01"]["image"] == NODE01_IMAGE
    assert doc["services"]["node02"]["image"] == NODE02_IMAGE
    path = tmp_path / "rendered.json"
    path.write_text(json.dumps(doc))
    result = subprocess.run(
        [sys.executable, str(CLI), "--mode", "dev-e2e", "--control-json", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["static_compose_shape_valid"] is True
    assert outcome["deployment_ready"] is False
    assert outcome["host_identity_verified"] is False
    assert outcome["runtime_verified"] is False
    assert outcome["network_acl_verified"] is False


@pytest.mark.parametrize(
    "missing", ["SSH_OVER_MCP_IMAGE", "SSH_OVER_MCP_NODE01_IMAGE", "SSH_OVER_MCP_NODE02_IMAGE"]
)
def test_missing_image_digest_fails_rendering(missing):
    env = synthetic_env()
    env.pop(missing)
    proc = render(env=env, require_success=False)
    assert proc.returncode != 0
    assert proc.stdout == ""


@pytest.mark.parametrize(
    "attack",
    [
        lambda d: d["services"]["node01"].update(ports=["0.0.0.0:22:22"]),
        lambda d: d["services"]["node01"].update(privileged=True),
        lambda d: d["services"]["node01"].update(networks=["node01_ssh", "node02_ssh"]),
        lambda d: d["services"]["mcp"].update(networks={"origin_internal": {}, "ssh_egress": {}}),
        lambda d: d["services"]["node02"]["volumes"].__setitem__(
            0, {"type": "volume", "source": "node01-data", "target": "/srv/data"}
        ),
        lambda d: d["services"]["node02"].update(user="0:0"),
    ],
)
def test_mutated_rendered_document_refused(attack):
    doc = render()
    attack(doc)
    # Import the existing validator; do not reinvent or widen security policy.
    sys.path.insert(0, str(ROOT / "ops/mvp"))
    from compose_config_preflight import Refused, check_mode_a

    with pytest.raises(Refused):
        check_mode_a(doc)


def test_operator_sample_declares_no_authorized_runtime_image_or_secret():
    sample = SAMPLE.read_text()
    assert "SSH_OVER_MCP_IMAGE=" in sample
    assert "SSH_OVER_MCP_NODE01_IMAGE=" in sample
    assert "SSH_OVER_MCP_NODE02_IMAGE=" in sample
    assert "phase6b" not in sample
    assert "DO_NOT_DEPLOY" in sample


def test_actual_render_and_topology_bundle_agree_on_static_digests(tmp_path):
    import base64
    import hashlib

    rendered = render()
    topology = {
        "schema": "som-mvp-compose-topology-v1",
        "mode": "dev-e2e",
        "control": {"engine": "disposable-mode-a", "image": CONTROL_IMAGE},
        "targets": [
            {
                "alias": alias,
                "engine": "disposable-mode-a",
                "image": image,
                "host_key_pin": "SHA256:"
                + base64.b64encode(hashlib.sha256(alias.encode()).digest()).decode().rstrip("="),
            }
            for alias, image in (("node01", NODE01_IMAGE), ("node02", NODE02_IMAGE))
        ],
    }
    topology_path = tmp_path / "synthetic-topology.json"
    control_path = tmp_path / "rendered-control.json"
    topology_path.write_text(json.dumps(topology))
    control_path.write_text(json.dumps(rendered))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "ops/mvp/bundle_preflight.py"),
            "--topology-json",
            str(topology_path),
            "--control-json",
            str(control_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["static_artifacts_consistent"] is True
    assert report["deployment_ready"] is False
    assert report["image_trust_verified"] is False
    assert report["live_e2e_verified"] is False


@pytest.mark.parametrize(
    "invalid",
    [
        "ssh-over-mcp:phase6b",
        "registry.example.invalid/image:latest",
        "registry.example.invalid/node@sha256:abc",
    ],
)
def test_mutable_or_fake_digest_is_not_accepted_by_real_preflight(tmp_path, invalid):
    doc = render()
    doc["services"]["node01"]["image"] = invalid
    path = tmp_path / "invalid-rendered.json"
    path.write_text(json.dumps(doc))
    result = subprocess.run(
        [sys.executable, str(CLI), "--mode", "dev-e2e", "--control-json", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    assert result.returncode == 2 and result.stdout == ""
    assert invalid not in result.stderr


def test_baseline_wide_ssh_egress_remains_outside_the_overlay_contract():
    document = overlay()
    assert "ssh_egress" not in document["networks"]
    assert "ssh_egress" not in document["services"]["mcp"]["networks"]
    baseline = yaml.safe_load(BASE.read_text())
    assert "ssh_egress" in baseline["networks"]
    assert "ssh_egress" in baseline["services"]["mcp"]["networks"]
    # The reference overlay does NOT silently migrate or approve production.


@pytest.mark.parametrize("profile", ["admin", "cloudflare"])
def test_opt_in_control_services_remain_isolated_after_overlay(profile, tmp_path):
    command = _compose_command()
    if command is None:
        pytest.skip("No Compose plugin or standalone CLI; static YAML test unaffected")
    result = subprocess.run(
        [
            *command,
            "-f",
            str(BASE),
            "-f",
            str(OVERLAY),
            "--project-name",
            "som-mode-a-synthetic",
            "--profile",
            profile,
            "config",
            "--format",
            "json",
        ],
        env=synthetic_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr[:250]
    doc = json.loads(result.stdout)
    if profile == "admin":
        assert doc["services"]["approvalctl"]["network_mode"] == "none"
        assert {v["source"].split("_")[-1] for v in doc["services"]["approvalctl"]["volumes"]} == {
            "ledger-admin"
        }
    else:
        assert set(doc["services"]["cloudflared"]["networks"]) == {
            "origin_internal",
            "cloudflare_egress",
        }
        assert "node01_ssh" not in doc["services"]["cloudflared"]["networks"]
        assert "node02_ssh" not in doc["services"]["cloudflared"]["networks"]
    path = tmp_path / (profile + ".json")
    path.write_text(json.dumps(doc))
    check = subprocess.run(
        [sys.executable, str(CLI), "--mode", "dev-e2e", "--control-json", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    assert check.returncode == 0, check.stderr
    assert json.loads(check.stdout)["deployment_ready"] is False


def test_compose_cli_falls_back_to_plugin_on_plugin_only_system(monkeypatch):
    """CI may have `docker compose` but no `docker-compose` standalone."""
    import types
    from unittest.mock import patch

    def which(name):
        return "/usr/bin/docker" if name == "docker" else None

    monkeypatch.setattr(shutil, "which", which)
    with patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as cmd:
        assert _compose_command() == ["docker", "compose"]
        assert cmd.call_args.args[0] == ["docker", "compose", "version"]


def test_compose_standalone_used_only_if_plugin_not_available(monkeypatch):
    import types
    from unittest.mock import patch

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    with patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=1)):
        assert _compose_command() == ["docker-compose"]


def test_missing_ssh_digest_still_fails_under_poisoned_ambient_compose_env(
    tmp_path,
    monkeypatch,
):
    env_file = tmp_path / "spoofed-ambient.env"
    env_file.write_text("SSH_OVER_MCP_NODE01_IMAGE=" + NODE01_IMAGE + "\n")
    monkeypatch.setenv("COMPOSE_ENV_FILES", str(env_file))
    monkeypatch.setenv("COMPOSE_PROFILES", "cloudflare,admin")
    env = synthetic_env()
    assert "COMPOSE_ENV_FILES" not in env
    assert "COMPOSE_PROFILES" not in env
    assert env["COMPOSE_DISABLE_ENV_FILE"] == "1"
    env.pop("SSH_OVER_MCP_NODE01_IMAGE")
    proc = render(env=env, require_success=False)
    assert proc.returncode != 0
    assert not proc.stdout


def test_documented_compose_floor_matches_base_gateway_priority_requirement():
    runbook = (ROOT / "docs/runbooks/mvp-mode-a-compose-render.md").read_text()
    assert "2.33.1+" in runbook
    assert "Compose 2.24.4+" not in runbook


def test_render_stays_in_default_profile_even_with_ambient_profile_set(monkeypatch):
    monkeypatch.setenv("COMPOSE_PROFILES", "admin,cloudflare")
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "ambient-poison")
    assert "COMPOSE_PROFILES" not in synthetic_env()
    assert "COMPOSE_PROJECT_NAME" not in synthetic_env()
    doc = render()
    assert set(doc["services"]) == {"ledger-init", "ledger", "mcp", "node01", "node02"}
    assert doc["name"] == "som-mode-a-synthetic"


def test_operator_docs_expose_reverse_node_to_mcp_bridge_reachability():
    # A shared Docker bridge is not a directional ACL. This is a live HOLD.
    doc = overlay()
    assert doc["services"]["mcp"]["networks"]["node01_ssh"] == {}
    assert doc["services"]["node01"]["networks"] == ["node01_ssh"]
    baseline = yaml.safe_load(BASE.read_text())
    assert baseline["services"]["mcp"]["environment"]["SSH_OVER_MCP_BIND_HOST"] == "0.0.0.0"
    runbook = (ROOT / "docs/runbooks/mvp-mode-a-compose-render.md").read_text()
    assert "node-initiated" in runbook
    assert "bidirectional" in runbook
    assert "real negative" in runbook
