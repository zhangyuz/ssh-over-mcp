from __future__ import annotations

import json
import os
import subprocess

import pytest

_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_CONTAINER") == "1"
_IMAGE = os.environ.get("SSH_OVER_MCP_CONTAINER_IMAGE", "")

pytestmark = pytest.mark.skipif(
    not _RUN_LIVE,
    reason="set SSH_OVER_MCP_RUN_LIVE_CONTAINER=1 for the live image probe",
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        check=False,
        capture_output=True,
        text=True,
    )


def _require_success(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 0, (
        f"command failed ({result.returncode}):\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    return result.stdout


def test_container_image_defaults_to_non_root_identity() -> None:
    assert _IMAGE, "SSH_OVER_MCP_CONTAINER_IMAGE is required for live probe"
    result = _run(
        "docker",
        "image",
        "inspect",
        "--format",
        "{{json .Config.User}}",
        _IMAGE,
    )
    user = json.loads(_require_success(result).strip())

    assert user not in {"", "0", "root", "0:0", "root:root"}
    assert user == "10001:10001"


def test_container_runtime_has_zero_caps_and_no_new_privileges() -> None:
    assert _IMAGE
    code = r"""
import os
from pathlib import Path

status = {}
for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        status[key] = value.strip()

assert os.getuid() != 0
assert status["CapEff"] == "0000000000000000"
assert status["NoNewPrivs"] == "1"
assert not Path("/var/run/docker.sock").exists()
"""
    result = _run(
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        _IMAGE,
        "python",
        "-c",
        code,
    )
    _require_success(result)


def test_container_resolves_entrypoints_without_repository_secrets() -> None:
    assert _IMAGE
    code = r"""
from importlib.metadata import distribution
from pathlib import Path

import ssh_over_mcp

names = {
    "ssh-over-mcp-host-agent",
    "ssh-over-mcp-server",
    "ssh-over-mcp-ledger",
    "ssh-over-mcp-approvalctl",
}
dist = distribution("ssh-over-mcp")
entrypoints = {
    entry.name: entry
    for entry in dist.entry_points
    if entry.group == "console_scripts"
}
assert names <= set(entrypoints)
for name in names:
    entrypoints[name].load()

app_root = Path("/app")
for path in app_root.rglob("*"):
    rel = path.relative_to(app_root)
    parts = set(rel.parts)
    assert ".git" not in parts
    assert ".worktrees" not in parts
    assert "secrets" not in parts
    assert path.name not in {".env", "known_hosts.local"}
    assert not path.name.startswith(".env.")
    assert path.suffix != ".key"
"""
    result = _run(
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        _IMAGE,
        "python",
        "-c",
        code,
    )
    _require_success(result)
