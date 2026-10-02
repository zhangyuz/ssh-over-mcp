from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_REPRODUCIBLE_IMAGE") == "1"
_EPOCH = "315532800"

pytestmark = pytest.mark.skipif(
    not _RUN_LIVE,
    reason=(
        "set SSH_OVER_MCP_RUN_LIVE_REPRODUCIBLE_IMAGE=1 "
        "for the two-build reproducibility probe"
    ),
)


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


def _build(tag: str) -> None:
    result = _run(
        [
            "docker",
            "buildx",
            "build",
            "--platform",
            "linux/amd64",
            "--no-cache",
            "--provenance=false",
            "--sbom=false",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={_EPOCH}",
            "--load",
            "-t",
            tag,
            ".",
        ]
    )
    _require_success(result)


def _inspect(tag: str) -> dict:
    result = _run(["docker", "image", "inspect", tag])
    return json.loads(_require_success(result))[0]


def _package_inventory(tag: str) -> list[list[str]]:
    code = r"""
import json
from importlib.metadata import distributions

items = sorted(
    (dist.metadata["Name"].lower(), dist.version)
    for dist in distributions()
    if dist.metadata["Name"]
)
print(json.dumps(items, separators=(",", ":")))
"""
    result = _run(["docker", "run", "--rm", tag, "python", "-c", code])
    return json.loads(_require_success(result))


def _assert_hardened_runtime(tag: str) -> None:
    code = r"""
import os
from pathlib import Path

status = {}
for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        status[key] = value.strip()

assert os.getuid() == 10001
assert os.getgid() == 10001
assert status["CapEff"] == "0000000000000000"
assert status["NoNewPrivs"] == "1"
assert not Path("/var/run/docker.sock").exists()
"""
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            tag,
            "python",
            "-c",
            code,
        ]
    )
    _require_success(result)


def test_two_no_cache_builds_are_bit_reproducible() -> None:
    tag_a = f"ssh-over-mcp:repro-a-{os.getpid()}"
    tag_b = f"ssh-over-mcp:repro-b-{os.getpid()}"
    try:
        _build(tag_a)
        _build(tag_b)

        image_a = _inspect(tag_a)
        image_b = _inspect(tag_b)

        assert image_a["Id"] == image_b["Id"]
        assert image_a["RootFS"]["Layers"] == image_b["RootFS"]["Layers"]

        for key in ("User", "Cmd", "Entrypoint", "ExposedPorts"):
            assert image_a["Config"].get(key) == image_b["Config"].get(key)

        assert image_a["Config"]["User"] == "10001:10001"
        assert image_a["Config"]["Cmd"] == ["ssh-over-mcp-server"]
        assert image_a["Config"]["ExposedPorts"] == {"8000/tcp": {}}

        assert _package_inventory(tag_a) == _package_inventory(tag_b)
        _assert_hardened_runtime(tag_a)
        _assert_hardened_runtime(tag_b)
    finally:
        _run(["docker", "image", "rm", "-f", tag_a, tag_b])
