#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_IMAGE = "ssh-over-mcp-workload-identity-live:local"
_BUILD_TIMEOUT_SECONDS = 300
_RUN_TIMEOUT_SECONDS = 60


def _run(command: list[str], *, cwd: Path, timeout: int) -> None:
    subprocess.run(
        command,
        cwd=cwd,
        check=True,
        timeout=timeout,
    )


def main() -> int:
    if shutil.which("docker") is None:
        print("docker is required for the live workload-identity probe", file=sys.stderr)
        return 2

    repository = Path(__file__).resolve().parents[1]
    container = f"ssh-over-mcp-workload-identity-{os.getpid()}"

    _run(
        [
            "docker",
            "build",
            "--file",
            "tests/live/Dockerfile.workload-identity",
            "--tag",
            _IMAGE,
            ".",
        ],
        cwd=repository,
        timeout=_BUILD_TIMEOUT_SECONDS,
    )

    try:
        _run(
            [
                "docker",
                "run",
                "--name",
                container,
                "--network",
                "none",
                "--cap-drop=ALL",
                "--cap-add=SETUID",
                "--cap-add=SETGID",
                "--pids-limit",
                "64",
                "--memory",
                "512m",
                "-e",
                "SSH_OVER_MCP_RUN_LIVE_WORKLOAD_IDENTITY=1",
                _IMAGE,
            ],
            cwd=repository,
            timeout=_RUN_TIMEOUT_SECONDS,
        )
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container],
            cwd=repository,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
