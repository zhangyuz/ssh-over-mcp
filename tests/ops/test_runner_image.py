from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "ops" / "runner" / "Dockerfile"


def test_runner_image_installs_sqlite_runtime_for_setup_python() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "libsqlite3-0" in dockerfile
