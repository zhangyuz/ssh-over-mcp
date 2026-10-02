from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_REQUIRED_DOCKERIGNORE = {
    ".git",
    ".worktrees",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    ".superpowers",
    "__pycache__",
    ".env",
    ".env.*",
    "secrets",
    "*.pem",
    "*.key",
    "*.crt",
    "known_hosts.local",
    "dist",
    "build",
    "*.egg-info",
}


def test_dockerignore_excludes_local_and_secret_material() -> None:
    path = _REPO_ROOT / ".dockerignore"
    assert path.is_file()
    entries = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert _REQUIRED_DOCKERIGNORE <= entries


def test_dockerfile_pins_hardened_runtime_contract() -> None:
    path = _REPO_ROOT / "Dockerfile"
    assert path.is_file()
    dockerfile = path.read_text(encoding="utf-8")

    assert dockerfile.count("FROM python:3.13-slim-bookworm") == 2
    assert "USER 10001:10001" in dockerfile
    assert "EXPOSE 8000" in dockerfile
    assert 'CMD ["ssh-over-mcp-server"]' in dockerfile
    assert "COPY . " not in dockerfile
