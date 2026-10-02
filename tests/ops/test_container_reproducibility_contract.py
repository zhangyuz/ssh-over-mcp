from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _REPO_ROOT / "Dockerfile"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_BUILD_IN = _REPO_ROOT / "requirements" / "build.in"
_BUILD_LOCK = _REPO_ROOT / "requirements" / "build.lock"
_RUNTIME_IN = _REPO_ROOT / "requirements" / "runtime.in"
_RUNTIME_LOCK = _REPO_ROOT / "requirements" / "runtime.lock"

_BASE = (
    "python:3.13-slim-bookworm@"
    "sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed"
)
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)")
_EXACT = re.compile(r"^[A-Za-z0-9_.-]+==[^\s\\]+(?:\s|\\|$)")


def _logical_requirements(path: Path) -> list[str]:
    logical: list[str] = []
    current: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--") and not current:
            raise AssertionError(f"global option is not allowed in lock: {line}")
        current.append(line.removesuffix("\\").strip())
        if not line.endswith("\\"):
            logical.append(" ".join(current))
            current = []
    assert not current, f"unterminated requirement block in {path}"
    return logical


def _direct_names(path: Path) -> set[str]:
    return {
        canonicalize_name(Requirement(line).name)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def test_dockerfile_pins_base_and_deterministic_build_contract() -> None:
    dockerfile = _DOCKERFILE.read_text(encoding="utf-8")

    from_lines = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.lstrip().startswith("FROM ")
    ]
    assert from_lines == [f"FROM {_BASE} AS builder", f"FROM {_BASE}"]
    assert "FROM python:3.13-slim-bookworm\n" not in dockerfile

    for required in (
        "ARG SOURCE_DATE_EPOCH=315532800",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-build-isolation",
        "--no-index",
        "--no-compile",
        "USER 10001:10001",
        "EXPOSE 8000",
        'CMD ["ssh-over-mcp-server"]',
    ):
        assert required in dockerfile

    assert "groupadd" not in dockerfile
    assert "useradd" not in dockerfile
    assert "ssh-over-mcp:x:10001:" in dockerfile
    assert "ssh-over-mcp:x:10001:10001:" in dockerfile


def test_dependency_input_files_mirror_pyproject_direct_requirements() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))

    runtime_expected = {
        canonicalize_name(Requirement(value).name)
        for value in document["project"]["dependencies"]
    }
    build_expected = {
        canonicalize_name(Requirement(value).name)
        for value in document["build-system"]["requires"]
    }

    assert _direct_names(_RUNTIME_IN) == runtime_expected
    assert _direct_names(_BUILD_IN) == build_expected


def test_build_and_runtime_locks_are_exact_and_hash_complete() -> None:
    forbidden_fragments = (
        ">=",
        "<=",
        "~=",
        " @ ",
        "git+",
        "file:",
        "-e ",
        "--editable",
        "--trusted-host",
    )

    for path in (_BUILD_LOCK, _RUNTIME_LOCK):
        assert path.is_file()
        requirements = _logical_requirements(path)
        assert requirements
        for requirement in requirements:
            assert _EXACT.match(requirement), requirement
            assert _HASH.search(requirement), requirement
            assert not any(fragment in requirement for fragment in forbidden_fragments)


def test_dockerfile_consumes_only_committed_lock_files_for_dependencies() -> None:
    dockerfile = _DOCKERFILE.read_text(encoding="utf-8")

    assert "requirements/build.lock" in dockerfile
    assert "requirements/runtime.lock" in dockerfile
    assert "requirements/build.in" not in dockerfile
    assert "requirements/runtime.in" not in dockerfile

    assert "pip install --no-cache-dir --require-hashes --no-compile" in dockerfile
    assert "--only-binary=:all: -r requirements/build.lock" in dockerfile
    assert "pip download --require-hashes --only-binary=:all: --no-deps" in dockerfile
    assert "pip wheel --no-build-isolation --no-deps" in dockerfile
    assert "pip install --no-cache-dir --no-index --no-compile" in dockerfile
