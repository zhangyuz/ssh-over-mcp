from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.filesystem_mutation import (
    DIRECTORY_CREATE_MODE,
    FilesystemMutationError,
    create_directory,
)

pytestmark = pytest.mark.skipif(
    not hasattr(os, "O_PATH"),
    reason="descriptor-safe filesystem primitives require Linux O_PATH",
)


def test_create_directory_creates_absent_final_entry(tmp_path: Path) -> None:
    target = tmp_path / "created"

    create_directory(str(target))

    info = target.stat()
    assert stat.S_ISDIR(info.st_mode)
    assert stat.S_IMODE(info.st_mode) & ~DIRECTORY_CREATE_MODE == 0


def test_create_directory_does_not_widen_restrictive_umask(
    tmp_path: Path,
) -> None:
    target = tmp_path / "created"
    previous = os.umask(0o777)
    try:
        create_directory(str(target))
    finally:
        os.umask(previous)

    assert stat.S_IMODE(target.stat().st_mode) == 0


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_create_directory_rejects_existing_final_entry(
    tmp_path: Path,
    kind: str,
) -> None:
    target = tmp_path / "target"
    if kind == "file":
        target.write_bytes(b"keep")
    elif kind == "directory":
        target.mkdir()
    else:
        destination = tmp_path / "destination"
        destination.mkdir()
        target.symlink_to(destination, target_is_directory=True)

    with pytest.raises(
        FilesystemMutationError,
        match="already exists",
    ):
        create_directory(str(target))

    if kind == "file":
        assert target.read_bytes() == b"keep"
    elif kind == "directory":
        assert target.is_dir()
    else:
        assert target.is_symlink()


def test_create_directory_rejects_intermediate_symlink(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(FilesystemMutationError, match="unsafe"):
        create_directory(str(link / "created"))

    assert not (real / "created").exists()


def test_create_directory_rejects_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "missing" / "created"

    with pytest.raises(FilesystemMutationError, match="unsafe"):
        create_directory(str(target))

    assert not target.exists()


def test_create_directory_rejects_filesystem_root() -> None:
    with pytest.raises(FilesystemMutationError, match="filesystem root"):
        create_directory("/")


def test_create_directory_never_reopens_final_path_after_mkdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created"
    real_open = os.open
    final_opens: list[object] = []

    def tracking_open(path, flags, *args, **kwargs):
        if path == target.name:
            final_opens.append(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)

    create_directory(str(target))

    assert target.is_dir()
    assert final_opens == []
