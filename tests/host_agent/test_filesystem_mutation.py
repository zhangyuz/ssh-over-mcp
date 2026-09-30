from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.filesystem_mutation import (
    DIRECTORY_CREATE_MODE,
    FILE_CREATE_MODE,
    MAX_FS_WRITE_BYTES,
    FilesystemMutationCommittedError,
    FilesystemMutationError,
    create_directory,
    create_regular_file,
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


def test_create_regular_file_publishes_exact_data_create_only(
    tmp_path: Path,
) -> None:
    target = tmp_path / "created.bin"
    data = b"\x00payload\xff"

    create_regular_file(
        str(target),
        data,
        expected_length=len(data),
    )

    assert target.read_bytes() == data
    info = target.stat()
    assert stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) & ~FILE_CREATE_MODE == 0


def test_create_regular_file_does_not_widen_restrictive_umask(
    tmp_path: Path,
) -> None:
    target = tmp_path / "created.bin"
    previous = os.umask(0o777)
    try:
        create_regular_file(str(target), b"x", expected_length=1)
    finally:
        os.umask(previous)

    info = target.stat()
    assert info.st_size == 1
    assert stat.S_IMODE(info.st_mode) == 0


def test_create_regular_file_rejects_existing_destination_without_replace(
    tmp_path: Path,
) -> None:
    target = tmp_path / "existing.bin"
    target.write_bytes(b"keep")

    with pytest.raises(
        FilesystemMutationError,
        match="already exists",
    ):
        create_regular_file(str(target), b"new", expected_length=3)

    assert target.read_bytes() == b"keep"


@pytest.mark.parametrize(
    ("data", "expected_length"),
    [
        (b"short", 6),
        (b"x", True),
        (b"", MAX_FS_WRITE_BYTES + 1),
    ],
)
def test_create_regular_file_rejects_invalid_length_before_publication(
    tmp_path: Path,
    data: bytes,
    expected_length: int,
) -> None:
    target = tmp_path / "created.bin"

    with pytest.raises(FilesystemMutationError):
        create_regular_file(
            str(target),
            data,
            expected_length=expected_length,
        )

    assert not target.exists()


def test_create_regular_file_rejects_intermediate_symlink(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(FilesystemMutationError, match="unsafe"):
        create_regular_file(
            str(link / "created.bin"),
            b"data",
            expected_length=4,
        )

    assert not (real / "created.bin").exists()


def test_create_regular_file_fails_closed_when_tmpfile_is_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created.bin"
    real_open = os.open

    def fail_tmpfile(path, flags, *args, **kwargs):
        if hasattr(os, "O_TMPFILE") and (flags & os.O_TMPFILE) == os.O_TMPFILE:
            raise OSError(errno.EOPNOTSUPP, "unsupported")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail_tmpfile)

    with pytest.raises(FilesystemMutationError, match="unnamed"):
        create_regular_file(str(target), b"data", expected_length=4)

    assert not target.exists()


def test_create_regular_file_publish_failure_leaves_no_final_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created.bin"

    def fail_link(*_args, **_kwargs):
        raise OSError(errno.EXDEV, "unsupported publication")

    monkeypatch.setattr(os, "link", fail_link)

    with pytest.raises(FilesystemMutationError, match="publish"):
        create_regular_file(str(target), b"data", expected_length=4)

    assert not target.exists()


def test_create_regular_file_parent_fsync_failure_is_committed_not_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created.bin"
    real_fsync = os.fsync
    fsync_calls = 0

    def fail_post_publish_parent_fsync(fd: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 3:
            raise OSError(errno.EIO, "simulated directory fsync failure")
        real_fsync(fd)

    def forbidden_unlink(*_args, **_kwargs):
        raise AssertionError("committed mutation must not blind-clean final path")

    monkeypatch.setattr(os, "fsync", fail_post_publish_parent_fsync)
    monkeypatch.setattr(os, "unlink", forbidden_unlink)
    monkeypatch.setattr(os, "rmdir", forbidden_unlink)

    with pytest.raises(
        FilesystemMutationCommittedError,
        match="published",
    ):
        create_regular_file(str(target), b"data", expected_length=4)

    assert fsync_calls == 3
    assert target.read_bytes() == b"data"


def test_create_regular_file_never_opens_named_temp_or_final_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created.bin"
    real_open = os.open
    opened_names: list[object] = []

    def tracking_open(path, flags, *args, **kwargs):
        opened_names.append(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)

    create_regular_file(str(target), b"data", expected_length=4)

    assert target.read_bytes() == b"data"
    assert target.name not in opened_names
