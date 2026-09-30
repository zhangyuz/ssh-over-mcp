from __future__ import annotations

import errno
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
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


def test_create_regular_file_supports_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"

    create_regular_file(str(target), b"", expected_length=0)

    assert target.read_bytes() == b""
    assert target.stat().st_size == 0


@pytest.mark.parametrize("kind", ["directory", "symlink"])
def test_create_regular_file_never_replaces_non_file_destination(
    tmp_path: Path,
    kind: str,
) -> None:
    target = tmp_path / "target"
    if kind == "directory":
        target.mkdir()
    else:
        destination = tmp_path / "destination"
        destination.write_bytes(b"keep")
        target.symlink_to(destination)

    with pytest.raises(FilesystemMutationError, match="already exists"):
        create_regular_file(str(target), b"new", expected_length=3)

    if kind == "directory":
        assert target.is_dir()
    else:
        assert target.is_symlink()
        assert target.resolve().read_bytes() == b"keep"


@pytest.mark.parametrize(
    ("data", "expected_length"),
    [
        (b"", -1),
        (b"", 1),
        (b"x", 0),
    ],
)
def test_create_regular_file_invalid_body_rejected_before_filesystem_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
    expected_length: int,
) -> None:
    target = tmp_path / "created.bin"
    real_open = os.open
    root_opened = False

    def tracking_open(path, flags, *args, **kwargs):
        nonlocal root_opened
        if path == "/":
            root_opened = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)

    with pytest.raises(FilesystemMutationError):
        create_regular_file(
            str(target),
            data,
            expected_length=expected_length,
        )

    assert root_opened is False
    assert not target.exists()


def test_create_regular_file_rejects_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "missing" / "created.bin"

    with pytest.raises(FilesystemMutationError, match="unsafe"):
        create_regular_file(str(target), b"data", expected_length=4)

    assert not target.exists()


def test_create_regular_file_rejects_filesystem_root() -> None:
    with pytest.raises(FilesystemMutationError, match="filesystem root"):
        create_regular_file("/", b"", expected_length=0)


def test_create_regular_file_write_failure_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created.bin"

    def fail_write(_fd: int, _data) -> int:
        raise OSError(errno.EIO, "synthetic write failure")

    monkeypatch.setattr(os, "write", fail_write)

    with pytest.raises(FilesystemMutationError, match="write failed"):
        create_regular_file(str(target), b"data", expected_length=4)

    assert not target.exists()


def test_create_regular_file_file_fsync_failure_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "created.bin"
    real_fsync = os.fsync
    calls = 0

    def fail_file_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(errno.EIO, "synthetic file fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_file_fsync)

    with pytest.raises(
        FilesystemMutationError,
        match="data cannot be synchronized",
    ):
        create_regular_file(str(target), b"data", expected_length=4)

    assert calls == 2
    assert not target.exists()


def test_create_regular_file_real_collision_race_publishes_one_complete_body(
    tmp_path: Path,
) -> None:
    target = tmp_path / "raced.bin"
    payloads = tuple(
        f"writer-{index:02d}-payload".encode("ascii")
        for index in range(8)
    )
    barrier = threading.Barrier(len(payloads))

    def attempt(data: bytes) -> tuple[str, bytes]:
        barrier.wait(timeout=5)
        try:
            create_regular_file(
                str(target),
                data,
                expected_length=len(data),
            )
        except FilesystemMutationError:
            return ("denied", data)
        return ("created", data)

    with ThreadPoolExecutor(max_workers=len(payloads)) as pool:
        outcomes = tuple(pool.map(attempt, payloads))

    winners = [data for state, data in outcomes if state == "created"]
    losers = [data for state, data in outcomes if state == "denied"]

    assert len(winners) == 1
    assert len(losers) == len(payloads) - 1
    assert target.read_bytes() == winners[0]
    assert target.read_bytes() in payloads


def test_create_regular_file_fsyncs_data_before_publish_visibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "ordered.bin"
    real_fsync = os.fsync
    real_link = os.link
    events: list[str] = []

    def tracking_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        events.append("fsync-dir" if stat.S_ISDIR(mode) else "fsync-file")
        real_fsync(fd)

    def tracking_link(*args, **kwargs):
        events.append("publish")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", tracking_fsync)
    monkeypatch.setattr(os, "link", tracking_link)

    create_regular_file(
        str(target),
        b"ordered-data",
        expected_length=len(b"ordered-data"),
    )

    assert target.read_bytes() == b"ordered-data"
    assert events == [
        "fsync-dir",
        "fsync-file",
        "publish",
        "fsync-dir",
    ]
