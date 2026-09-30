from __future__ import annotations

import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.filesystem import (
    MAX_FS_READ_BYTES,
    FilesystemAccessError,
    read_file,
    stat_path,
)


pytestmark = pytest.mark.skipif(
    not hasattr(os, "O_PATH"),
    reason="descriptor-safe filesystem primitives require Linux O_PATH",
)


def test_stat_regular_file_returns_bounded_metadata(tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"abc")
    target.chmod(0o640)

    result = stat_path(str(target))

    assert result.path == str(target)
    assert result.kind == "regular"
    assert result.size == 3
    assert result.mode == 0o640
    assert result.uid == os.getuid()
    assert result.gid == os.getgid()


def test_stat_directory_is_supported(tmp_path: Path) -> None:
    result = stat_path(str(tmp_path))

    assert result.kind == "directory"


@pytest.mark.parametrize(
    "path",
    [
        "relative/path",
        "//tmp/example",
        "/tmp/../tmp/example",
        "/tmp/example/",
        "/tmp//example",
    ],
)
def test_noncanonical_paths_fail_closed(path: str) -> None:
    with pytest.raises(FilesystemAccessError, match="canonical"):
        stat_path(path)


def test_final_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(FilesystemAccessError, match="not supported"):
        stat_path(str(link))
    with pytest.raises(FilesystemAccessError):
        read_file(str(link), max_bytes=64)


def test_intermediate_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "data"
    target.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(FilesystemAccessError, match="unsafe parent"):
        stat_path(str(link / "data"))
    with pytest.raises(FilesystemAccessError, match="unsafe parent"):
        read_file(str(link / "data"), max_bytes=64)


def test_read_file_preserves_binary_bytes_and_metadata(tmp_path: Path) -> None:
    target = tmp_path / "payload"
    payload = b"\x00\xffbinary\n"
    target.write_bytes(payload)

    result = read_file(str(target), max_bytes=len(payload))

    assert result.data == payload
    assert result.stat.kind == "regular"
    assert result.stat.size == len(payload)


def test_read_file_rejects_file_over_caller_bound(tmp_path: Path) -> None:
    target = tmp_path / "payload"
    target.write_bytes(b"1234")

    with pytest.raises(FilesystemAccessError, match="byte limit"):
        read_file(str(target), max_bytes=3)


@pytest.mark.parametrize("bound", [0, -1, MAX_FS_READ_BYTES + 1, True, 1.5])
def test_read_bound_fails_closed(bound) -> None:
    with pytest.raises(FilesystemAccessError):
        read_file("/definitely/not/read", max_bytes=bound)


def test_read_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FilesystemAccessError, match="not a regular file"):
        read_file(str(tmp_path), max_bytes=64)


def test_special_fifo_is_rejected_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    with pytest.raises(FilesystemAccessError, match="not supported"):
        stat_path(str(fifo))
    with pytest.raises(FilesystemAccessError, match="not a regular file"):
        read_file(str(fifo), max_bytes=64)


def test_read_detects_file_change_during_pinned_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload"
    target.write_bytes(b"a" * 128)
    real_pread = os.pread
    changed = False

    def changing_pread(fd: int, size: int, offset: int) -> bytes:
        nonlocal changed
        data = real_pread(fd, size, offset)
        if not changed:
            changed = True
            target.write_bytes(b"b" * 128)
        return data

    monkeypatch.setattr(os, "pread", changing_pread)

    with pytest.raises(FilesystemAccessError, match="changed during read"):
        read_file(str(target), max_bytes=128)
