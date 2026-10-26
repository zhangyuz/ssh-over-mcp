"""Concrete create-only mkdir durability semantics across supported POSIX hosts.

Uses a pinned parent fd supplied by the fixture; on Linux, the production
_open_parent still provides symlink-free O_PATH traversal.
"""

from __future__ import annotations

import errno
import io
import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent import filesystem_mutation as mutation
from ssh_over_mcp.host_agent.cli import EX_FS_COMMITTED, run
from ssh_over_mcp.host_agent.filesystem_mutation import (
    FilesystemMutationCommittedError,
    FilesystemMutationError,
)
from tests.host_agent.test_cli import filesystem_policy, fs_mkdir_payload, make_executable


@pytest.fixture
def pinned_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Only bypass Linux O_PATH traversal, never the actual create/fsync syscalls."""
    parent = tmp_path / "parent"
    parent.mkdir()

    def pin(path: str) -> tuple[int, str]:
        assert path == str(parent / "new-directory")
        return os.open(parent, os.O_RDONLY | os.O_DIRECTORY), "new-directory"

    monkeypatch.setattr(mutation, "_open_parent", pin)
    return parent


def test_mkdir_success_requires_two_parent_fsyncs(
    pinned_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[str] = []

    def synced(fd: int) -> None:
        opened = os.fstat(fd)
        pinned = pinned_parent.stat()
        assert (opened.st_dev, opened.st_ino) == (pinned.st_dev, pinned.st_ino)
        observed.append("fsync")

    monkeypatch.setattr(os, "fsync", synced)
    mutation.create_directory(str(pinned_parent / "new-directory"))

    assert (pinned_parent / "new-directory").is_dir()
    assert observed == ["fsync", "fsync"]


def test_mkdir_preflight_sync_failure_does_not_create(
    pinned_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError(errno.EIO)))
    with pytest.raises(FilesystemMutationError):
        mutation.create_directory(str(pinned_parent / "new-directory"))
    assert not (pinned_parent / "new-directory").exists()


def test_mkdir_post_commit_sync_failure_preserves_path_and_reports_uncertainty(
    pinned_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def fail_second(_fd: int) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise OSError(errno.EIO, "secret post-create failure")

    monkeypatch.setattr(os, "fsync", fail_second)
    monkeypatch.setattr(
        os, "rmdir", lambda *_a, **_k: pytest.fail("must not roll back a committed mkdir")
    )
    with pytest.raises(FilesystemMutationCommittedError):
        mutation.create_directory(str(pinned_parent / "new-directory"))
    assert attempts == 2
    assert (pinned_parent / "new-directory").is_dir()


def test_mkdir_host_agent_reports_committed_uncertain_without_internals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = make_executable(tmp_path)

    def committed(_path: str) -> None:
        raise FilesystemMutationCommittedError("secret post-create failure")

    monkeypatch.setattr("ssh_over_mcp.host_agent.cli.create_directory", committed)
    error = io.StringIO()
    code = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_mkdir_payload("/srv/app/new-directory")),
        stdout=io.BytesIO(),
        stderr=error,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(executable, mkdir_roots=("/srv/app",)),
    )
    assert code == EX_FS_COMMITTED
    assert error.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem mkdir committed; "
        "durability uncertain; do not retry blindly\n"
    )
    assert "secret" not in error.getvalue()


def test_mkdir_close_error_cannot_mask_post_commit_durability_uncertainty(
    pinned_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_syncable = mutation._open_syncable_parent
    real_close = os.close
    opened: list[int] = []
    closed: list[int] = []
    sync_count = 0
    pinned_fd = -1

    def open_syncable(fd: int) -> int:
        nonlocal pinned_fd
        pinned_fd = fd
        sync_fd = real_syncable(fd)
        opened.append(sync_fd)
        return sync_fd

    def fsync(_fd: int) -> None:
        nonlocal sync_count
        sync_count += 1
        if sync_count == 2:
            raise OSError(errno.EIO, "secret post-commit durability uncertainty")

    def close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)
        if fd in opened:
            raise OSError(errno.EIO, "secret close error")

    monkeypatch.setattr(mutation, "_open_syncable_parent", open_syncable)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "close", close)
    try:
        with pytest.raises(FilesystemMutationCommittedError, match="mkdir committed"):
            mutation.create_directory(str(pinned_parent / "new-directory"))
    finally:
        monkeypatch.setattr(os, "close", real_close)

    assert (pinned_parent / "new-directory").is_dir()
    assert sync_count == 2
    assert len(opened) == 1
    assert opened[0] in closed
    assert pinned_fd in closed
