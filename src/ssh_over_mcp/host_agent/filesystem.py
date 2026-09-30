from __future__ import annotations

import os
import posixpath
import stat
from dataclasses import dataclass
from typing import Literal


MAX_FS_READ_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


class FilesystemAccessError(RuntimeError):
    """A typed filesystem operation could not be completed safely."""


FilesystemObjectKind = Literal["regular", "directory"]


@dataclass(frozen=True, slots=True)
class ReadOnlyFileStat:
    path: str
    kind: FilesystemObjectKind
    size: int
    mode: int
    uid: int
    gid: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class ReadFileResult:
    data: bytes
    stat: ReadOnlyFileStat


def _require_linux_open_support() -> None:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_PATH")
    missing = [name for name in required if not hasattr(os, name)]
    if missing or not hasattr(os, "pread"):
        raise FilesystemAccessError(
            "required Linux descriptor-safe filesystem primitives are unavailable"
        )


def _canonical_absolute_path(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path:
        raise FilesystemAccessError("filesystem path must be a non-empty string")
    if "\x00" in path:
        raise FilesystemAccessError("filesystem path contains NUL")
    if not path.startswith("/") or path.startswith("//"):
        raise FilesystemAccessError("filesystem path must be absolute and canonical")

    normalized = posixpath.normpath(path)
    if normalized != path:
        raise FilesystemAccessError("filesystem path must be absolute and canonical")

    if path == "/":
        return ()
    return tuple(path[1:].split("/"))


def _open_root() -> int:
    _require_linux_open_support()
    flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
    try:
        return os.open("/", flags)
    except OSError as exc:
        raise FilesystemAccessError("cannot open filesystem root") from exc


def _open_parent(path: str) -> tuple[int, str | None]:
    components = _canonical_absolute_path(path)
    current_fd = _open_root()

    try:
        for component in components[:-1]:
            flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise FilesystemAccessError(
                    "filesystem path contains an unavailable or unsafe parent"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd

        final_name = components[-1] if components else None
        return current_fd, final_name
    except BaseException:
        os.close(current_fd)
        raise


def _kind(info: os.stat_result) -> FilesystemObjectKind:
    if stat.S_ISREG(info.st_mode):
        return "regular"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    raise FilesystemAccessError("filesystem object type is not supported")


def _result_stat(path: str, info: os.stat_result) -> ReadOnlyFileStat:
    return ReadOnlyFileStat(
        path=path,
        kind=_kind(info),
        size=info.st_size,
        mode=stat.S_IMODE(info.st_mode),
        uid=info.st_uid,
        gid=info.st_gid,
        mtime_ns=info.st_mtime_ns,
    )


def stat_path(path: str) -> ReadOnlyFileStat:
    """Stat a regular file or directory without following any path symlink."""

    parent_fd, final_name = _open_parent(path)
    target_fd: int | None = None
    try:
        if final_name is None:
            target_fd = parent_fd
            parent_fd = -1
        else:
            flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                target_fd = os.open(final_name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise FilesystemAccessError(
                    "filesystem object is unavailable"
                ) from exc

        try:
            info = os.fstat(target_fd)
        except OSError as exc:
            raise FilesystemAccessError(
                "cannot inspect filesystem object"
            ) from exc

        return _result_stat(path, info)
    finally:
        if target_fd is not None:
            os.close(target_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _same_read_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_ctime_ns == right.st_ctime_ns
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_size == right.st_size
    )


def read_file(path: str, *, max_bytes: int) -> ReadFileResult:
    """Read one bounded regular file through a symlink-free pinned descriptor."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise FilesystemAccessError("filesystem read bound must be an integer")
    if max_bytes <= 0 or max_bytes > MAX_FS_READ_BYTES:
        raise FilesystemAccessError("filesystem read bound is outside the supported range")

    parent_fd, final_name = _open_parent(path)
    file_fd: int | None = None
    try:
        if final_name is None:
            raise FilesystemAccessError("filesystem read target is not a regular file")

        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            file_fd = os.open(final_name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise FilesystemAccessError("filesystem read target is unavailable") from exc

        try:
            before = os.fstat(file_fd)
        except OSError as exc:
            raise FilesystemAccessError("cannot inspect filesystem read target") from exc

        if not stat.S_ISREG(before.st_mode):
            raise FilesystemAccessError("filesystem read target is not a regular file")
        if before.st_size > max_bytes:
            raise FilesystemAccessError("filesystem read exceeds configured byte limit")

        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            try:
                chunk = os.pread(
                    file_fd,
                    min(_READ_CHUNK_BYTES, before.st_size - offset),
                    offset,
                )
            except OSError as exc:
                raise FilesystemAccessError("filesystem read failed") from exc
            if not chunk:
                raise FilesystemAccessError("filesystem object changed during read")
            chunks.append(chunk)
            offset += len(chunk)

        try:
            extra = os.pread(file_fd, 1, before.st_size)
            after = os.fstat(file_fd)
        except OSError as exc:
            raise FilesystemAccessError("filesystem read verification failed") from exc

        if extra or not _same_read_identity(before, after):
            raise FilesystemAccessError("filesystem object changed during read")

        return ReadFileResult(
            data=b"".join(chunks),
            stat=_result_stat(path, after),
        )
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)
