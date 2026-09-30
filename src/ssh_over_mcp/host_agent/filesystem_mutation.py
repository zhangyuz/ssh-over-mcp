from __future__ import annotations

import os
import stat

from .filesystem import FilesystemAccessError, _open_parent

DIRECTORY_CREATE_MODE = 0o700
FILE_CREATE_MODE = 0o600
MAX_FS_WRITE_BYTES = 64 * 1024 * 1024
_WRITE_CHUNK_BYTES = 64 * 1024


class FilesystemMutationError(RuntimeError):
    """A typed filesystem mutation could not be completed safely."""


class FilesystemMutationCommittedError(FilesystemMutationError):
    """The namespace commit happened but directory durability is uncertain."""


def create_directory(path: str) -> None:
    """Create one directory at an absent final path.

    The only namespace mutation is the atomic mkdirat-style syscall itself.
    The final pathname is deliberately not reopened, chmodded, or removed after
    creation because a concurrently writable directory could retarget that
    pathname between syscalls.
    """

    try:
        parent_fd, final_name = _open_parent(path)
    except FilesystemAccessError as exc:
        raise FilesystemMutationError(
            "filesystem mkdir parent is unavailable or unsafe"
        ) from exc

    try:
        if final_name is None:
            raise FilesystemMutationError(
                "filesystem mkdir cannot target the filesystem root"
            )

        try:
            os.mkdir(
                final_name,
                DIRECTORY_CREATE_MODE,
                dir_fd=parent_fd,
            )
        except FileExistsError as exc:
            raise FilesystemMutationError(
                "filesystem mkdir destination already exists"
            ) from exc
        except OSError as exc:
            raise FilesystemMutationError(
                "filesystem mkdir failed"
            ) from exc
    finally:
        os.close(parent_fd)


def _validate_create_body(data: bytes, expected_length: int) -> None:
    if not isinstance(data, bytes):
        raise FilesystemMutationError("filesystem write body must be bytes")
    if (
        isinstance(expected_length, bool)
        or not isinstance(expected_length, int)
        or expected_length < 0
        or expected_length > MAX_FS_WRITE_BYTES
    ):
        raise FilesystemMutationError(
            "filesystem write length is outside the supported range"
        )
    if len(data) != expected_length:
        raise FilesystemMutationError(
            "filesystem write body length does not match declared length"
        )


def _open_syncable_parent(parent_fd: int) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    try:
        sync_fd = os.open(".", flags, dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemMutationError(
            "filesystem write parent cannot be opened for durability"
        ) from exc

    try:
        pinned = os.fstat(parent_fd)
        opened = os.fstat(sync_fd)
    except OSError as exc:
        os.close(sync_fd)
        raise FilesystemMutationError(
            "filesystem write parent identity cannot be verified"
        ) from exc

    if pinned.st_dev != opened.st_dev or pinned.st_ino != opened.st_ino:
        os.close(sync_fd)
        raise FilesystemMutationError(
            "filesystem write parent identity changed unexpectedly"
        )
    return sync_fd


def _open_tmpfile(parent_fd: int) -> int:
    if not hasattr(os, "O_TMPFILE"):
        raise FilesystemMutationError(
            "filesystem does not support unnamed temporary files"
        )
    flags = os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC
    try:
        return os.open(".", flags, FILE_CREATE_MODE, dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemMutationError(
            "filesystem does not support safe unnamed file creation"
        ) from exc


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(
                fd,
                view[offset : offset + _WRITE_CHUNK_BYTES],
            )
        except OSError as exc:
            raise FilesystemMutationError(
                "filesystem write failed before publication"
            ) from exc
        if written <= 0:
            raise FilesystemMutationError(
                "filesystem write made no progress before publication"
            )
        offset += written


def _verify_tmpfile(fd: int, expected_length: int) -> None:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise FilesystemMutationError(
            "filesystem write inode cannot be verified"
        ) from exc

    if not stat.S_ISREG(info.st_mode):
        raise FilesystemMutationError(
            "filesystem write temporary inode is not regular"
        )
    if stat.S_IMODE(info.st_mode) & ~FILE_CREATE_MODE:
        raise FilesystemMutationError(
            "filesystem write temporary inode mode is too permissive"
        )
    if info.st_size != expected_length:
        raise FilesystemMutationError(
            "filesystem write temporary inode has unexpected size"
        )
    if info.st_nlink != 0:
        raise FilesystemMutationError(
            "filesystem write temporary inode was published unexpectedly"
        )


def _publish_tmpfile(tmp_fd: int, parent_fd: int, final_name: str) -> None:
    source = f"/proc/self/fd/{tmp_fd}"
    try:
        os.link(
            source,
            final_name,
            dst_dir_fd=parent_fd,
            follow_symlinks=True,
        )
    except FileExistsError as exc:
        raise FilesystemMutationError(
            "filesystem write destination already exists"
        ) from exc
    except (NotImplementedError, OSError) as exc:
        raise FilesystemMutationError(
            "filesystem cannot safely publish unnamed file"
        ) from exc


def create_regular_file(
    path: str,
    data: bytes,
    *,
    expected_length: int,
) -> None:
    """Create one absent regular file through an unnamed inode.

    Every failure before the publish link leaves no final pathname. Publication
    is the namespace commit point. A later parent-directory fsync failure is
    reported separately and never triggers blind pathname cleanup.
    """

    _validate_create_body(data, expected_length)

    try:
        parent_fd, final_name = _open_parent(path)
    except FilesystemAccessError as exc:
        raise FilesystemMutationError(
            "filesystem write parent is unavailable or unsafe"
        ) from exc

    sync_parent_fd: int | None = None
    tmp_fd: int | None = None
    try:
        if final_name is None:
            raise FilesystemMutationError(
                "filesystem write cannot target the filesystem root"
            )

        sync_parent_fd = _open_syncable_parent(parent_fd)
        try:
            os.fsync(sync_parent_fd)
        except OSError as exc:
            raise FilesystemMutationError(
                "filesystem write parent does not support durable publication"
            ) from exc

        tmp_fd = _open_tmpfile(parent_fd)
        _write_all(tmp_fd, data)

        try:
            os.fsync(tmp_fd)
        except OSError as exc:
            raise FilesystemMutationError(
                "filesystem write data cannot be synchronized"
            ) from exc

        _verify_tmpfile(tmp_fd, expected_length)
        _publish_tmpfile(tmp_fd, parent_fd, final_name)

        try:
            os.fsync(sync_parent_fd)
        except OSError as exc:
            raise FilesystemMutationCommittedError(
                "filesystem write was published but directory durability is uncertain"
            ) from exc
    finally:
        if tmp_fd is not None:
            os.close(tmp_fd)
        if sync_parent_fd is not None:
            os.close(sync_parent_fd)
        os.close(parent_fd)
