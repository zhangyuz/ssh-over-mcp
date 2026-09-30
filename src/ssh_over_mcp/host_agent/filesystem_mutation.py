from __future__ import annotations

import os

from .filesystem import FilesystemAccessError, _open_parent

DIRECTORY_CREATE_MODE = 0o700


class FilesystemMutationError(RuntimeError):
    """A typed filesystem mutation could not be completed safely."""


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
