"""Inactive Linux-only directory-listing primitive for a *future* typed fs_list.

No caller in the shipped host-agent/MCP runtime invokes this function.
The callback hooks alone do not authenticate a central policy snapshot, verify
an epoch, or constitute permission to expose results to an MCP client.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable

from .filesystem import (
    FilesystemAccessError,
    ReadOnlyFileStat,
    _canonical_absolute_path,
    _open_pinned_final,
    _open_root,
    _result_stat,
    _same_read_identity,
)
from .visibility_policy_v5 import canonical_visibility_path

MAX_LIST_SCANNED_ENTRIES = 64


def _authorized(callback: Callable[[str], bool], path: str) -> bool:
    try:
        return callback(path) is True
    except Exception as exc:
        raise FilesystemAccessError("filesystem authorization unavailable") from exc


def list_directory_candidate(
    path: str,
    *,
    authorize_traverse: Callable[[str], bool],
    authorize_directory: Callable[[str], bool],
    authorize_child: Callable[[str], bool],
    max_entries: int = MAX_LIST_SCANNED_ENTRIES,
) -> tuple[ReadOnlyFileStat, ...]:
    """Collect one bounded directory without reading denied child metadata.

    The caller must provide independently authenticated policy callbacks.
    This primitive is **not** a stable cursor/snapshot implementation and
    is not a remotely authorized or audited FS tool.
    """

    if type(max_entries) is not int or not 1 <= max_entries <= MAX_LIST_SCANNED_ENTRIES:
        raise FilesystemAccessError("directory listing bound is invalid")
    if not all(
        callable(cb)
        for cb in (
            authorize_traverse,
            authorize_directory,
            authorize_child,
        )
    ):
        raise FilesystemAccessError("directory authorization callbacks are unavailable")
    try:
        canonical = canonical_visibility_path(path)
        components = _canonical_absolute_path(canonical)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise FilesystemAccessError("directory listing path is invalid") from exc

    # The root must be authorized before opening even the first path FD.
    if not _authorized(authorize_directory, canonical):
        raise FilesystemAccessError("directory listing denied")
    if not _authorized(authorize_traverse, "/"):
        raise FilesystemAccessError("directory traversal denied")

    pinned_fd: int | None = None
    directory_fd: int | None = None
    try:
        pinned_fd = _open_root()
        prefix = ""
        for component in components:
            prefix += "/" + component
            if not _authorized(authorize_traverse, prefix):
                raise FilesystemAccessError("directory traversal denied")
            try:
                next_fd = os.open(
                    component,
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=pinned_fd,
                )
            except OSError as exc:
                raise FilesystemAccessError("unsafe directory traversal") from exc
            os.close(pinned_fd)
            pinned_fd = next_fd

        # Reopen the pinned inode (not the mutable original pathname) for
        # readdir. /proc/self/fd/N is necessarily a procfs symlink; O_NOFOLLOW
        # is intentionally omitted *only here*, then identity is rechecked.
        try:
            pinned_before = os.fstat(pinned_fd)
            if not stat.S_ISDIR(pinned_before.st_mode):
                raise FilesystemAccessError("listing target is not a directory")
            directory_fd = os.open(
                f"/proc/self/fd/{pinned_fd}",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK | os.O_CLOEXEC,
            )
            directory_before = os.fstat(directory_fd)
        except OSError as exc:
            raise FilesystemAccessError("cannot inspect pinned listing directory") from exc
        if not _same_read_identity(pinned_before, directory_before):
            raise FilesystemAccessError("directory changed before listing")

        names: list[tuple[bytes, str, str]] = []
        try:
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if len(names) >= max_entries:
                        raise FilesystemAccessError("directory listing entry limit exceeded")
                    # The kernel has returned this name, but do not touch its
                    # inode/metadata until the child authorization succeeds.
                    child_path = canonical.rstrip("/") + "/" + entry.name
                    try:
                        canonical_visibility_path(child_path)
                        utf8_name = entry.name.encode("utf-8", errors="strict")
                    except (ValueError, UnicodeError) as exc:
                        raise FilesystemAccessError("invalid directory entry") from exc
                    names.append((utf8_name, entry.name, child_path))
        except OSError as exc:
            raise FilesystemAccessError("directory enumeration failed") from exc

        results: list[ReadOnlyFileStat] = []
        for _, name, child_path in sorted(names, key=lambda item: item[0]):
            if not _authorized(authorize_child, child_path):
                continue
            child_fd = None
            try:
                child_fd, info = _open_pinned_final(directory_fd, name)
                # _result_stat refuses symlinks, FIFOs, sockets and devices.
                results.append(_result_stat(child_path, info))
            finally:
                if child_fd is not None:
                    os.close(child_fd)

        try:
            after = os.fstat(directory_fd)
        except OSError as exc:
            raise FilesystemAccessError("listing directory verification failed") from exc
        if not _same_read_identity(directory_before, after):
            raise FilesystemAccessError("directory changed during listing")
        return tuple(results)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        if pinned_fd is not None:
            os.close(pinned_fd)
