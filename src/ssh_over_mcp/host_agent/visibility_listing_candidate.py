"""Inactive Linux-only directory-listing primitive for a *future* typed fs_list.

No caller in the shipped host-agent/MCP runtime invokes this function.
The callback hooks alone do not authenticate a central policy snapshot, verify
an epoch, or constitute permission to expose results to an MCP client.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from .visibility_snapshot_v5 import VerifiedVisibilitySnapshot

MAX_LIST_SCANNED_ENTRIES = 64
# Fixed work bound for one readdir; never derived from the caller's request.
# Only this constant (not max_entries) may refuse because of denied entries.
MAX_LIST_PHYSICAL_ENTRIES = 4096


def _always_allowed(_: str) -> bool:
    return True


def _authorized(callback: Callable[[str], bool], path: str) -> bool:
    try:
        return callback(path) is True
    except Exception as exc:
        raise FilesystemAccessError("filesystem authorization unavailable") from exc


def select_visible_children(
    parent: str,
    names: Iterable[str],
    *,
    authorize_child: Callable[[str], bool],
    max_entries: int,
) -> list[tuple[bytes, str, str]]:
    """Authorize kernel-returned names lexically; count only visible ones.

    Denied children never count toward the caller's `max_entries`, so no
    caller-chosen bound can reveal how many denied siblings exist. Names that
    are not canonical refuse the whole listing before any authorization:
    denied subtrees are canonical paths, so such a name is never denied.
    """

    scanned: list[tuple[bytes, str, str]] = []
    for name in names:
        if len(scanned) >= MAX_LIST_PHYSICAL_ENTRIES:
            raise FilesystemAccessError("directory exceeds fixed listing scan limit")
        child_path = parent.rstrip("/") + "/" + name
        try:
            canonical_visibility_path(child_path)
            utf8_name = name.encode("utf-8", errors="strict")
        except (ValueError, UnicodeError) as exc:
            raise FilesystemAccessError("invalid directory entry") from exc
        scanned.append((utf8_name, name, child_path))

    visible: list[tuple[bytes, str, str]] = []
    for item in sorted(scanned, key=lambda entry: entry[0]):
        if not _authorized(authorize_child, item[2]):
            continue
        if len(visible) >= max_entries:
            raise FilesystemAccessError("directory listing entry limit exceeded")
        visible.append(item)
    return visible


def list_directory_candidate(
    path: str,
    *,
    authorize_traverse: Callable[[str], bool],
    authorize_directory: Callable[[str], bool],
    authorize_child: Callable[[str], bool],
    before_child_open: Callable[[str], bool] | None = None,
    max_entries: int = MAX_LIST_SCANNED_ENTRIES,
) -> tuple[ReadOnlyFileStat, ...]:
    """Collect one bounded directory without reading denied child metadata.

    The caller must provide independently authenticated policy callbacks.
    This primitive is **not** a stable cursor/snapshot implementation and
    is not a remotely authorized or audited FS tool.
    """

    if type(max_entries) is not int or not 1 <= max_entries <= MAX_LIST_SCANNED_ENTRIES:
        raise FilesystemAccessError("directory listing bound is invalid")
    if before_child_open is None:
        before_child_open = _always_allowed
    if not all(
        callable(cb)
        for cb in (
            authorize_traverse,
            authorize_directory,
            authorize_child,
            before_child_open,
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

        # The kernel has returned these names, but do not touch any child
        # inode/metadata until that child's authorization succeeds.
        try:
            with os.scandir(directory_fd) as iterator:
                visible = select_visible_children(
                    canonical,
                    (entry.name for entry in iterator),
                    authorize_child=authorize_child,
                    max_entries=max_entries,
                )
        except OSError as exc:
            raise FilesystemAccessError("directory enumeration failed") from exc

        results: list[ReadOnlyFileStat] = []
        for _, name, child_path in visible:
            # Runs only for visible children, so its cost cannot reveal how
            # many denied siblings exist. A refusal discards every result.
            if not _authorized(before_child_open, child_path):
                raise FilesystemAccessError("listing authorization changed")
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


def list_verified_directory_candidate(
    verified: VerifiedVisibilitySnapshot,
    *,
    is_epoch_active: Callable[[], bool],
) -> tuple[ReadOnlyFileStat, ...]:
    """Wire verified central AND local policies to the inactive FD primitive.

    The epoch guard must be a trusted, live host-local revocation check.
    The guard is *not* a substitute for an ACK barrier preventing revocation
    from racing the final returned result. Caller must still central-recheck.
    """

    from .visibility_snapshot_v5 import VerifiedVisibilitySnapshot

    if (
        not isinstance(verified, VerifiedVisibilitySnapshot)
        or verified.snapshot.operation != "fs_list"
        or not callable(is_epoch_active)
    ):
        raise FilesystemAccessError("verified listing authority unavailable")

    def require_active() -> None:
        try:
            if is_epoch_active() is True:
                return
        except Exception as exc:
            raise FilesystemAccessError("listing policy epoch unavailable") from exc
        raise FilesystemAccessError("listing policy epoch unavailable")

    def guarded(callback: Callable[[str], bool]) -> Callable[[str], bool]:
        def check(path: str) -> bool:
            require_active()
            return callback(path)

        return check

    require_active()
    # Child names are authorized lexically against the verified snapshot with
    # no epoch reload: a per-name reload made latency proportional to the
    # number of denied siblings (timing oracle). The live epoch is checked
    # for traversal, the root, each *visible* child before open, and after.
    result = list_directory_candidate(
        verified.snapshot.root,
        authorize_traverse=guarded(verified.may_traverse),
        authorize_directory=guarded(verified.may_inspect),
        authorize_child=verified.may_inspect,
        before_child_open=guarded(verified.may_inspect),
        max_entries=verified.snapshot.max_entries,
    )
    require_active()
    return result
