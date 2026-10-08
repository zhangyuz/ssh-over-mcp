"""Dormant incident preflight building blocks; no CLI, capture, or workflow.

The private chain seam accepts disposable fixture components only in Slice A.
It is not an inspection entrypoint and confers no authority over incident roots.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType

_FAILURE = "staging preflight rejected"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class PreflightError(RuntimeError):
    """Sanitized preflight failure; no process ownership or retry authority."""

    def __init__(self, *, cleanup_uncertain: bool = False):
        if type(cleanup_uncertain) is not bool:
            raise TypeError(_FAILURE)
        super().__init__(_FAILURE)
        self._cleanup_uncertain = cleanup_uncertain

    @property
    def cleanup_uncertain(self) -> bool:
        return self._cleanup_uncertain


@dataclass(frozen=True, slots=True)
class _Incident:
    selector: str
    basename: str
    device: int
    inode: int
    expected_commit: str
    uid: int = 502
    mode: int = 0o700


_INCIDENTS = MappingProxyType(
    {
        "stale-target": _Incident(
            "stale-target",
            "ssh-over-mcp-e2e-i8ow1ni6",
            16777220,
            187176421,
            "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
        ),
        "older-target": _Incident(
            "older-target",
            "ssh-over-mcp-e2e-w_kn4rus",
            16777220,
            186877220,
            "bf84c7aafa5c79d629fc04488b5e0bda1cd98cef",
        ),
    }
)


def _select_incident(selector: str) -> _Incident:
    """Only the two approved incident bindings; no caller-selected path."""
    if type(selector) is not str or selector not in _INCIDENTS:
        raise PreflightError()
    return _INCIDENTS[selector]


@dataclass(frozen=True, slots=True)
class DirectoryMetadata:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int


def _metadata(info: os.stat_result) -> DirectoryMetadata:
    if not stat.S_ISDIR(info.st_mode):
        raise PreflightError()
    result = DirectoryMetadata(
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
    )
    if any(
        type(x) is not int
        for x in (result.device, result.inode, result.uid, result.gid, result.mode)
    ):
        raise PreflightError()
    return result


@dataclass(frozen=True, slots=True)
class _PinnedDirectoryChain:
    """Owns descriptors only from private fixture/pinned-parent composition."""

    _fds: tuple[int, ...]
    _parts: tuple[str, ...]
    _initial: tuple[DirectoryMetadata, ...]

    @property
    def metadata(self) -> tuple[DirectoryMetadata, ...]:
        return self._initial[1:]

    def revalidate(self) -> None:
        """Every original parent-to-child edge must still name the held object."""
        try:
            for fd, original in zip(self._fds, self._initial, strict=True):
                if _metadata(os.fstat(fd)) != original:
                    raise PreflightError()
            for index, name in enumerate(self._parts):
                now = os.stat(
                    name,
                    dir_fd=self._fds[index],
                    follow_symlinks=False,
                )
                if _metadata(now) != self._initial[index + 1]:
                    raise PreflightError()
        except (OSError, ValueError, TypeError, OverflowError):
            raise PreflightError() from None


def _verify_parts_and_policies(
    start_fd: int,
    parts: tuple[str, ...],
    rules: tuple[tuple[int, tuple[int, ...]], ...],
) -> None:
    if (
        type(start_fd) is not int
        or start_fd < 0
        or type(parts) is not tuple
        or type(rules) is not tuple
        or not parts
        or len(parts) != len(rules)
        or len(parts) > 16
    ):
        raise PreflightError()
    for name, rule in zip(parts, rules, strict=True):
        if (
            type(name) is not str
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or not name.isascii()
            or len(name) > 255
            or any(ord(char) < 33 or ord(char) > 126 for char in name)
            or type(rule) is not tuple
            or len(rule) != 2
        ):
            raise PreflightError()
        uid, modes = rule
        if (
            type(uid) is not int
            or uid < 0
            or type(modes) is not tuple
            or not modes
            or any(
                type(mode) is not int or mode < 0 or mode > 0o777 or mode & 0o022 for mode in modes
            )
        ):
            raise PreflightError()


@contextmanager
def _pin_directory_chain(
    start_fd: int,
    parts: tuple[str, ...],
    rules: tuple[tuple[int, tuple[int, ...]], ...],
) -> Iterator[_PinnedDirectoryChain]:
    """Private, read-only fixture seam; never accepts user-selected incident paths.

    Duplicates the borrowed start FD; closes only descriptors opened by this
    helper. The caller must retain the context until final edge revalidation.
    """
    _verify_parts_and_policies(start_fd, parts, rules)
    owned: list[int] = []
    try:
        try:
            root = os.dup(start_fd)
            owned.append(root)
            snapshots = [_metadata(os.fstat(root))]
            for name, (uid, modes) in zip(parts, rules, strict=True):
                before = _metadata(os.stat(name, dir_fd=owned[-1], follow_symlinks=False))
                if before.uid != uid or before.mode not in modes:
                    raise PreflightError()
                child = os.open(name, _DIR_FLAGS, dir_fd=owned[-1])
                owned.append(child)
                after = _metadata(os.fstat(child))
                if after != before:
                    raise PreflightError()
                snapshots.append(after)
            pinned = _PinnedDirectoryChain(tuple(owned), parts, tuple(snapshots))
        except (OSError, ValueError, TypeError, OverflowError):
            raise PreflightError() from None
        yield pinned
    finally:
        cleanup_uncertain = False
        for fd in reversed(owned):
            try:
                os.close(fd)
            except (OSError, ValueError, TypeError, OverflowError):
                cleanup_uncertain = True
        if cleanup_uncertain:
            raise PreflightError(cleanup_uncertain=True) from None
