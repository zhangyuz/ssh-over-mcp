from __future__ import annotations

import os
import socket
import stat
from dataclasses import dataclass
from pathlib import Path

from .containment import ContainmentError

_MAX_KERNEL_ID = (1 << 32) - 1
_MAX_LINUX_UNIX_PATH_BYTES = 107
_ALLOWED_SOCKET_MODES = frozenset({0o600, 0o660})


class ContainmentManagerEndpointError(ContainmentError):
    """A filesystem Unix manager endpoint failed a security invariant."""


@dataclass(frozen=True, slots=True)
class UnixManagerEndpointPolicy:
    path: Path
    directory_uid: int
    directory_gid: int
    socket_uid: int
    socket_gid: int
    socket_mode: int = 0o660
    backlog: int = 16

    def __post_init__(self) -> None:
        path = Path(self.path)
        object.__setattr__(self, "path", path)
        raw = os.fspath(path)

        if "\x00" in raw:
            raise ValueError("manager endpoint path must not contain NUL")
        if not path.is_absolute() or raw.startswith("//"):
            raise ValueError("manager endpoint path must be absolute")
        if os.path.normpath(raw) != raw:
            raise ValueError("manager endpoint path must be lexically canonical")
        if path.name in {"", ".", ".."}:
            raise ValueError("manager endpoint path must include a filename")
        if len(os.fsencode(raw)) > _MAX_LINUX_UNIX_PATH_BYTES:
            raise ValueError("manager endpoint path exceeds Linux AF_UNIX limit")

        for label, value in (
            ("directory_uid", self.directory_uid),
            ("directory_gid", self.directory_gid),
            ("socket_uid", self.socket_uid),
            ("socket_gid", self.socket_gid),
        ):
            _validate_kernel_id(value, label)

        if self.socket_mode not in _ALLOWED_SOCKET_MODES:
            raise ValueError("manager socket mode must be 0600 or 0660")
        if (
            isinstance(self.backlog, bool)
            or not isinstance(self.backlog, int)
            or not 1 <= self.backlog <= 128
        ):
            raise ValueError("manager endpoint backlog must be in [1, 128]")


@dataclass(frozen=True, slots=True)
class _SocketIdentity:
    device: int
    inode: int


def _validate_kernel_id(value: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_KERNEL_ID
    ):
        raise ValueError(f"{label} must be a valid Linux uid/gid value")


def _validate_parent(policy: UnixManagerEndpointPolicy) -> Path:
    parent = policy.path.parent

    try:
        resolved = parent.resolve(strict=True)
        info = parent.lstat()
    except OSError as exc:
        raise ContainmentManagerEndpointError(
            "manager endpoint parent directory is unavailable"
        ) from exc

    if resolved != parent:
        raise ContainmentManagerEndpointError(
            "manager endpoint parent directory must be canonical and not a symlink"
        )
    if not stat.S_ISDIR(info.st_mode):
        raise ContainmentManagerEndpointError(
            "manager endpoint parent is not a directory"
        )
    if info.st_uid != policy.directory_uid or info.st_gid != policy.directory_gid:
        raise ContainmentManagerEndpointError(
            "manager endpoint parent ownership does not match policy"
        )
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ContainmentManagerEndpointError(
            "manager endpoint parent must not be group/world writable"
        )

    return parent


def _require_endpoint_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ContainmentManagerEndpointError(
            "cannot inspect manager endpoint path"
        ) from exc

    raise ContainmentManagerEndpointError(
        "manager endpoint path already exists"
    )


def _read_socket_identity(path: Path) -> tuple[_SocketIdentity, os.stat_result]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ContainmentManagerEndpointError(
            "manager endpoint socket is unavailable"
        ) from exc

    if not stat.S_ISSOCK(info.st_mode):
        raise ContainmentManagerEndpointError(
            "manager endpoint path is not a socket"
        )

    return _SocketIdentity(info.st_dev, info.st_ino), info


def _matches_identity(info: os.stat_result, identity: _SocketIdentity) -> bool:
    return info.st_dev == identity.device and info.st_ino == identity.inode


def _cleanup_owned_path(path: Path, identity: _SocketIdentity | None) -> None:
    if identity is None:
        return

    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ContainmentManagerEndpointError(
            "cannot inspect manager endpoint during cleanup"
        ) from exc

    if not stat.S_ISSOCK(info.st_mode) or not _matches_identity(info, identity):
        raise ContainmentManagerEndpointError(
            "manager endpoint path changed before cleanup"
        )

    try:
        path.unlink()
    except OSError as exc:
        raise ContainmentManagerEndpointError(
            "cannot remove manager endpoint socket"
        ) from exc


class UnixContainmentManagerListener:
    """Own one secure pathname AF_UNIX listener.

    The parent directory must already exist and be policy-owned. Existing
    endpoint paths are never removed automatically.
    """

    def __init__(
        self,
        *,
        policy: UnixManagerEndpointPolicy,
        sock: socket.socket,
        identity: _SocketIdentity,
    ) -> None:
        self._policy = policy
        self._sock = sock
        self._identity = identity
        self._closed = False

    @classmethod
    def create(
        cls,
        policy: UnixManagerEndpointPolicy,
    ) -> "UnixContainmentManagerListener":
        _validate_parent(policy)
        _require_endpoint_absent(policy.path)

        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        sock.set_inheritable(False)
        identity: _SocketIdentity | None = None

        try:
            sock.bind(os.fspath(policy.path))
            identity, info = _read_socket_identity(policy.path)

            if info.st_uid != policy.socket_uid or info.st_gid != policy.socket_gid:
                os.chown(
                    policy.path,
                    policy.socket_uid,
                    policy.socket_gid,
                    follow_symlinks=False,
                )

            os.chmod(
                policy.path,
                policy.socket_mode,
            )

            verified_identity, verified = _read_socket_identity(policy.path)
            if verified_identity != identity:
                raise ContainmentManagerEndpointError(
                    "manager endpoint socket changed during setup"
                )
            if (
                verified.st_uid != policy.socket_uid
                or verified.st_gid != policy.socket_gid
            ):
                raise ContainmentManagerEndpointError(
                    "manager endpoint socket ownership does not match policy"
                )
            if stat.S_IMODE(verified.st_mode) != policy.socket_mode:
                raise ContainmentManagerEndpointError(
                    "manager endpoint socket mode does not match policy"
                )

            # No peer can complete a stream connection until listen() occurs.
            # Permission/ownership verification therefore happens first.
            sock.listen(policy.backlog)

            return cls(
                policy=policy,
                sock=sock,
                identity=identity,
            )
        except Exception as exc:
            try:
                sock.close()
            finally:
                try:
                    _cleanup_owned_path(policy.path, identity)
                except ContainmentManagerEndpointError as cleanup_exc:
                    raise cleanup_exc from exc
            if isinstance(exc, ContainmentManagerEndpointError):
                raise
            raise ContainmentManagerEndpointError(
                "cannot create manager endpoint"
            ) from exc

    @property
    def path(self) -> Path:
        return self._policy.path

    @property
    def fileno(self) -> int:
        return self._sock.fileno()

    @property
    def inheritable(self) -> bool:
        return self._sock.get_inheritable()

    def accept(self) -> socket.socket:
        if self._closed:
            raise ContainmentManagerEndpointError(
                "manager endpoint listener is closed"
            )

        try:
            connection, _address = self._sock.accept()
        except OSError as exc:
            raise ContainmentManagerEndpointError(
                "cannot accept manager connection"
            ) from exc

        connection.set_inheritable(False)
        return connection

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        try:
            self._sock.close()
        finally:
            _cleanup_owned_path(
                self._policy.path,
                self._identity,
            )

    def __enter__(self) -> "UnixContainmentManagerListener":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
