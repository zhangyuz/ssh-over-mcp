from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .containment import ContainmentError, ContainmentUnavailableError

_UCRED = struct.Struct("=iII")
_MAX_KERNEL_ID = (1 << 32) - 1


class ContainmentManagerPeerAuthError(ContainmentError):
    """The connected local peer does not match the configured OS identity."""


@dataclass(frozen=True, slots=True)
class LinuxPeerCredentials:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class LinuxPeerCredentialPolicy:
    """Exact Linux SO_PEERCRED policy for one pre-connected Unix peer."""

    expected_uid: int
    expected_gid: int | None = None

    def __post_init__(self) -> None:
        _validate_kernel_id(self.expected_uid, "expected_uid")
        if self.expected_gid is not None:
            _validate_kernel_id(self.expected_gid, "expected_gid")


def _validate_kernel_id(value: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_KERNEL_ID
    ):
        raise ValueError(f"{label} must be a valid Linux uid/gid value")


def read_linux_unix_peer_credentials(
    sock: socket.socket,
    *,
    allow_invisible_pid: bool = False,
) -> LinuxPeerCredentials:
    """Read kernel-captured credentials for a connected AF_UNIX peer."""

    if sock.family != socket.AF_UNIX:
        raise ValueError("peer credentials require AF_UNIX")

    try:
        socket_type = sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    except OSError as exc:
        raise ContainmentUnavailableError(
            "cannot inspect containment-manager peer socket"
        ) from exc
    if socket_type != socket.SOCK_STREAM:
        raise ValueError("peer credentials require SOCK_STREAM")

    try:
        sock.getpeername()
    except OSError as exc:
        raise ContainmentUnavailableError(
            "containment-manager peer socket is not connected"
        ) from exc

    if not hasattr(socket, "SO_PEERCRED"):
        raise ContainmentUnavailableError(
            "Linux SO_PEERCRED is unavailable"
        )

    try:
        raw = sock.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            _UCRED.size,
        )
    except OSError as exc:
        raise ContainmentUnavailableError(
            "cannot read containment-manager peer credentials"
        ) from exc

    if len(raw) != _UCRED.size:
        raise ContainmentUnavailableError(
            "invalid containment-manager peer credential size"
        )

    pid, uid, gid = _UCRED.unpack(raw)
    if pid < 0 or (pid == 0 and not allow_invisible_pid):
        raise ContainmentUnavailableError(
            "invalid containment-manager peer pid"
        )

    return LinuxPeerCredentials(
        pid=pid,
        uid=uid,
        gid=gid,
    )


def authenticate_linux_unix_peer(
    sock: socket.socket,
    policy: LinuxPeerCredentialPolicy,
    *,
    allow_invisible_pid: bool = False,
) -> LinuxPeerCredentials:
    """Fail closed unless the kernel-reported peer matches policy."""

    credentials = read_linux_unix_peer_credentials(
        sock,
        allow_invisible_pid=allow_invisible_pid,
    )

    if credentials.uid != policy.expected_uid:
        raise ContainmentManagerPeerAuthError(
            "containment manager peer is not authorized"
        )
    if (
        policy.expected_gid is not None
        and credentials.gid != policy.expected_gid
    ):
        raise ContainmentManagerPeerAuthError(
            "containment manager peer is not authorized"
        )

    return credentials
