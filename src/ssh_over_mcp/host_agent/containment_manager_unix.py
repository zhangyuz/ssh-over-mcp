from __future__ import annotations

import math
import socket
import struct
import threading
import time

from .containment import ContainmentUnavailableError
from .containment_manager import (
    MANAGER_PROTOCOL_MAGIC,
    MAX_MANAGER_MESSAGE_BYTES,
    ContainmentManagerDispatcher,
    ContainmentManagerProtocolError,
    ContainmentManagerTransport,
)
from .containment_manager_peer import (
    LinuxPeerCredentialPolicy,
    LinuxPeerCredentials,
    authenticate_linux_unix_peer,
)

_HEADER_SIZE = len(MANAGER_PROTOCOL_MAGIC) + 4


def _require_unix_stream(sock: socket.socket) -> None:
    if sock.family != socket.AF_UNIX:
        raise ValueError("containment manager transport requires AF_UNIX")
    try:
        socket_type = sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    except OSError as exc:
        raise ValueError("cannot inspect containment manager socket type") from exc
    if socket_type != socket.SOCK_STREAM:
        raise ValueError("containment manager transport requires SOCK_STREAM")
    try:
        sock.getpeername()
    except OSError as exc:
        raise ValueError(
            "containment manager transport requires a connected socket"
        ) from exc


def _validate_complete_frame(frame: bytes) -> None:
    if len(frame) < _HEADER_SIZE:
        raise ContainmentManagerProtocolError(
            "invalid outbound containment-manager frame"
        )
    if frame[: len(MANAGER_PROTOCOL_MAGIC)] != MANAGER_PROTOCOL_MAGIC:
        raise ContainmentManagerProtocolError(
            "invalid outbound containment-manager magic"
        )

    (length,) = struct.unpack(
        ">I",
        frame[len(MANAGER_PROTOCOL_MAGIC) : _HEADER_SIZE],
    )
    if length > MAX_MANAGER_MESSAGE_BYTES:
        raise ContainmentManagerProtocolError(
            "outbound containment-manager frame exceeds maximum"
        )
    if len(frame) != _HEADER_SIZE + length:
        raise ContainmentManagerProtocolError(
            "invalid outbound containment-manager frame length"
        )


def _recv_exact(
    sock: socket.socket,
    size: int,
    *,
    deadline: float | None = None,
    allow_clean_eof: bool = False,
) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size

    while remaining:
        if deadline is not None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise ContainmentUnavailableError(
                    "containment manager transport timed out"
                )
            sock.settimeout(remaining_time)

        try:
            chunk = sock.recv(remaining)
        except TimeoutError as exc:
            raise ContainmentUnavailableError(
                "containment manager transport timed out"
            ) from exc
        except OSError as exc:
            raise ContainmentUnavailableError(
                "containment manager transport read failed"
            ) from exc

        if not chunk:
            if allow_clean_eof and not chunks:
                return None
            raise ContainmentUnavailableError(
                "containment manager connection closed mid-frame"
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _recv_frame(
    sock: socket.socket,
    *,
    deadline: float | None = None,
    allow_clean_eof: bool = False,
) -> bytes | None:
    header = _recv_exact(
        sock,
        _HEADER_SIZE,
        deadline=deadline,
        allow_clean_eof=allow_clean_eof,
    )
    if header is None:
        return None

    if header[: len(MANAGER_PROTOCOL_MAGIC)] != MANAGER_PROTOCOL_MAGIC:
        raise ContainmentManagerProtocolError(
            "invalid containment-manager transport magic"
        )

    (length,) = struct.unpack(
        ">I",
        header[len(MANAGER_PROTOCOL_MAGIC) :],
    )
    if length > MAX_MANAGER_MESSAGE_BYTES:
        raise ContainmentManagerProtocolError(
            "containment-manager transport frame exceeds maximum"
        )

    payload = _recv_exact(
        sock,
        length,
        deadline=deadline,
    )
    assert payload is not None
    return header + payload


class UnixContainmentManagerTransport(ContainmentManagerTransport):
    """Synchronous transport over one pre-connected Unix stream socket.

    This class intentionally does not know a socket path and cannot establish a
    new manager session. Connection acquisition/authentication is a separate
    privilege-boundary concern.
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        peer_policy: LinuxPeerCredentialPolicy,
        timeout_seconds: float = 2.0,
    ) -> None:
        _require_unix_stream(sock)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 30
        ):
            raise ValueError(
                "containment manager timeout must be in (0, 30] seconds"
            )

        self._sock = sock
        self._sock.set_inheritable(False)
        try:
            self._peer_credentials = authenticate_linux_unix_peer(
                self._sock,
                peer_policy,
            )
        except Exception:
            try:
                self._sock.close()
            except OSError:
                pass
            raise
        self._timeout_seconds = float(timeout_seconds)
        self._lock = threading.Lock()
        self._closed = False

    @property
    def peer_credentials(self) -> LinuxPeerCredentials:
        return self._peer_credentials

    @property
    def fileno(self) -> int:
        return self._sock.fileno()

    @property
    def inheritable(self) -> bool:
        return self._sock.get_inheritable()

    def _close_unlocked(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass

    def round_trip(self, frame: bytes) -> bytes:
        _validate_complete_frame(frame)

        with self._lock:
            if self._closed:
                raise ContainmentUnavailableError(
                    "containment manager transport is closed"
                )

            deadline = time.monotonic() + self._timeout_seconds
            try:
                self._sock.settimeout(self._timeout_seconds)
                self._sock.sendall(frame)

                response = _recv_frame(
                    self._sock,
                    deadline=deadline,
                )
                assert response is not None
                return response
            except TimeoutError as exc:
                self._close_unlocked()
                raise ContainmentUnavailableError(
                    "containment manager transport timed out"
                ) from exc
            except (
                ContainmentManagerProtocolError,
                ContainmentUnavailableError,
            ):
                self._close_unlocked()
                raise
            except OSError as exc:
                self._close_unlocked()
                raise ContainmentUnavailableError(
                    "containment manager transport I/O failed"
                ) from exc

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()


def serve_containment_manager_connection(
    sock: socket.socket,
    dispatcher: ContainmentManagerDispatcher,
    *,
    peer_policy: LinuxPeerCredentialPolicy,
) -> None:
    """Serve a single already-authenticated local manager connection.

    Endpoint creation, accept policy, peer credentials, UID separation and
    daemon lifecycle are intentionally outside this function.
    """

    _require_unix_stream(sock)
    sock.set_inheritable(False)

    try:
        authenticate_linux_unix_peer(sock, peer_policy)
        while True:
            try:
                frame = _recv_frame(
                    sock,
                    allow_clean_eof=True,
                )
            except (
                ContainmentManagerProtocolError,
                ContainmentUnavailableError,
            ):
                # Invalid/truncated input terminates the session. There is no
                # trustworthy request identity to which an error can be bound.
                return

            if frame is None:
                return

            try:
                response = dispatcher.handle_frame(frame)
                sock.sendall(response)
            except (
                ContainmentManagerProtocolError,
                OSError,
            ):
                return
    finally:
        try:
            sock.close()
        except OSError:
            pass
