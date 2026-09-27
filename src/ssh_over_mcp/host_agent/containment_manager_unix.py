from __future__ import annotations

import math
import socket
import struct
import threading

from .containment import ContainmentUnavailableError
from .containment_manager import (
    MANAGER_PROTOCOL_MAGIC,
    MAX_MANAGER_MESSAGE_BYTES,
    ContainmentManagerDispatcher,
    ContainmentManagerProtocolError,
    ContainmentManagerTransport,
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
    allow_clean_eof: bool = False,
) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size

    while remaining:
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
    allow_clean_eof: bool = False,
) -> bytes | None:
    header = _recv_exact(
        sock,
        _HEADER_SIZE,
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

    payload = _recv_exact(sock, length)
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
        self._sock.settimeout(timeout_seconds)
        self._lock = threading.Lock()
        self._closed = False

    @property
    def fileno(self) -> int:
        return self._sock.fileno()

    @property
    def inheritable(self) -> bool:
        return self._sock.get_inheritable()

    def round_trip(self, frame: bytes) -> bytes:
        if self._closed:
            raise ContainmentUnavailableError(
                "containment manager transport is closed"
            )

        _validate_complete_frame(frame)

        with self._lock:
            try:
                self._sock.sendall(frame)
            except TimeoutError as exc:
                raise ContainmentUnavailableError(
                    "containment manager transport timed out"
                ) from exc
            except OSError as exc:
                raise ContainmentUnavailableError(
                    "containment manager transport write failed"
                ) from exc

            response = _recv_frame(self._sock)
            assert response is not None
            return response

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def serve_containment_manager_connection(
    sock: socket.socket,
    dispatcher: ContainmentManagerDispatcher,
) -> None:
    """Serve a single already-authenticated local manager connection.

    Endpoint creation, accept policy, peer credentials, UID separation and
    daemon lifecycle are intentionally outside this function.
    """

    _require_unix_stream(sock)
    sock.set_inheritable(False)

    try:
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
