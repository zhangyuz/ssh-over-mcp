from __future__ import annotations

import os
import socket
import struct
from pathlib import Path
from typing import Protocol

from ssh_over_mcp.host_agent.containment import ContainmentUnavailableError
from ssh_over_mcp.host_agent.containment_manager_peer import (
    ContainmentManagerPeerAuthError,
    LinuxPeerCredentialPolicy,
    authenticate_linux_unix_peer,
)

from .protocol import (
    LEDGER_PROTOCOL_MAGIC,
    MAX_LEDGER_MESSAGE_BYTES,
    LedgerProtocolError,
    decode_ledger_request,
    encode_ledger_message,
)


class LedgerTransportError(RuntimeError):
    """The local Security Ledger transport failed safely."""


class LedgerTransport(Protocol):
    def round_trip(self, frame: bytes) -> bytes: ...


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except (OSError, TimeoutError):
            raise LedgerTransportError(
                "Security Ledger transport unavailable"
            ) from None
        if not chunk:
            raise LedgerTransportError(
                "Security Ledger frame is truncated"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_ledger_frame(
    sock: socket.socket,
    *,
    require_eof: bool,
) -> bytes:
    header_size = len(LEDGER_PROTOCOL_MAGIC) + 4
    header = _recv_exact(sock, header_size)
    if header[: len(LEDGER_PROTOCOL_MAGIC)] != LEDGER_PROTOCOL_MAGIC:
        raise LedgerTransportError("invalid Security Ledger frame")
    (payload_size,) = struct.unpack(
        ">I",
        header[len(LEDGER_PROTOCOL_MAGIC) :],
    )
    if payload_size > MAX_LEDGER_MESSAGE_BYTES:
        raise LedgerTransportError("invalid Security Ledger frame")
    payload = _recv_exact(sock, payload_size)
    frame = header + payload
    if require_eof:
        try:
            extra = sock.recv(1)
        except (OSError, TimeoutError):
            raise LedgerTransportError(
                "Security Ledger stream did not terminate"
            ) from None
        if extra:
            raise LedgerTransportError(
                "Security Ledger stream contains trailing data"
            )
    return frame


class UnixLedgerTransport:
    def __init__(
        self,
        socket_path: Path,
        expected_server: LinuxPeerCredentialPolicy,
        *,
        timeout_seconds: float = 2.0,
    ) -> None:
        path = Path(socket_path)
        raw = os.fspath(path)
        if (
            "\x00" in raw
            or not path.is_absolute()
            or raw.startswith("//")
            or os.path.normpath(raw) != raw
        ):
            raise ValueError(
                "Security Ledger socket path must be absolute and canonical"
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError(
                "Security Ledger transport timeout must be in (0, 30]"
            )
        self._socket_path = path
        self._expected_server = expected_server
        self._timeout_seconds = float(timeout_seconds)

    def round_trip(self, frame: bytes) -> bytes:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.set_inheritable(False)
        sock.settimeout(self._timeout_seconds)
        try:
            try:
                sock.connect(os.fspath(self._socket_path))
            except OSError:
                raise LedgerTransportError(
                    "Security Ledger transport unavailable"
                ) from None

            try:
                authenticate_linux_unix_peer(
                    sock,
                    self._expected_server,
                    allow_invisible_pid=True,
                )
            except ContainmentManagerPeerAuthError:
                raise LedgerTransportError(
                    "Security Ledger server is not authorized"
                ) from None
            except (ContainmentUnavailableError, ValueError):
                raise LedgerTransportError(
                    "Security Ledger server identity is unavailable"
                ) from None

            try:
                sock.sendall(frame)
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                raise LedgerTransportError(
                    "Security Ledger transport unavailable"
                ) from None
            return receive_ledger_frame(sock, require_eof=True)
        finally:
            sock.close()


def serve_one_ledger_connection(
    connection: socket.socket,
    *,
    peer_policy: LinuxPeerCredentialPolicy,
    dispatcher,
    timeout_seconds: float = 2.0,
) -> None:
    connection.settimeout(timeout_seconds)
    try:
        try:
            peer = authenticate_linux_unix_peer(
                connection,
                peer_policy,
                allow_invisible_pid=True,
            )
        except ContainmentManagerPeerAuthError:
            raise LedgerTransportError(
                "Security Ledger peer is not authorized"
            ) from None
        except (ContainmentUnavailableError, ValueError):
            raise LedgerTransportError(
                "Security Ledger peer identity is unavailable"
            ) from None

        frame = receive_ledger_frame(
            connection,
            require_eof=True,
        )
        try:
            request = decode_ledger_request(frame)
        except LedgerProtocolError:
            raise LedgerTransportError(
                "invalid Security Ledger request"
            ) from None
        response = dispatcher.dispatch(request, peer=peer)
        try:
            connection.sendall(encode_ledger_message(response))
        except OSError:
            raise LedgerTransportError(
                "Security Ledger response could not be sent"
            ) from None
    finally:
        # The owning service is responsible for closing the accepted socket.
        pass
