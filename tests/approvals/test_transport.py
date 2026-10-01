from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import pytest

from ssh_over_mcp.approvals.protocol import PingRequest, PongResponse, encode_ledger_message
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED required",
)


def _listener(path: Path) -> socket.socket:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(path))
    listener.listen(1)
    return listener


def test_unix_transport_authenticates_server_before_sending_request(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.transport import LedgerTransportError, UnixLedgerTransport

    path = tmp_path / "ledger.sock"
    listener = _listener(path)
    received: list[bytes] = []

    def server() -> None:
        conn, _ = listener.accept()
        try:
            conn.settimeout(1)
            received.append(conn.recv(4096))
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        transport = UnixLedgerTransport(
            path,
            LinuxPeerCredentialPolicy(expected_uid=os.getuid() + 1),
            timeout_seconds=1.0,
        )
        with pytest.raises(LedgerTransportError, match="server is not authorized"):
            transport.round_trip(
                encode_ledger_message(
                    PingRequest(message_id="msg_" + "1" * 32)
                )
            )
    finally:
        thread.join(timeout=3)

    assert received == [b""]


def test_unix_transport_round_trip_requires_one_framed_response(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.transport import UnixLedgerTransport, receive_ledger_frame

    path = tmp_path / "ledger.sock"
    listener = _listener(path)
    request_frame = encode_ledger_message(
        PingRequest(message_id="msg_" + "1" * 32)
    )
    response_frame = encode_ledger_message(
        PongResponse(message_id="msg_" + "1" * 32)
    )

    def server() -> None:
        conn, _ = listener.accept()
        try:
            assert receive_ledger_frame(conn, require_eof=True) == request_frame
            conn.sendall(response_frame)
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        transport = UnixLedgerTransport(
            path,
            LinuxPeerCredentialPolicy(
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            ),
            timeout_seconds=1.0,
        )
        assert transport.round_trip(request_frame) == response_frame
    finally:
        thread.join(timeout=3)


def test_server_connection_authenticates_peer_before_read_or_dispatch() -> None:
    from ssh_over_mcp.approvals.transport import (
        LedgerTransportError,
        serve_one_ledger_connection,
    )

    server_sock, client_sock = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    secret_frame = b"SUPERSECRET-request-body"
    client_sock.sendall(secret_frame)
    client_sock.shutdown(socket.SHUT_WR)
    calls: list[object] = []

    class Dispatcher:
        def dispatch(self, request, *, peer):
            calls.append((request, peer))
            return PongResponse(message_id=request.message_id)

    try:
        with pytest.raises(LedgerTransportError, match="peer is not authorized"):
            serve_one_ledger_connection(
                server_sock,
                peer_policy=LinuxPeerCredentialPolicy(
                    expected_uid=os.getuid() + 1,
                ),
                dispatcher=Dispatcher(),
                timeout_seconds=1.0,
            )
        server_sock.settimeout(1)
        assert server_sock.recv(len(secret_frame)) == secret_frame
        assert calls == []
    finally:
        server_sock.close()
        client_sock.close()
