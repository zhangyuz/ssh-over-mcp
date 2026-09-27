from __future__ import annotations

import socket
import struct
import threading

import pytest

from ssh_over_mcp.host_agent.containment import (
    ContainmentBackend,
    ContainmentHandle,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
    ContainmentUnavailableError,
)
from ssh_over_mcp.host_agent.containment_manager import (
    MANAGER_PROTOCOL_MAGIC,
    ContainmentManagerClient,
    ContainmentManagerDispatcher,
)
from ssh_over_mcp.host_agent.containment_manager_unix import (
    UnixContainmentManagerTransport,
    serve_containment_manager_connection,
)


class FakeHandle(ContainmentHandle):
    def __init__(self) -> None:
        self.attached: list[int] = []
        self.kills = 0
        self.closed = False

    @property
    def scope_id(self) -> str:
        return "scope_12345678"

    def attach(self, pid: int) -> None:
        self.attached.append(pid)

    def kill_all(self) -> None:
        self.kills += 1

    def stats(self) -> ContainmentStats:
        return ContainmentStats(
            memory_current_bytes=123,
            pids_current=len(self.attached),
            cpu_usage_usec=456,
            populated=False,
        )

    def close(self) -> None:
        self.closed = True


class FakeBackend(ContainmentBackend):
    def __init__(self) -> None:
        self.handle = FakeHandle()

    @property
    def name(self) -> str:
        return "fake"

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        return self.handle


def request() -> ContainmentRequest:
    return ContainmentRequest(
        request_id="req_12345678",
        limits=ContainmentLimits(
            memory_max_bytes=512 * 1024 * 1024,
            pids_max=64,
            cpu_quota_us=50_000,
            cpu_period_us=100_000,
        ),
    )


def socket_pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )


def start_server(
    server_sock: socket.socket,
    backend: FakeBackend,
) -> threading.Thread:
    dispatcher = ContainmentManagerDispatcher(
        backend,
        capability_factory=lambda: "A" * 43,
    )
    thread = threading.Thread(
        target=serve_containment_manager_connection,
        args=(server_sock, dispatcher),
        daemon=True,
    )
    thread.start()
    return thread


def test_unix_transport_full_manager_lifecycle():
    client_sock, server_sock = socket_pair()
    backend = FakeBackend()
    thread = start_server(server_sock, backend)
    transport = UnixContainmentManagerTransport(
        client_sock,
        timeout_seconds=1.0,
    )
    client = ContainmentManagerClient(transport)

    try:
        handle = client.create(request())
        handle.attach(4321)
        stats = handle.stats()
        handle.kill_all()
        handle.close()

        assert backend.handle.attached == [4321]
        assert backend.handle.kills == 1
        assert backend.handle.closed is True
        assert stats.memory_current_bytes == 123
        assert stats.cpu_usage_usec == 456
    finally:
        transport.close()
        thread.join(timeout=1.0)

    assert thread.is_alive() is False


def test_transport_socket_is_non_inheritable():
    client_sock, server_sock = socket_pair()
    try:
        client_sock.set_inheritable(True)
        transport = UnixContainmentManagerTransport(client_sock)
        assert transport.inheritable is False
        transport.close()
    finally:
        server_sock.close()


def test_transport_timeout_fails_closed():
    client_sock, server_sock = socket_pair()
    transport = UnixContainmentManagerTransport(
        client_sock,
        timeout_seconds=0.01,
    )
    client = ContainmentManagerClient(transport)

    try:
        with pytest.raises(
            ContainmentUnavailableError,
            match="timed out",
        ):
            client.create(request())
    finally:
        transport.close()
        server_sock.close()


def test_truncated_manager_response_fails_closed():
    client_sock, server_sock = socket_pair()

    def broken_server() -> None:
        try:
            server_sock.recv(65536)
            server_sock.sendall(
                MANAGER_PROTOCOL_MAGIC
                + struct.pack(">I", 100)
                + b"{}"
            )
        finally:
            server_sock.close()

    thread = threading.Thread(
        target=broken_server,
        daemon=True,
    )
    thread.start()

    transport = UnixContainmentManagerTransport(
        client_sock,
        timeout_seconds=1.0,
    )
    client = ContainmentManagerClient(transport)

    try:
        with pytest.raises(
            ContainmentUnavailableError,
            match="invalid response|closed mid-frame",
        ):
            client.create(request())
    finally:
        transport.close()
        thread.join(timeout=1.0)


def test_server_closes_session_on_malformed_frame():
    client_sock, server_sock = socket_pair()
    backend = FakeBackend()
    thread = start_server(server_sock, backend)

    try:
        client_sock.sendall(
            b"BADBAD"
            + struct.pack(">I", 2)
            + b"{}"
        )
        client_sock.settimeout(1.0)
        assert client_sock.recv(1) == b""
    finally:
        client_sock.close()
        thread.join(timeout=1.0)

    assert backend.handle.attached == []


def test_transport_rejects_non_unix_socket():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(ValueError, match="AF_UNIX"):
            UnixContainmentManagerTransport(tcp)
    finally:
        tcp.close()


def test_schema_invalid_manager_response_is_unavailable():
    client_sock, server_sock = socket_pair()

    def invalid_server() -> None:
        try:
            server_sock.recv(65536)
            raw = b"{}"
            server_sock.sendall(
                MANAGER_PROTOCOL_MAGIC
                + struct.pack(">I", len(raw))
                + raw
            )
        finally:
            server_sock.close()

    thread = threading.Thread(
        target=invalid_server,
        daemon=True,
    )
    thread.start()

    transport = UnixContainmentManagerTransport(
        client_sock,
        timeout_seconds=1.0,
    )
    client = ContainmentManagerClient(transport)

    try:
        with pytest.raises(
            ContainmentUnavailableError,
            match="invalid response",
        ):
            client.create(request())
    finally:
        transport.close()
        thread.join(timeout=1.0)
