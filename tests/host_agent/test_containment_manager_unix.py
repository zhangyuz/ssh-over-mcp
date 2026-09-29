from __future__ import annotations

import os
import socket
import struct
import threading
import time

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
    ContainmentManagerProtocolError,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    ContainmentServiceIdentityPlan,
    LinuxProcessIdentity,
    LinuxProcessIdentityError,
)
from ssh_over_mcp.host_agent.containment_manager_peer import (
    ContainmentManagerPeerAuthError,
    LinuxPeerCredentialPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_unix import (
    UnixContainmentManagerTransport,
    connect_authenticated_containment_manager,
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


def peer_policy() -> LinuxPeerCredentialPolicy:
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("Linux SO_PEERCRED is required")
    return LinuxPeerCredentialPolicy(
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    )


def service_identity_plan() -> ContainmentServiceIdentityPlan:
    return ContainmentServiceIdentityPlan(
        manager=LinuxProcessIdentity(uid=2101, gid=3101),
        host_agent=LinuxProcessIdentity(uid=2102, gid=3102),
        workload=LinuxProcessIdentity(uid=2103, gid=3103),
        manager_client_gid=3199,
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
        kwargs={"peer_policy": peer_policy()},
        daemon=True,
    )
    thread.start()
    return thread


def test_connect_validates_host_agent_identity_before_socket_open(
    tmp_path,
    monkeypatch,
):
    plan = service_identity_plan()
    observed = {}

    def reject_identity(policy):
        observed["policy"] = policy
        raise LinuxProcessIdentityError("wrong host-agent identity")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.require_linux_process_identity",
        reject_identity,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.socket.socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("socket opened before identity validation")
        ),
    )

    with pytest.raises(
        LinuxProcessIdentityError,
        match="wrong host-agent identity",
    ):
        connect_authenticated_containment_manager(
            tmp_path / "manager.sock",
            identity_plan=plan,
        )

    assert observed["policy"] == plan.host_agent_process_policy()


def test_connect_uses_identity_plan_and_owns_transport_lifecycle(
    tmp_path,
    monkeypatch,
):
    plan = service_identity_plan()
    observed = {}

    class FakeSocket:
        def __init__(self):
            self.inheritable = True
            self.timeout = None
            self.connected_path = None
            self.closed = False

        def set_inheritable(self, value):
            self.inheritable = value

        def settimeout(self, value):
            self.timeout = value

        def connect(self, value):
            self.connected_path = value

        def close(self):
            self.closed = True

    sock = FakeSocket()

    def socket_factory(family, socket_type):
        observed["socket_args"] = (family, socket_type)
        return sock

    class FakeTransport:
        def __init__(
            self,
            connected_sock,
            *,
            peer_policy,
            timeout_seconds,
        ):
            observed["transport_sock"] = connected_sock
            observed["peer_policy"] = peer_policy
            observed["transport_timeout"] = timeout_seconds
            self._sock = connected_sock

        def close(self):
            self._sock.close()

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.require_linux_process_identity",
        lambda policy: observed.setdefault("identity_policy", policy),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.socket.socket",
        socket_factory,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.UnixContainmentManagerTransport",
        FakeTransport,
    )

    endpoint = tmp_path / "manager.sock"
    client = connect_authenticated_containment_manager(
        endpoint,
        identity_plan=plan,
        timeout_seconds=1.25,
    )

    assert isinstance(client, ContainmentManagerClient)
    assert observed["identity_policy"] == plan.host_agent_process_policy()
    assert observed["peer_policy"] == plan.host_agent_connect_peer_policy()
    assert observed["socket_args"] == (socket.AF_UNIX, socket.SOCK_STREAM)
    assert observed["transport_sock"] is sock
    assert observed["transport_timeout"] == 1.25
    assert sock.inheritable is False
    assert sock.timeout == 1.25
    assert sock.connected_path == os.fspath(endpoint)
    assert sock.closed is False

    client.close()
    assert sock.closed is True

    with pytest.raises(
        ContainmentUnavailableError,
        match="client is closed",
    ):
        client.create(request())


def test_connect_preserves_peer_auth_failure_and_closes_socket(
    tmp_path,
    monkeypatch,
):
    plan = service_identity_plan()

    class FakeSocket:
        def __init__(self):
            self.closed = False

        def set_inheritable(self, _value):
            return

        def settimeout(self, _value):
            return

        def connect(self, _path):
            return

        def close(self):
            self.closed = True

    sock = FakeSocket()
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.require_linux_process_identity",
        lambda _policy: None,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.socket.socket",
        lambda *_args, **_kwargs: sock,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.UnixContainmentManagerTransport",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ContainmentManagerPeerAuthError("manager peer rejected")
        ),
    )

    with pytest.raises(
        ContainmentManagerPeerAuthError,
        match="manager peer rejected",
    ):
        connect_authenticated_containment_manager(
            tmp_path / "manager.sock",
            identity_plan=plan,
        )

    assert sock.closed is True


def test_connect_failure_closes_socket_and_fails_unavailable(
    tmp_path,
    monkeypatch,
):
    plan = service_identity_plan()

    class FailingSocket:
        def __init__(self):
            self.closed = False

        def set_inheritable(self, _value):
            return

        def settimeout(self, _value):
            return

        def connect(self, _path):
            raise FileNotFoundError("manager endpoint unavailable")

        def close(self):
            self.closed = True

    sock = FailingSocket()
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.require_linux_process_identity",
        lambda _policy: None,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_unix.socket.socket",
        lambda *_args, **_kwargs: sock,
    )

    with pytest.raises(
        ContainmentUnavailableError,
        match="cannot connect to containment manager",
    ):
        connect_authenticated_containment_manager(
            tmp_path / "manager.sock",
            identity_plan=plan,
        )

    assert sock.closed is True


def test_unix_transport_full_manager_lifecycle():
    client_sock, server_sock = socket_pair()
    backend = FakeBackend()
    thread = start_server(server_sock, backend)
    transport = UnixContainmentManagerTransport(
        client_sock,
        peer_policy=peer_policy(),
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
        transport = UnixContainmentManagerTransport(
        client_sock,
        peer_policy=peer_policy(),
    )
        assert transport.inheritable is False
        assert transport.peer_credentials.uid == os.getuid()
        assert transport.peer_credentials.gid == os.getgid()
        transport.close()
    finally:
        server_sock.close()


def test_manager_transport_fd_is_closed_by_child_fd_sanitation():
    if not hasattr(socket, "SO_PEERCRED") or not hasattr(os, "fork"):
        pytest.skip("requires Linux SO_PEERCRED and fork")

    from ssh_over_mcp.host_agent.supervisor import _close_unrelated_fds

    client_sock, server_sock = socket_pair()
    transport = UnixContainmentManagerTransport(
        client_sock,
        peer_policy=peer_policy(),
    )
    manager_fd = transport.fileno
    result_read, result_write = os.pipe()

    pid = os.fork()
    if pid == 0:
        try:
            os.close(result_read)
            _close_unrelated_fds({result_write})
            try:
                os.fstat(manager_fd)
            except OSError:
                os.write(result_write, b"closed")
            else:
                os.write(result_write, b"open")
        finally:
            os._exit(0)

    os.close(result_write)
    try:
        result = os.read(result_read, 16)
        _, status = os.waitpid(pid, 0)
    finally:
        os.close(result_read)
        transport.close()
        server_sock.close()

    assert result == b"closed"
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0


def test_transport_timeout_fails_closed():
    client_sock, server_sock = socket_pair()
    transport = UnixContainmentManagerTransport(
        client_sock,
        peer_policy=peer_policy(),
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
        peer_policy=peer_policy(),
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
        try:
            assert client_sock.recv(1) == b""
        except ConnectionResetError:
            # The server intentionally closes as soon as the invalid header is
            # detected. Linux may report RST when unread payload bytes remain.
            pass
    finally:
        client_sock.close()
        thread.join(timeout=1.0)

    assert backend.handle.attached == []


def test_transport_rejects_non_unix_socket():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(ValueError, match="AF_UNIX"):
            UnixContainmentManagerTransport(
                tcp,
                peer_policy=peer_policy(),
            )
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
        peer_policy=peer_policy(),
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


def test_transport_rejects_malformed_outbound_frame_before_send():
    client_sock, server_sock = socket_pair()
    transport = UnixContainmentManagerTransport(
            client_sock,
            peer_policy=peer_policy(),
        )
    try:
        bad = (
            MANAGER_PROTOCOL_MAGIC
            + struct.pack(">I", 10)
            + b"{}"
        )
        with pytest.raises(
            ContainmentManagerProtocolError,
            match="frame length",
        ):
            transport.round_trip(bad)

        server_sock.setblocking(False)
        with pytest.raises(BlockingIOError):
            server_sock.recv(1)
    finally:
        transport.close()
        server_sock.close()


@pytest.mark.parametrize(
    "timeout",
    [True, 0, -1, float("inf"), float("nan"), 31],
)
def test_transport_rejects_invalid_timeouts(timeout):
    client_sock, server_sock = socket_pair()
    try:
        with pytest.raises(ValueError, match="timeout"):
            UnixContainmentManagerTransport(
                client_sock,
                peer_policy=peer_policy(),
                timeout_seconds=timeout,
            )
    finally:
        client_sock.close()
        server_sock.close()


def test_round_trip_timeout_is_total_deadline_not_per_recv():
    client_sock, server_sock = socket_pair()

    def drip_server() -> None:
        try:
            server_sock.recv(65536)
            payload = b"{}"
            frame = (
                MANAGER_PROTOCOL_MAGIC
                + struct.pack(">I", len(payload))
                + payload
            )
            for byte in frame:
                try:
                    server_sock.sendall(bytes([byte]))
                except OSError:
                    return
                time.sleep(0.015)
        finally:
            server_sock.close()

    thread = threading.Thread(
        target=drip_server,
        daemon=True,
    )
    thread.start()

    transport = UnixContainmentManagerTransport(
        client_sock,
        peer_policy=peer_policy(),
        timeout_seconds=0.05,
    )
    client = ContainmentManagerClient(transport)

    started = time.monotonic()
    try:
        with pytest.raises(
            ContainmentUnavailableError,
            match="timed out",
        ):
            client.create(request())
        elapsed = time.monotonic() - started
        assert elapsed < 0.20
    finally:
        transport.close()
        thread.join(timeout=1.0)


def test_broken_response_poisons_transport():
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
        peer_policy=peer_policy(),
        timeout_seconds=1.0,
    )
    client = ContainmentManagerClient(transport)

    try:
        with pytest.raises(ContainmentUnavailableError):
            client.create(request())

        with pytest.raises(
            ContainmentUnavailableError,
            match="closed",
        ):
            client.create(request())
    finally:
        transport.close()
        thread.join(timeout=1.0)


def test_transport_rejects_unconnected_unix_stream_socket():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ValueError, match="connected"):
            UnixContainmentManagerTransport(
                sock,
                peer_policy=peer_policy(),
            )
    finally:
        sock.close()


def test_transport_peer_auth_failure_closes_socket():
    client_sock, server_sock = socket_pair()
    try:
        wrong_uid = 0 if os.getuid() != 0 else 1
        with pytest.raises(ContainmentManagerPeerAuthError):
            UnixContainmentManagerTransport(
                client_sock,
                peer_policy=LinuxPeerCredentialPolicy(
                    expected_uid=wrong_uid,
                ),
            )

        assert client_sock.fileno() == -1
    finally:
        server_sock.close()


def test_server_peer_auth_failure_closes_before_protocol_read():
    client_sock, server_sock = socket_pair()
    backend = FakeBackend()
    dispatcher = ContainmentManagerDispatcher(
        backend,
        capability_factory=lambda: "A" * 43,
    )
    wrong_uid = 0 if os.getuid() != 0 else 1

    try:
        with pytest.raises(ContainmentManagerPeerAuthError):
            serve_containment_manager_connection(
                server_sock,
                dispatcher,
                peer_policy=LinuxPeerCredentialPolicy(
                    expected_uid=wrong_uid,
                ),
            )

        assert server_sock.fileno() == -1
        assert backend.handle.attached == []
    finally:
        client_sock.close()
