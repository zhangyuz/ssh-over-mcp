from __future__ import annotations

import importlib
import os
import socket
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from ssh_over_mcp.host_agent.containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentRequest,
    ContainmentStats,
    ContainmentUnavailableError,
)
from ssh_over_mcp.host_agent.containment_manager import (
    ContainmentManagerDispatcher,
    CreateRequest,
    CreateResponse,
    ErrorResponse,
    ManagerLimits,
    decode_manager_response,
    encode_manager_message,
)
from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    ContainmentManagerEndpointError,
    UnixManagerEndpointPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityError,
    LinuxProcessIdentityPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_peer import (
    ContainmentManagerPeerAuthError,
    LinuxPeerCredentialPolicy,
)


def _service_module():
    try:
        return importlib.import_module(
            "ssh_over_mcp.host_agent.containment_manager_service"
        )
    except ModuleNotFoundError:
        pytest.fail("containment manager service module is missing")


@pytest.mark.parametrize(
    "failure_case",
    ["real_uid", "effective_uid", "saved_uid", "supplementary_groups"],
)
def test_identity_failure_happens_before_listener_creation(
    monkeypatch,
    failure_case: str,
):
    module = _service_module()
    events: list[str] = []

    def fail_identity(_policy):
        events.append("identity")
        raise LinuxProcessIdentityError(failure_case)

    def create_listener(_policy):
        events.append("listener")
        return SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(module, "require_linux_process_identity", fail_identity)
    monkeypatch.setattr(
        module.UnixContainmentManagerListener,
        "create",
        create_listener,
    )

    with pytest.raises(LinuxProcessIdentityError):
        module.ContainmentManagerService.create(
            identity_policy=object(),
            endpoint_policy=object(),
            peer_policy=object(),
            dispatcher=object(),
        )

    assert events == ["identity"]


def test_valid_identity_creates_listener_once(monkeypatch):
    module = _service_module()
    events: list[str] = []
    listener = SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(
        module,
        "require_linux_process_identity",
        lambda _policy: events.append("identity"),
    )

    def create_listener(_policy):
        events.append("listener")
        return listener

    monkeypatch.setattr(
        module.UnixContainmentManagerListener,
        "create",
        create_listener,
    )

    service = module.ContainmentManagerService.create(
        identity_policy=object(),
        endpoint_policy=object(),
        peer_policy=object(),
        dispatcher=object(),
    )

    assert events == ["identity", "listener"]
    service.close()


def test_service_close_delegates_once_and_is_idempotent(monkeypatch):
    module = _service_module()
    close_calls: list[str] = []
    listener = SimpleNamespace(
        close=lambda: close_calls.append("close")
    )

    monkeypatch.setattr(
        module,
        "require_linux_process_identity",
        lambda _policy: None,
    )
    monkeypatch.setattr(
        module.UnixContainmentManagerListener,
        "create",
        lambda _policy: listener,
    )

    service = module.ContainmentManagerService.create(
        identity_policy=object(),
        endpoint_policy=object(),
        peer_policy=object(),
        dispatcher=object(),
    )

    service.close()
    service.close()

    assert close_calls == ["close"]


def _current_identity_policy() -> LinuxProcessIdentityPolicy:
    return LinuxProcessIdentityPolicy(
        identity=LinuxProcessIdentity(uid=os.getuid(), gid=os.getgid()),
        supplementary_gids=frozenset(set(os.getgroups()) - {os.getgid()}),
    )


def _endpoint_policy(endpoint: Path) -> UnixManagerEndpointPolicy:
    return UnixManagerEndpointPolicy(
        path=endpoint,
        directory_uid=os.getuid(),
        directory_gid=os.getgid(),
        socket_uid=os.getuid(),
        socket_gid=os.getgid(),
        socket_mode=0o600,
        backlog=4,
    )


def _create_real_service(tmp_path: Path):
    module = _service_module()
    parent = tmp_path / "manager"
    parent.mkdir()
    parent.chmod(0o700)
    endpoint = parent / "manager.sock"
    service = module.ContainmentManagerService.create(
        identity_policy=_current_identity_policy(),
        endpoint_policy=_endpoint_policy(endpoint),
        peer_policy=object(),
        dispatcher=object(),
    )
    return service, endpoint


def test_service_close_removes_still_owned_socket(tmp_path: Path):
    service, endpoint = _create_real_service(tmp_path)

    assert stat.S_ISSOCK(endpoint.lstat().st_mode)

    service.close()

    assert not endpoint.exists()


def test_service_close_accepts_already_absent_endpoint(tmp_path: Path):
    service, endpoint = _create_real_service(tmp_path)
    endpoint.unlink()

    service.close()

    assert not endpoint.exists()


@pytest.mark.parametrize(
    "replacement_kind",
    ["regular_file", "symlink", "different_socket"],
)
def test_service_close_preserves_replacement_path(
    tmp_path: Path,
    replacement_kind: str,
):
    service, endpoint = _create_real_service(tmp_path)
    endpoint.unlink()
    replacement_socket = None

    if replacement_kind == "regular_file":
        endpoint.write_text("replacement", encoding="utf-8")
    elif replacement_kind == "symlink":
        target = endpoint.parent / "replacement-target"
        target.write_text("sentinel", encoding="utf-8")
        endpoint.symlink_to(target)
    else:
        replacement_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement_socket.bind(os.fspath(endpoint))

    try:
        before = endpoint.lstat()
        with pytest.raises(
            ContainmentManagerEndpointError,
            match="changed before cleanup",
        ):
            service.close()
        after = endpoint.lstat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    finally:
        if replacement_socket is not None:
            replacement_socket.close()
            endpoint.unlink(missing_ok=True)


class _QueueListener:
    def __init__(self, accepted):
        self.accepted = list(accepted)
        self.accept_calls = 0

    def accept(self):
        self.accept_calls += 1
        if not self.accepted:
            raise AssertionError("no queued connection")
        value = self.accepted.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    @property
    def fileno(self):
        return 123

    def close(self):
        pass


def _unit_service(module, listener):
    return module.ContainmentManagerService(
        listener=listener,
        peer_policy=object(),
        dispatcher=object(),
    )


def test_serve_one_accepts_and_delegates_exactly_one_session(monkeypatch):
    module = _service_module()
    accepted = object()
    listener = _QueueListener([accepted])
    calls = []
    monkeypatch.setattr(
        module,
        "serve_containment_manager_connection",
        lambda sock, dispatcher, *, peer_policy: calls.append(
            (sock, dispatcher, peer_policy)
        ),
    )
    service = _unit_service(module, listener)

    service.serve_one()

    assert listener.accept_calls == 1
    assert calls == [(accepted, service._dispatcher, service._peer_policy)]


def test_unauthorized_peer_is_session_local(monkeypatch):
    module = _service_module()
    first = object()
    second = object()
    listener = _QueueListener([first, second])
    calls = []

    def serve(sock, _dispatcher, *, peer_policy):
        calls.append((sock, peer_policy))
        if sock is first:
            raise ContainmentManagerPeerAuthError("not authorized")

    monkeypatch.setattr(module, "serve_containment_manager_connection", serve)
    service = _unit_service(module, listener)

    service.serve_one()
    service.serve_one()

    assert [sock for sock, _ in calls] == [first, second]


def test_clean_peer_eof_is_session_local(monkeypatch):
    module = _service_module()
    first = object()
    second = object()
    listener = _QueueListener([first, second])
    calls = []

    monkeypatch.setattr(
        module,
        "serve_containment_manager_connection",
        lambda sock, _dispatcher, *, peer_policy: calls.append(sock),
    )
    service = _unit_service(module, listener)

    service.serve_one()
    service.serve_one()

    assert calls == [first, second]


def test_listener_accept_failure_is_service_fatal(monkeypatch):
    module = _service_module()
    listener = _QueueListener(
        [ContainmentManagerEndpointError("cannot accept manager connection")]
    )
    service = _unit_service(module, listener)

    with pytest.raises(ContainmentManagerEndpointError):
        service.serve_one()


def test_non_auth_transport_failure_is_not_hidden(monkeypatch):
    module = _service_module()
    listener = _QueueListener([object()])

    def fail_transport(_sock, _dispatcher, *, peer_policy):
        raise ContainmentUnavailableError("transport failed")

    monkeypatch.setattr(
        module,
        "serve_containment_manager_connection",
        fail_transport,
    )
    service = _unit_service(module, listener)

    with pytest.raises(ContainmentUnavailableError, match="transport failed"):
        service.serve_one()


def test_serve_one_rejects_closed_service():
    module = _service_module()
    service = _unit_service(module, _QueueListener([]))
    service.close()

    with pytest.raises(
        module.ContainmentManagerServiceError,
        match="closed",
    ):
        service.serve_one()


class _ProtocolHandle(ContainmentHandle):
    def __init__(self) -> None:
        self._closed = False

    @property
    def scope_id(self) -> str:
        return "scope-test-0001"

    def attach(self, pid: int) -> None:
        pass

    def kill_all(self) -> None:
        pass

    def stats(self) -> ContainmentStats:
        return ContainmentStats()

    def close(self) -> None:
        self._closed = True


class _ProtocolBackend(ContainmentBackend):
    def __init__(self) -> None:
        self.fail_next_create = False
        self.created = 0

    @property
    def name(self) -> str:
        return "test"

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        if self.fail_next_create:
            self.fail_next_create = False
            raise ContainmentError("planned create failure")
        self.created += 1
        return _ProtocolHandle()


def _create_protocol_service(tmp_path: Path, backend: _ProtocolBackend):
    module = _service_module()
    parent = tmp_path / "protocol-manager"
    parent.mkdir()
    parent.chmod(0o700)
    endpoint = parent / "manager.sock"
    dispatcher = ContainmentManagerDispatcher(
        backend,
        capability_factory=lambda: "A" * 43,
    )
    service = module.ContainmentManagerService.create(
        identity_policy=_current_identity_policy(),
        endpoint_policy=_endpoint_policy(endpoint),
        peer_policy=LinuxPeerCredentialPolicy(
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        ),
        dispatcher=dispatcher,
    )
    return service, endpoint


def _create_frame(message_id: str, request_id: str) -> bytes:
    return encode_manager_message(
        CreateRequest(
            message_id=message_id,
            request_id=request_id,
            limits=ManagerLimits(
                memory_max_bytes=64 * 1024 * 1024,
                pids_max=16,
                cpu_quota_us=50_000,
                cpu_period_us=100_000,
            ),
        )
    )


def _run_one_session(service, endpoint: Path, frame: bytes) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1.0)
    try:
        client.connect(os.fspath(endpoint))
        client.sendall(frame)
        client.shutdown(socket.SHUT_WR)
        service.serve_one()

        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        client.close()


def test_malformed_session_does_not_poison_next_valid_session(tmp_path: Path):
    backend = _ProtocolBackend()
    service, endpoint = _create_protocol_service(tmp_path, backend)
    bad_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bad_client.settimeout(1.0)
    try:
        bad_client.connect(os.fspath(endpoint))
        bad_client.sendall(
            b"BADBAD"
            + (2).to_bytes(4, "big")
            + b"{}"
        )
        bad_client.shutdown(socket.SHUT_WR)
        service.serve_one()
        try:
            bad_client.recv(1)
        except ConnectionResetError:
            pass

        response = _run_one_session(
            service,
            endpoint,
            _create_frame("msg-test-0001", "req-test-0001"),
        )
        decoded = decode_manager_response(response)
        assert isinstance(decoded, CreateResponse)
        assert backend.created == 1
    finally:
        bad_client.close()
        service.close()


def test_backend_operation_error_response_does_not_poison_next_session(
    tmp_path: Path,
):
    backend = _ProtocolBackend()
    backend.fail_next_create = True
    service, endpoint = _create_protocol_service(tmp_path, backend)

    try:
        first = decode_manager_response(
            _run_one_session(
                service,
                endpoint,
                _create_frame("msg-test-0002", "req-test-0002"),
            )
        )
        assert isinstance(first, ErrorResponse)
        assert first.code == "operation_failed"

        second = decode_manager_response(
            _run_one_session(
                service,
                endpoint,
                _create_frame("msg-test-0003", "req-test-0003"),
            )
        )
        assert isinstance(second, CreateResponse)
        assert backend.created == 1
    finally:
        service.close()


def test_serve_forever_stops_without_accept_when_stop_already_requested(
    monkeypatch,
):
    module = _service_module()
    listener = _QueueListener([])
    service = _unit_service(module, listener)
    waits = []
    monkeypatch.setattr(
        module,
        "_wait_listener_readable",
        lambda fd: waits.append(fd) or True,
        raising=False,
    )

    service.serve_forever(stop_requested=lambda: True)

    assert waits == []
    assert listener.accept_calls == 0


def test_serve_forever_rechecks_stop_after_readiness(monkeypatch):
    module = _service_module()
    service = _unit_service(module, _QueueListener([]))
    stop_states = iter([False, True])
    served = []
    monkeypatch.setattr(
        module,
        "_wait_listener_readable",
        lambda _fd: True,
        raising=False,
    )
    monkeypatch.setattr(
        service,
        "serve_one",
        lambda: served.append("served"),
    )

    service.serve_forever(stop_requested=lambda: next(stop_states))

    assert served == []


def test_interrupted_readiness_poll_retries_via_stop_check(monkeypatch):
    module = _service_module()

    def interrupt(*_args):
        raise InterruptedError

    monkeypatch.setattr(module.select, "select", interrupt)

    assert module._wait_listener_readable(123) is False


def test_readiness_infrastructure_error_is_service_fatal(monkeypatch):
    module = _service_module()

    def fail(*_args):
        raise OSError("poll failed")

    monkeypatch.setattr(module.select, "select", fail)

    with pytest.raises(
        module.ContainmentManagerServiceError,
        match="cannot poll containment manager listener",
    ):
        module._wait_listener_readable(123)


def test_ready_listener_serves_one_then_returns_to_poll(monkeypatch):
    module = _service_module()
    service = _unit_service(module, _QueueListener([]))
    stop_states = iter([False, False, True])
    served = []

    monkeypatch.setattr(
        module,
        "_wait_listener_readable",
        lambda _fd: True,
        raising=False,
    )
    monkeypatch.setattr(
        service,
        "serve_one",
        lambda: served.append("served"),
    )

    service.serve_forever(stop_requested=lambda: next(stop_states))

    assert served == ["served"]


def test_serve_forever_rejects_closed_service():
    module = _service_module()
    service = _unit_service(module, _QueueListener([]))
    service.close()

    with pytest.raises(
        module.ContainmentManagerServiceError,
        match="closed",
    ):
        service.serve_forever(stop_requested=lambda: True)


def test_serve_forever_stops_while_idle(tmp_path: Path):
    service, _endpoint = _create_real_service(tmp_path)
    stop = threading.Event()
    errors: list[BaseException] = []

    def run_service() -> None:
        try:
            service.serve_forever(stop_requested=stop.is_set)
        except ContainmentError as exc:
            errors.append(exc)

    thread = threading.Thread(target=run_service, daemon=True)
    thread.start()
    time.sleep(0.05)
    stop.set()
    thread.join(timeout=1.0)

    try:
        assert thread.is_alive() is False
        assert errors == []
    finally:
        service.close()


def test_host_agent_package_exports_manager_service():
    module = _service_module()
    from ssh_over_mcp import host_agent

    assert host_agent.ContainmentManagerService is module.ContainmentManagerService
    assert (
        host_agent.ContainmentManagerServiceError
        is module.ContainmentManagerServiceError
    )
