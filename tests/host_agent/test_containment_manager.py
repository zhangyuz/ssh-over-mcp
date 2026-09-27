from __future__ import annotations

import struct

import pytest

from ssh_over_mcp.host_agent.containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
)
from ssh_over_mcp.host_agent.containment_manager import (
    MANAGER_PROTOCOL_MAGIC,
    MAX_MANAGER_MESSAGE_BYTES,
    AckResponse,
    AttachRequest,
    ContainmentManagerClient,
    ContainmentManagerDispatcher,
    ContainmentManagerProtocolError,
    CreateRequest,
    InMemoryContainmentManagerTransport,
    KillRequest,
    ManagerLimits,
    StatsRequest,
    decode_manager_request,
    encode_manager_message,
)


class FakeHandle(ContainmentHandle):
    def __init__(self, scope_id: str) -> None:
        self._scope_id = scope_id
        self.attached: list[int] = []
        self.kills = 0
        self.closed = False

    @property
    def scope_id(self) -> str:
        return self._scope_id

    def attach(self, pid: int) -> None:
        self.attached.append(pid)

    def kill_all(self) -> None:
        self.kills += 1

    def stats(self) -> ContainmentStats:
        return ContainmentStats(
            memory_current_bytes=123,
            pids_current=len(self.attached),
            cpu_usage_usec=456,
            populated=bool(self.attached) and self.kills == 0,
        )

    def close(self) -> None:
        self.closed = True


class FakeBackend(ContainmentBackend):
    def __init__(self) -> None:
        self.requests: list[ContainmentRequest] = []
        self.handles: list[FakeHandle] = []

    @property
    def name(self) -> str:
        return "fake-manager-backend"

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        self.requests.append(request)
        handle = FakeHandle(f"scope_{len(self.handles):08d}")
        self.handles.append(handle)
        return handle


def limits() -> ContainmentLimits:
    return ContainmentLimits(
        memory_max_bytes=512 * 1024 * 1024,
        pids_max=64,
        cpu_quota_us=50_000,
        cpu_period_us=100_000,
    )


def request() -> ContainmentRequest:
    return ContainmentRequest(
        request_id="req_12345678",
        limits=limits(),
    )


def make_client(
    *,
    capability: str = "A" * 43,
) -> tuple[
    ContainmentManagerClient,
    FakeBackend,
    ContainmentManagerDispatcher,
]:
    backend = FakeBackend()
    dispatcher = ContainmentManagerDispatcher(
        backend,
        capability_factory=lambda: capability,
    )
    transport = InMemoryContainmentManagerTransport(dispatcher)
    return ContainmentManagerClient(transport), backend, dispatcher


def test_manager_client_round_trip_lifecycle():
    client, backend, _dispatcher = make_client()

    handle = client.create(request())
    handle.attach(4321)
    stats = handle.stats()
    handle.kill_all()
    handle.close()
    handle.close()

    assert client.name == "containment-manager"
    assert backend.requests == [request()]
    assert backend.handles[0].attached == [4321]
    assert backend.handles[0].kills == 1
    assert backend.handles[0].closed is True
    assert stats.memory_current_bytes == 123
    assert stats.pids_current == 1
    assert stats.cpu_usage_usec == 456


def test_protocol_contains_no_command_or_path_fields():
    message = CreateRequest(
        message_id="msg_12345678",
        request_id="req_12345678",
        limits=ManagerLimits.from_limits(limits()),
    )

    payload = encode_manager_message(message).decode(
        "utf-8",
        errors="ignore",
    )

    for forbidden in (
        "command",
        "executable",
        "argv",
        "cwd",
        "path",
        "shell",
    ):
        assert forbidden not in payload


def test_wrong_capability_is_rejected_without_touching_handle():
    client, backend, dispatcher = make_client()
    handle = client.create(request())

    forged = AttachRequest(
        message_id="msg_12345678",
        scope_id=handle.scope_id,
        capability="B" * 43,
        pid=4321,
    )
    response = dispatcher.handle_frame(
        encode_manager_message(forged)
    )

    from ssh_over_mcp.host_agent.containment_manager import (
        ErrorResponse,
        decode_manager_response,
    )

    decoded = decode_manager_response(response)
    assert isinstance(decoded, ErrorResponse)
    assert decoded.code == "not_authorized"
    assert backend.handles[0].attached == []


def test_unknown_scope_is_indistinguishable_from_wrong_capability():
    _client, _backend, dispatcher = make_client()
    message = StatsRequest(
        message_id="msg_12345678",
        scope_id="scope_99999999",
        capability="A" * 43,
    )

    from ssh_over_mcp.host_agent.containment_manager import (
        ErrorResponse,
        decode_manager_response,
    )

    decoded = decode_manager_response(
        dispatcher.handle_frame(
            encode_manager_message(message)
        )
    )
    assert isinstance(decoded, ErrorResponse)
    assert decoded.code == "not_authorized"


def test_closed_scope_capability_cannot_be_reused():
    client, _backend, _dispatcher = make_client()
    handle = client.create(request())
    handle.close()

    with pytest.raises(ContainmentError, match="closed"):
        handle.kill_all()


def test_response_correlation_is_enforced():
    client, _backend, dispatcher = make_client()

    class WrongCorrelationTransport:
        def round_trip(self, frame: bytes) -> bytes:
            request_message = decode_manager_request(frame)
            return encode_manager_message(
                AckResponse(
                    message_id="msg_different123",
                )
            )

    bad_client = ContainmentManagerClient(
        WrongCorrelationTransport()
    )

    with pytest.raises(ContainmentError, match="correlation"):
        bad_client.create(request())


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"wrong-magic",
        MANAGER_PROTOCOL_MAGIC + struct.pack(">I", 100) + b"{}",
        (
            MANAGER_PROTOCOL_MAGIC
            + struct.pack(">I", MAX_MANAGER_MESSAGE_BYTES + 1)
        ),
    ],
)
def test_invalid_frames_fail_closed(frame: bytes):
    with pytest.raises(ContainmentManagerProtocolError):
        decode_manager_request(frame)


def test_extra_message_fields_are_rejected():
    raw = (
        b'{"version":1,"message_id":"msg_12345678",'
        b'"op":"kill","scope_id":"scope_12345678",'
        b'"capability":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",'
        b'"command":"id"}'
    )
    frame = (
        MANAGER_PROTOCOL_MAGIC
        + struct.pack(">I", len(raw))
        + raw
    )

    with pytest.raises(ContainmentManagerProtocolError):
        decode_manager_request(frame)


def test_capability_must_decode_to_32_bytes():
    with pytest.raises(ValueError):
        KillRequest(
            message_id="msg_12345678",
            scope_id="scope_12345678",
            capability="too-short",
        )


def test_boolean_pid_is_rejected():
    with pytest.raises(ValueError):
        AttachRequest(
            message_id="msg_12345678",
            scope_id="scope_12345678",
            capability="A" * 43,
            pid=True,
        )


def test_non_urlsafe_capability_is_rejected():
    with pytest.raises(ValueError):
        KillRequest(
            message_id="msg_12345678",
            scope_id="scope_12345678",
            capability="!" * 43,
        )


def test_manager_error_does_not_leak_backend_exception_text():
    class FailingBackend(ContainmentBackend):
        @property
        def name(self) -> str:
            return "failing"

        def create(self, request: ContainmentRequest) -> ContainmentHandle:
            raise ContainmentError(
                "secret filesystem detail /sys/fs/cgroup/private"
            )

    dispatcher = ContainmentManagerDispatcher(
        FailingBackend(),
        capability_factory=lambda: "A" * 43,
    )
    message = CreateRequest(
        message_id="msg_12345678",
        request_id="req_12345678",
        limits=ManagerLimits.from_limits(limits()),
    )

    raw = dispatcher.handle_frame(
        encode_manager_message(message)
    )
    decoded_text = raw.decode("utf-8", errors="ignore")

    assert "secret filesystem detail" not in decoded_text
    assert "/sys/fs/cgroup/private" not in decoded_text


def test_failed_create_response_closes_unpublished_scope():
    class InvalidScopeBackend(FakeBackend):
        def create(self, request: ContainmentRequest) -> ContainmentHandle:
            self.requests.append(request)
            handle = FakeHandle("bad")
            self.handles.append(handle)
            return handle

    backend = InvalidScopeBackend()
    dispatcher = ContainmentManagerDispatcher(
        backend,
        capability_factory=lambda: "A" * 43,
    )
    message = CreateRequest(
        message_id="msg_12345678",
        request_id="req_12345678",
        limits=ManagerLimits.from_limits(limits()),
    )

    from ssh_over_mcp.host_agent.containment_manager import (
        ErrorResponse,
        decode_manager_response,
    )

    decoded = decode_manager_response(
        dispatcher.handle_frame(
            encode_manager_message(message)
        )
    )

    assert isinstance(decoded, ErrorResponse)
    assert decoded.code == "operation_failed"
    assert backend.handles[0].closed is True
