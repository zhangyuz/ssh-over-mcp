import asyncio
from datetime import UTC, datetime

import asyncssh
import pytest

import ssh_over_mcp.ssh.errors as ssh_errors
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.errors import (
    SSHApprovalRequired,
    SSHPolicyDenied,
)
from ssh_over_mcp.ssh.executor import SSHExecutor
from ssh_over_mcp.ssh.protocol import (
    REMOTE_PROTOCOL_COMMAND,
    decode_request,
)
from ssh_over_mcp.ssh.transport import SSHExecutionResult, StructuredSSHTransport


class Policy:
    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    def evaluate(self, request):
        self.calls.append(request)
        return self.decision

    async def authorize(self, context, request, facts):
        decision = self.evaluate(request)
        if decision.decision is Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision is Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        return decision


def context() -> OperationContext:
    return OperationContext(
        request_id="req_" + ("1" * 32),
        principal=PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


class Reader:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def read(self, size):
        await asyncio.sleep(0)
        return self.chunks.pop(0) if self.chunks else b""


class Process:
    def __init__(self, stdout=(b"ok",), stderr=(), delay=0):
        self.stdout = Reader(stdout)
        self.stderr = Reader(stderr)
        self.delay = delay
        self.closed = False
        self.terminated = False
        self.exit_status = 0
        self.exit_signal = None
        self._closed = asyncio.Event()

    async def wait(self, check=False):
        raise AssertionError(
            "manual stream readers must not be combined with process.wait()"
        )

    def terminate(self):
        self.terminated = True

    def close(self):
        self.closed = True
        self._closed.set()

    async def wait_closed(self):
        if self.closed:
            return

        if self.delay <= 0:
            self.closed = True
            self._closed.set()
            return

        try:
            await asyncio.wait_for(
                self._closed.wait(),
                timeout=self.delay,
            )
        except TimeoutError:
            # Simulate a normal remote channel close.
            self.closed = True
            self._closed.set()


class Connection:
    def __init__(self, process):
        self.process = process
        self.calls = []

    async def create_process(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return self.process


class Slot:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class Manager:
    def __init__(self, connection):
        self.connection = connection
        self.get_calls = 0

    def session_slot(self, alias):
        return Slot()

    async def get_connection(self, alias):
        self.get_calls += 1
        return self.connection


ALLOW = PolicyDecision(
    decision=Decision.ALLOW,
    reason="ok",
    risk=RiskLevel.LOW,
    normalized_executable="/usr/bin/git",
    normalized_cwd="/srv/app",
    policy_version="sha256:x",
)


def request() -> EvaluationRequest:
    return EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        executable="/usr/bin/git",
        args=("status",),
        cwd="/srv/app",
    )


@pytest.mark.asyncio
async def test_policy_denial_happens_before_ssh():
    manager = Manager(Connection(Process()))
    executor = SSHExecutor(
        authorizer=Policy(
            PolicyDecision(
                decision=Decision.DENY,
                reason="no",
                risk=RiskLevel.LOW,
                policy_version="sha256:x",
            )
        ),
        connections=manager,
    )

    with pytest.raises(SSHPolicyDenied):
        await executor.execute(request(), context=context())

    assert manager.get_calls == 0


@pytest.mark.asyncio
async def test_approval_required_happens_before_ssh():
    manager = Manager(Connection(Process()))
    executor = SSHExecutor(
        authorizer=Policy(
            PolicyDecision(
                decision=Decision.APPROVAL_REQUIRED,
                reason="approve",
                risk=RiskLevel.HIGH,
                approval_required=True,
                policy_version="sha256:x",
            )
        ),
        connections=manager,
    )

    with pytest.raises(SSHApprovalRequired):
        await executor.execute(request(), context=context())

    assert manager.get_calls == 0


@pytest.mark.asyncio
async def test_fixed_remote_command_and_framed_payload():
    process = Process()
    connection = Connection(process)
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=Manager(connection),
    )

    result = await executor.execute(
        request(),
        context=context(),
        stdin=b"hello",
    )

    command, kwargs = connection.calls[0]
    assert command == REMOTE_PROTOCOL_COMMAND
    assert kwargs["request_pty"] is False
    assert kwargs["encoding"] is None
    assert kwargs["env"] == {}
    assert kwargs["send_env"] == []
    assert kwargs["x11_forwarding"] is False

    envelope, stdin = decode_request(kwargs["input"])
    assert envelope.executable == "/usr/bin/git"
    assert envelope.argv == ("status",)
    assert stdin == b"hello"

    assert result.stdout == b"ok"
    assert result.exit_status == 0


@pytest.mark.asyncio
async def test_output_is_bounded_and_process_closed():
    process = Process(
        stdout=(b"1234567890",),
        delay=0.1,
    )
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=Manager(Connection(process)),
    )

    result = await executor.execute(
        request(),
        context=context(),
        max_output_bytes=5,
    )

    assert result.stdout == b"12345"
    assert result.truncated is True
    assert process.closed is True


@pytest.mark.asyncio
async def test_remote_exit_before_local_deadline_is_not_local_timeout():
    process = Process(delay=0)
    process.exit_status = 143
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=Manager(Connection(process)),
    )

    result = await executor.execute(
        request(),
        context=context(),
        timeout_seconds=1.0,
    )

    assert result.exit_status == 143
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_exact_remote_output_budget_is_not_local_truncation():
    process = Process(stdout=(b"12345",), delay=0)
    process.exit_status = 137
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=Manager(Connection(process)),
    )

    result = await executor.execute(
        request(),
        context=context(),
        max_output_bytes=5,
    )

    assert result.stdout == b"12345"
    assert result.exit_status == 137
    assert result.truncated is False


@pytest.mark.asyncio
async def test_timeout_closes_remote_channel():
    process = Process(delay=0.2)
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=Manager(Connection(process)),
        cleanup_timeout_seconds=0.1,
    )

    result = await executor.execute(
        request(),
        context=context(),
        timeout_seconds=0.01,
    )

    assert result.timed_out is True
    assert process.closed is True


@pytest.mark.asyncio
async def test_cancellation_aborts_remote_process():
    process = Process(delay=10)
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=Manager(Connection(process)),
        cleanup_timeout_seconds=0.05,
    )

    task = asyncio.create_task(executor.execute(request(), context=context()))
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.closed is True


@pytest.mark.asyncio
async def test_structured_transport_runs_preframed_payload_with_hardened_channel():
    process = Process(stdout=(b"data",), stderr=(b"err",))
    connection = Connection(process)
    manager = Manager(connection)
    transport = StructuredSSHTransport(
        connections=manager,
        cleanup_timeout_seconds=0.1,
    )

    result = await transport.run(
        host="dev01",
        payload=b"framed",
        request_id="req_transport_1234",
        timeout_seconds=1.0,
        max_output_bytes=1024,
    )

    assert manager.get_calls == 1
    command, kwargs = connection.calls[0]
    assert command == REMOTE_PROTOCOL_COMMAND
    assert kwargs["input"] == b"framed"
    assert kwargs["request_pty"] is False
    assert kwargs["term_type"] is None
    assert kwargs["env"] == {}
    assert kwargs["send_env"] == []
    assert kwargs["x11_forwarding"] is False
    assert kwargs["encoding"] is None
    assert result.request_id == "req_transport_1234"
    assert result.host == "dev01"
    assert result.stdout == b"data"
    assert result.stderr == b"err"
    assert result.exit_status == 0
    assert result.timed_out is False
    assert result.truncated is False


class RecordingTransport:
    def __init__(self):
        self.calls = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return SSHExecutionResult(
            request_id=kwargs["request_id"],
            host=kwargs["host"],
            exit_status=0,
            stdout=b"delegated",
            duration_ms=1,
        )


@pytest.mark.asyncio
async def test_executor_delegates_allowed_request_to_injected_transport():
    manager = Manager(Connection(Process()))
    transport = RecordingTransport()
    executor = SSHExecutor(
        authorizer=Policy(ALLOW),
        connections=manager,
        transport=transport,
    )

    result = await executor.execute(
        request(),
        context=context(),
        stdin=b"hello",
        timeout_seconds=7.0,
        max_output_bytes=321,
        max_stdin_bytes=654,
    )
    assert manager.get_calls == 0
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["host"] == "dev01"
    assert call["request_id"] == context().request_id
    assert call["timeout_seconds"] == 7.0
    assert call["max_output_bytes"] == 321

    envelope, stdin = decode_request(call["payload"])
    assert envelope.profile == "developer"
    assert envelope.executable == "/usr/bin/git"
    assert envelope.argv == ("status",)
    assert envelope.cwd == "/srv/app"
    assert envelope.limits.timeout_seconds == 7.0
    assert envelope.limits.max_output_bytes == 321
    assert envelope.limits.max_stdin_bytes == 654
    assert stdin == b"hello"
    assert result.stdout == b"delegated"


class RaisingConnection:
    def __init__(self, error):
        self.error = error
        self.calls = []

    async def create_process(self, command, **kwargs):
        self.calls.append((command, kwargs))
        raise self.error


@pytest.mark.asyncio
async def test_transport_channel_open_failure_is_definite_transport_failure():
    connection = RaisingConnection(
        asyncssh.ChannelOpenError(
            asyncssh.OPEN_CONNECT_FAILED,
            "SUPERSECRET remote refusal detail",
        )
    )
    transport = StructuredSSHTransport(
        connections=Manager(connection),
        cleanup_timeout_seconds=0.1,
    )

    with pytest.raises(
        ssh_errors.SSHConnectionError,
        match="SSH structured channel open failed",
    ) as exc_info:
        await transport.run(
            host="dev01",
            payload=b"framed",
            request_id="req_open_1234",
            timeout_seconds=1.0,
            max_output_bytes=1024,
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_transport_post_open_failure_is_outcome_uncertain():
    uncertain_error = getattr(
        ssh_errors,
        "SSHRequestOutcomeUncertain",
        None,
    )
    assert uncertain_error is not None

    connection = RaisingConnection(
        RuntimeError("SUPERSECRET write-or-redirect failure")
    )
    transport = StructuredSSHTransport(
        connections=Manager(connection),
        cleanup_timeout_seconds=0.1,
    )

    with pytest.raises(
        uncertain_error,
        match="structured SSH request outcome is uncertain",
    ) as exc_info:
        await transport.run(
            host="dev01",
            payload=b"framed",
            request_id="req_uncertain_1234",
            timeout_seconds=1.0,
            max_output_bytes=1024,
        )

    assert "SUPERSECRET" not in str(exc_info.value)


class FailingReader:
    async def read(self, size):
        raise RuntimeError("SUPERSECRET collection failure")


@pytest.mark.asyncio
async def test_transport_collection_failure_is_outcome_uncertain():
    process = Process()
    process.stdout = FailingReader()
    transport = StructuredSSHTransport(
        connections=Manager(Connection(process)),
        cleanup_timeout_seconds=0.1,
    )

    with pytest.raises(
        ssh_errors.SSHRequestOutcomeUncertain,
        match="structured SSH request outcome is uncertain",
    ) as exc_info:
        await transport.run(
            host="dev01",
            payload=b"framed",
            request_id="req_collect_1234",
            timeout_seconds=1.0,
            max_output_bytes=1024,
        )

    assert "SUPERSECRET" not in str(exc_info.value)
