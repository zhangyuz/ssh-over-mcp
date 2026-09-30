import asyncio

import pytest

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


class Policy:
    def __init__(self, decision):
        self.decision = decision

    def evaluate(self, request):
        return self.decision


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
        policy=Policy(
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
        await executor.execute(request())

    assert manager.get_calls == 0


@pytest.mark.asyncio
async def test_approval_required_happens_before_ssh():
    manager = Manager(Connection(Process()))
    executor = SSHExecutor(
        policy=Policy(
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
        await executor.execute(request())

    assert manager.get_calls == 0


@pytest.mark.asyncio
async def test_fixed_remote_command_and_framed_payload():
    process = Process()
    connection = Connection(process)
    executor = SSHExecutor(
        policy=Policy(ALLOW),
        connections=Manager(connection),
    )

    result = await executor.execute(
        request(),
        stdin=b"hello",
        request_id="req_12345678",
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
        policy=Policy(ALLOW),
        connections=Manager(Connection(process)),
    )

    result = await executor.execute(
        request(),
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
        policy=Policy(ALLOW),
        connections=Manager(Connection(process)),
    )

    result = await executor.execute(
        request(),
        timeout_seconds=1.0,
    )

    assert result.exit_status == 143
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_exact_remote_output_budget_is_not_local_truncation():
    process = Process(stdout=(b"12345",), delay=0)
    process.exit_status = 137
    executor = SSHExecutor(
        policy=Policy(ALLOW),
        connections=Manager(Connection(process)),
    )

    result = await executor.execute(
        request(),
        max_output_bytes=5,
    )

    assert result.stdout == b"12345"
    assert result.exit_status == 137
    assert result.truncated is False


@pytest.mark.asyncio
async def test_timeout_closes_remote_channel():
    process = Process(delay=0.2)
    executor = SSHExecutor(
        policy=Policy(ALLOW),
        connections=Manager(Connection(process)),
        cleanup_timeout_seconds=0.1,
    )

    result = await executor.execute(
        request(),
        timeout_seconds=0.01,
    )

    assert result.timed_out is True
    assert process.closed is True


@pytest.mark.asyncio
async def test_cancellation_aborts_remote_process():
    process = Process(delay=10)
    executor = SSHExecutor(
        policy=Policy(ALLOW),
        connections=Manager(Connection(process)),
        cleanup_timeout_seconds=0.05,
    )

    task = asyncio.create_task(executor.execute(request()))
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.closed is True
