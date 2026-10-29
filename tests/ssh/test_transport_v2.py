"""Exact v2 SSH command selection without weakening legacy v1 isolation."""

from __future__ import annotations

import asyncio

import asyncssh
import pytest

from ssh_over_mcp.ssh.connection import SSHConnectionManager
from ssh_over_mcp.ssh.credentials import SSHCredential, StaticCredentialProvider
from ssh_over_mcp.ssh.errors import (
    SSHConnectionError,
    SSHHostKeyVerificationError,
    SSHRequestOutcomeUncertain,
)
from ssh_over_mcp.ssh.transport import SSHExecutionResult, StructuredSSHTransport


class Connection:
    def __init__(self):
        self.calls = []

    async def create_process(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return object()


class Slot:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class Manager:
    def __init__(self, conn):
        self.conn = conn

    def session_slot(self, _host):
        return Slot()

    async def get_connection(self, _host):
        return self.conn


@pytest.mark.asyncio
async def test_v2_transport_selects_exact_new_force_command_without_pty(monkeypatch):
    connection = Connection()
    transport = StructuredSSHTransport(connections=Manager(connection))

    async def collected(_process, **kwargs):
        return SSHExecutionResult(
            request_id=kwargs["request_id"],
            host=kwargs["host"],
            exit_status=0,
            stdout=b"{}",
            duration_ms=1,
        )

    monkeypatch.setattr(transport, "_collect", collected)
    result = await transport.run_v2(
        host="node01",
        payload=b"SMCP\\x00\\x02-framed",
        request_id="req-0123456789",
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    assert result.stdout == b"{}"
    assert len(connection.calls) == 1
    command, kwargs = connection.calls[0]
    assert command == "mcp-v2"
    assert kwargs["input"] == b"SMCP\\x00\\x02-framed"
    assert kwargs["request_pty"] is False
    assert kwargs["term_type"] is None
    assert kwargs["env"] == {}
    assert kwargs["send_env"] == []
    assert kwargs["x11_forwarding"] is False
    assert kwargs["encoding"] is None


@pytest.mark.asyncio
async def test_existing_transport_run_still_uses_legacy_v1(monkeypatch):
    connection = Connection()
    transport = StructuredSSHTransport(connections=Manager(connection))

    async def collected(_process, **kwargs):
        return SSHExecutionResult(
            request_id=kwargs["request_id"],
            host=kwargs["host"],
            exit_status=0,
            duration_ms=1,
        )

    monkeypatch.setattr(transport, "_collect", collected)
    await transport.run(
        host="node01",
        payload=b"SMCP\\x00\\x01-framed",
        request_id="req-0123456789",
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    assert connection.calls[0][0] == "mcp-v1"


class Process:
    def __init__(self, *, stdout=b"", stderr=b"", hold_open=False):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()
        self.hold_open = hold_open
        self.waiting = asyncio.Event()
        self.closed = asyncio.Event()
        self.terminated = False
        self.exit_status = 137
        self.exit_signal = None

    async def wait_closed(self):
        self.waiting.set()
        if self.hold_open:
            await self.closed.wait()

    def terminate(self):
        self.terminated = True

    def close(self):
        self.closed.set()


class ProcessConnection(Connection):
    def __init__(self, process):
        super().__init__()
        self.process = process

    async def create_process(self, command, **kwargs):
        await super().create_process(command, **kwargs)
        return self.process


@pytest.fixture(params=[("run", "mcp-v1"), ("run_v2", "mcp-v2")])
def transport_entrypoint(request):
    return request.param


def arguments():
    return {
        "host": "dev01",
        "payload": b"opaque framed data; $(untrusted)\n",
        "request_id": "req_transport_1234",
        "timeout_seconds": 1.0,
        "max_output_bytes": 5,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("overflow", [False, True])
async def test_both_versions_share_output_budget_and_hardened_channel(
    transport_entrypoint, overflow
):
    method, expected_command = transport_entrypoint
    process = Process(stdout=b"abc", stderr=b"def" if overflow else b"de", hold_open=overflow)
    connection = ProcessConnection(process)
    transport = StructuredSSHTransport(connections=Manager(connection))

    result = await getattr(transport, method)(**arguments())

    assert connection.calls == [
        (
            expected_command,
            {
                "input": arguments()["payload"],
                "request_pty": False,
                "term_type": None,
                "env": {},
                "send_env": [],
                "x11_forwarding": False,
                "encoding": None,
            },
        )
    ]
    assert result.request_id == arguments()["request_id"]
    assert result.host == "dev01"
    assert len(result.stdout) + len(result.stderr) == 5
    assert result.truncated is overflow
    assert result.timed_out is False
    if overflow:
        assert process.terminated
        assert process.closed.is_set()
    else:
        assert result.stdout == b"abc"
        assert result.stderr == b"de"
        assert result.exit_status == 137


@pytest.mark.asyncio
async def test_both_versions_timeout_closes_channel(transport_entrypoint):
    method, _ = transport_entrypoint
    process = Process(hold_open=True)
    transport = StructuredSSHTransport(connections=Manager(ProcessConnection(process)))
    kwargs = arguments() | {"timeout_seconds": 0.01}

    result = await getattr(transport, method)(**kwargs)

    assert result.timed_out is True
    assert process.terminated
    assert process.closed.is_set()


@pytest.mark.asyncio
async def test_both_versions_cancellation_closes_channel(transport_entrypoint):
    method, _ = transport_entrypoint
    process = Process(hold_open=True)
    transport = StructuredSSHTransport(connections=Manager(ProcessConnection(process)))
    task = asyncio.create_task(getattr(transport, method)(**arguments()))
    try:
        await asyncio.wait_for(process.waiting.wait(), timeout=1)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert process.terminated
    assert process.closed.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["open", "send", "collect"])
async def test_both_versions_sanitize_failures_without_fallback(transport_entrypoint, failure):
    method, expected_command = transport_entrypoint
    process = Process()

    class FailingConnection(ProcessConnection):
        async def create_process(self, command, **kwargs):
            result = await super().create_process(command, **kwargs)
            if failure == "open":
                raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "secret detail")
            if failure == "send":
                raise RuntimeError("secret detail")
            return result

    if failure == "collect":
        process.stdout.set_exception(RuntimeError("secret detail"))
    connection = FailingConnection(process)
    transport = StructuredSSHTransport(connections=Manager(connection))
    expected_error = SSHConnectionError if failure == "open" else SSHRequestOutcomeUncertain
    expected_message = (
        "SSH structured channel open failed"
        if failure == "open"
        else "structured SSH request outcome is uncertain"
    )

    with pytest.raises(expected_error) as exc_info:
        await getattr(transport, method)(**arguments())

    assert str(exc_info.value) == expected_message
    assert [command for command, _ in connection.calls] == [expected_command]


@pytest.mark.asyncio
async def test_both_versions_do_not_accept_caller_command(transport_entrypoint):
    method, _ = transport_entrypoint
    connection = Connection()
    transport = StructuredSSHTransport(connections=Manager(connection))

    with pytest.raises(TypeError, match="command"):
        await getattr(transport, method)(**arguments(), command="arbitrary-command")

    assert connection.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["", "mcp-v2 ", "mcp-v2; untrusted", "untrusted"])
async def test_unlisted_internal_command_fails_before_connection(command):
    class NoNetworkManager:
        def session_slot(self, _host):
            pytest.fail("unsupported command reached connection management")

    transport = StructuredSSHTransport(connections=NoNetworkManager())

    with pytest.raises(ValueError, match="unsupported structured SSH command"):
        await transport._run(**arguments(), command=command)


@pytest.mark.asyncio
async def test_both_versions_preserve_inventory_host_pin_failure(transport_entrypoint, inventory):
    method, _ = transport_entrypoint
    calls = []
    host_spec = inventory.hosts["dev01"].model_copy(update={"host_key": "ssh-ed25519 ZmFrZS1rZXk="})
    inventory = inventory.model_copy(update={"hosts": {"dev01": host_spec}})

    async def connector(host, **kwargs):
        calls.append((host, kwargs))
        raise asyncssh.HostKeyNotVerifiable("synthetic changed host key")

    manager = SSHConnectionManager(
        inventory=inventory,
        credentials=StaticCredentialProvider(
            {
                "secret://ssh/dev01": SSHCredential(client_keys=("/synthetic/key",)),
            }
        ),
        connector=connector,
    )
    transport = StructuredSSHTransport(connections=manager)

    with pytest.raises(SSHHostKeyVerificationError):
        await getattr(transport, method)(**arguments())

    assert len(calls) == 1
    host, kwargs = calls[0]
    assert host == inventory.hosts["dev01"].address
    assert kwargs["username"] == inventory.hosts["dev01"].ssh_user
    assert kwargs["known_hosts"] == b"dev01 ssh-ed25519 ZmFrZS1rZXk=\n"
    assert kwargs["host_key_alias"] == "dev01"
    assert kwargs["config"] is None
    assert kwargs["agent_path"] is None
    assert kwargs["agent_forwarding"] is False
