from __future__ import annotations

import asyncio
import os
import re
import socket
import threading
from pathlib import Path

import pytest
import uvicorn
from mcp import Client

from ssh_over_mcp.api.app import build_application
from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.approvals.client import SecurityLedgerAdminClient
from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings
from ssh_over_mcp.approvals.service import SecurityLedgerService
from ssh_over_mcp.approvals.storage import LedgerDatabase
from ssh_over_mcp.approvals.transport import (
    UnixLedgerTransport,
)
from ssh_over_mcp.ssh.connection import SSHConnectionManager

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED required",
)

_APPROVAL_ID_RE = re.compile(r"approval_id=(apr_[0-9a-f]{32})")
_REQUEST_ID_RE = re.compile(r"request_id=(req_[0-9a-f]{32})")

_CONFIG = """
inventory:
  hosts:
    host-a:
      address: 10.0.0.1
      port: 22
      ssh_user: secret-user
      credential_ref: secret://host-a
      host_key: secret-host-key
      allowed_roles: [developer]
policy:
  version: 1
  default: deny
  roles:
    developer:
      env_allow: [LANG]
  rules:
    - id: developer.rm
      effect: allow
      roles: [developer]
      hosts: [host-a]
      tools: [ssh_exec]
      executables: [/usr/bin/rm]
"""


def _write_app_files(tmp_path: Path) -> tuple[Path, Path]:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_CONFIG, encoding="utf-8")

    key_path = tmp_path / "host-a.key"
    key_path.write_text("test-key-material", encoding="utf-8")
    credential_map_path = tmp_path / "credentials.yaml"
    credential_map_path.write_text(
        "credentials:\n"
        f'  "secret://host-a": "{key_path}"\n',
        encoding="utf-8",
    )
    return config_path, credential_map_path


def _ledger_settings(tmp_path: Path) -> SecurityLedgerRuntimeSettings:
    uid = os.getuid()
    gid = os.getgid()
    data_dir = tmp_path / "ledger-data"
    exec_dir = tmp_path / "ledger-exec"
    admin_dir = tmp_path / "ledger-admin"
    for directory in (data_dir, exec_dir, admin_dir):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)

    hmac_key = data_dir / "ledger.key"
    hmac_key.write_bytes(b"K" * 32)
    os.chmod(hmac_key, 0o600)

    return SecurityLedgerRuntimeSettings(
        db_path=data_dir / "ledger.db",
        hmac_key_path=hmac_key,
        service_uid=uid,
        service_gid=gid,
        execution_socket_path=exec_dir / "ledger.sock",
        execution_socket_gid=gid,
        execution_socket_mode=0o660,
        execution_peer_uid=uid,
        execution_peer_gid=gid,
        admin_socket_path=admin_dir / "ledger.sock",
        admin_socket_gid=gid,
        admin_socket_mode=0o660,
        admin_peer_uid=uid,
        admin_peer_gid=gid,
    )


def _mcp_settings(
    tmp_path: Path,
    ledger: SecurityLedgerRuntimeSettings,
) -> MCPRuntimeSettings:
    config_path, credential_map_path = _write_app_files(tmp_path)
    return MCPRuntimeSettings(
        config_path=config_path,
        credential_map_path=credential_map_path,
        profile="developer",
        ledger_socket_path=ledger.execution_socket_path,
        ledger_server_uid=ledger.service_uid,
        ledger_server_gid=ledger.service_gid,
        port=8000,
    )


class _Reader:
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = list(chunks)

    async def read(self, _size: int) -> bytes:
        await asyncio.sleep(0)
        return self._chunks.pop(0) if self._chunks else b""


class _Process:
    def __init__(self) -> None:
        self.stdout = _Reader((b"ok",))
        self.stderr = _Reader(())
        self.exit_status = 0
        self.exit_signal = None
        self.closed = False

    async def wait_closed(self) -> None:
        self.closed = True

    def terminate(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, state: dict[str, object]) -> None:
        self._state = state

    async def create_process(self, _command: str, **_kwargs):
        self._state["channel_calls"] = int(self._state["channel_calls"]) + 1
        if self._state["fail_next"]:
            self._state["fail_next"] = False
            raise RuntimeError("SUPERSECRET remote failure")
        return _Process()


def _tool_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


def _approval_id(result) -> str:
    text = _tool_text(result)
    match = _APPROVAL_ID_RE.search(text)
    if match is None:
        raise AssertionError(f"approval id missing from tool error: {text!r}")
    return match.group(1)


def _request_id(result) -> str:
    text = _tool_text(result)
    match = _REQUEST_ID_RE.search(text)
    if match is None:
        raise AssertionError(f"request id missing from tool error: {text!r}")
    return match.group(1)


def _base_request(
    suffix: str,
    *,
    env_value: str = "ENV_SECRET_BASE",
    stdin: str = "STDIN_SECRET_BASE",
    timeout_seconds: float = 30,
) -> dict[str, object]:
    return {
        "host": "host-a",
        "executable": "/usr/bin/rm",
        "args": ["-f", f"/tmp/ARG_SECRET_{suffix}"],
        "cwd": "/tmp",
        "env": {"LANG": env_value},
        "stdin": stdin,
        "timeout_seconds": timeout_seconds,
    }


async def _pending_and_grant(
    client: Client,
    admin: SecurityLedgerAdminClient,
    request: dict[str, object],
) -> str:
    pending = await client.call_tool("ssh_exec", request)
    assert pending.is_error is True
    approval_id = _approval_id(pending)
    granted = await admin.grant(approval_id)
    assert granted.state.value == "granted"
    return approval_id


@pytest.mark.asyncio
async def test_real_http_ssh_exec_approval_round_trip_is_single_use_and_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_settings = _ledger_settings(tmp_path)
    ledger_service = SecurityLedgerService.create(ledger_settings)
    ledger_stop = threading.Event()
    ledger_errors: list[BaseException] = []

    def run_ledger() -> None:
        try:
            ledger_service.serve_forever(
                stop_requested=ledger_stop.is_set,
            )
        except BaseException as exc:  # noqa: BLE001
            ledger_errors.append(exc)

    ledger_thread = threading.Thread(target=run_ledger)
    ledger_thread.start()

    frames: list[bytes] = []
    original_round_trip = UnixLedgerTransport.round_trip

    def capture_round_trip(
        transport: UnixLedgerTransport,
        frame: bytes,
    ) -> bytes:
        frames.append(frame)
        return original_round_trip(transport, frame)

    monkeypatch.setattr(
        UnixLedgerTransport,
        "round_trip",
        capture_round_trip,
    )

    ssh_state: dict[str, object] = {
        "get_calls": 0,
        "channel_calls": 0,
        "fail_next": False,
    }

    async def fake_get_connection(
        _manager: SSHConnectionManager,
        _alias: str,
    ) -> _Connection:
        ssh_state["get_calls"] = int(ssh_state["get_calls"]) + 1
        return _Connection(ssh_state)

    monkeypatch.setattr(
        SSHConnectionManager,
        "get_connection",
        fake_get_connection,
    )

    app = build_application(
        _mcp_settings(tmp_path, ledger_settings)
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    http_server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    http_task = asyncio.create_task(
        http_server.serve(sockets=[sock])
    )

    admin = SecurityLedgerAdminClient(
        UnixLedgerTransport(
            ledger_settings.admin_socket_path,
            ledger_settings.ledger_server_peer_policy(),
            timeout_seconds=2.0,
        )
    )

    initial_approval_id = ""
    success_request_id = ""
    fallback_request_ids: list[str] = []
    try:
        for _ in range(500):
            if http_server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("uvicorn did not start")

        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            ready_request = _base_request("INITIAL")

            pending = await client.call_tool(
                "ssh_exec",
                ready_request,
            )
            assert pending.is_error is True
            initial_approval_id = _approval_id(pending)
            pending_text = _tool_text(pending)
            assert "state=pending" in pending_text
            assert "retry the exact operation" in pending_text
            assert ssh_state["get_calls"] == 0
            assert ssh_state["channel_calls"] == 0

            visible = await client.call_tool(
                "approval_status",
                {"approval_id": initial_approval_id},
            )
            assert visible.is_error is False
            assert visible.structured_content["state"] == "pending"

            granted = await admin.grant(initial_approval_id)
            assert granted.state.value == "granted"

            exact_retry = dict(ready_request)
            exact_retry["approval_id"] = initial_approval_id
            success = await client.call_tool(
                "ssh_exec",
                exact_retry,
            )
            assert success.is_error is False
            success_request_id = success.structured_content["request_id"]
            assert success.structured_content["stdout_base64"] == "b2s="
            assert ssh_state["get_calls"] == 1
            assert ssh_state["channel_calls"] == 1

            consumed = await client.call_tool(
                "approval_status",
                {"approval_id": initial_approval_id},
            )
            assert consumed.is_error is False
            assert consumed.structured_content["state"] == "consumed"

            replay = await client.call_tool(
                "ssh_exec",
                exact_retry,
            )
            assert replay.is_error is True
            replacement_id = _approval_id(replay)
            fallback_request_ids.append(_request_id(replay))
            assert replacement_id != initial_approval_id
            assert "state=pending" in _tool_text(replay)
            assert ssh_state["get_calls"] == 1

            mutation_cases = (
                (
                    "ARGV_BASE",
                    {"args": ["-f", "/tmp/ARG_SECRET_MUTATED"]},
                ),
                (
                    "ENV_BASE",
                    {"env": {"LANG": "ENV_SECRET_MUTATED"}},
                ),
                (
                    "STDIN_BASE",
                    {"stdin": "STDIN_SECRET_MUTATED"},
                ),
                (
                    "TIMEOUT_BASE",
                    {"timeout_seconds": 31},
                ),
            )
            for suffix, mutation in mutation_cases:
                base = _base_request(suffix)
                base_id = await _pending_and_grant(
                    client,
                    admin,
                    base,
                )
                mutated = dict(base)
                mutated.update(mutation)
                mutated["approval_id"] = base_id

                rejected = await client.call_tool(
                    "ssh_exec",
                    mutated,
                )

                assert rejected.is_error is True
                replacement = _approval_id(rejected)
                fallback_request_ids.append(_request_id(rejected))
                assert replacement != base_id
                assert "state=pending" in _tool_text(rejected)
                assert ssh_state["get_calls"] == 1

                base_status = await client.call_tool(
                    "approval_status",
                    {"approval_id": base_id},
                )
                assert base_status.is_error is False
                assert base_status.structured_content["state"] == "granted"

            failure_base = _base_request("REMOTE_FAILURE")
            failure_id = await _pending_and_grant(
                client,
                admin,
                failure_base,
            )
            ssh_state["fail_next"] = True
            failure_retry = dict(failure_base)
            failure_retry["approval_id"] = failure_id
            failed = await client.call_tool(
                "ssh_exec",
                failure_retry,
            )

            assert failed.is_error is True
            assert "SSH execution failed" in _tool_text(failed)
            assert "SUPERSECRET" not in _tool_text(failed)
            assert ssh_state["get_calls"] == 2
            failure_status = await client.call_tool(
                "approval_status",
                {"approval_id": failure_id},
            )
            assert failure_status.is_error is False
            assert failure_status.structured_content["state"] == "consumed"

        captured = b"".join(frames)
        for forbidden in (
            b"ARG_SECRET_",
            b"ENV_SECRET_BASE",
            b"ENV_SECRET_MUTATED",
            b"STDIN_SECRET_BASE",
            b"STDIN_SECRET_MUTATED",
            b"test-key-material",
            b"secret://host-a",
        ):
            assert forbidden not in captured
    finally:
        http_server.should_exit = True
        await asyncio.wait_for(http_task, timeout=5)
        sock.close()
        ledger_stop.set()
        ledger_thread.join(timeout=3)
        ledger_service.close()

    assert not ledger_thread.is_alive()
    assert ledger_errors == []

    reopened = LedgerDatabase.open(
        ledger_settings.storage_settings()
    )
    try:
        events = reopened.connection.execute(
            "SELECT sequence,event_type,request_id,approval_id "
            "FROM audit_events ORDER BY sequence"
        ).fetchall()
    finally:
        reopened.close()

    interesting = [
        (sequence, event_type, request_id, approval_id)
        for sequence, event_type, request_id, approval_id in events
        if event_type in {
            "approval_required",
            "approval_granted",
            "approval_consumed",
            "execution_started",
            "execution_completed",
        }
    ]

    first_required = next(
        sequence
        for sequence, event_type, _request_id, approval_id in interesting
        if event_type == "approval_required"
        and approval_id == initial_approval_id
    )
    first_granted = next(
        sequence
        for sequence, event_type, _request_id, approval_id in interesting
        if event_type == "approval_granted"
        and approval_id == initial_approval_id
    )
    first_consumed = next(
        sequence
        for sequence, event_type, _request_id, approval_id in interesting
        if event_type == "approval_consumed"
        and approval_id == initial_approval_id
    )
    assert first_required < first_granted < first_consumed

    retry_events = [
        (sequence, event_type)
        for sequence, event_type, request_id, _approval_id in interesting
        if request_id == success_request_id
    ]
    retry_types = [event_type for _sequence, event_type in retry_events]
    assert retry_types == [
        "approval_required",
        "approval_consumed",
        "execution_started",
        "execution_completed",
    ]

    for request_id in fallback_request_ids:
        required_count = sum(
            event_type == "approval_required"
            and event_request_id == request_id
            for _sequence, event_type, event_request_id, _approval_id in events
        )
        assert required_count == 1
