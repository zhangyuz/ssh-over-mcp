from __future__ import annotations

import asyncio
import base64
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
from ssh_over_mcp.approvals.transport import UnixLedgerTransport
from ssh_over_mcp.ssh.connection import SSHConnectionManager
from ssh_over_mcp.ssh.protocol import decode_request
from ssh_over_mcp.ssh.transport import (
    SSHExecutionResult,
    StructuredSSHTransport,
)

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED required",
)

_APPROVAL_ID_RE = re.compile(r"approval_id=(apr_[0-9a-f]{32})")

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
    developer: {}
  rules:
    - id: developer.filesystem
      effect: allow
      roles: [developer]
      hosts: [host-a]
      tools: [fs_stat, fs_read, fs_mkdir, fs_write]
      paths: ["/srv/app/**"]
  risk:
    approval_required: [low, medium]
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


def _tool_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


def _approval_id(result) -> str:
    match = _APPROVAL_ID_RE.search(_tool_text(result))
    if match is None:
        raise AssertionError(
            f"approval id missing from tool error: {_tool_text(result)!r}"
        )
    return match.group(1)


@pytest.mark.asyncio
async def test_real_http_fs_read_pending_returns_handle_pre_network(
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

    connection_calls = 0

    async def forbidden_connection(
        _manager: SSHConnectionManager,
        _alias: str,
    ):
        nonlocal connection_calls
        connection_calls += 1
        raise AssertionError("pending approval must remain pre-network")

    monkeypatch.setattr(
        SSHConnectionManager,
        "get_connection",
        forbidden_connection,
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

    try:
        for _ in range(500):
            if http_server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("uvicorn did not start")

        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            pending = await client.call_tool(
                "fs_read",
                {
                    "host": "host-a",
                    "path": "/srv/app/data.bin",
                    "max_bytes": 4096,
                },
            )

        assert pending.is_error is True
        assert _approval_id(pending).startswith("apr_")
        assert "state=pending" in _tool_text(pending)
        assert connection_calls == 0
    finally:
        http_server.should_exit = True
        await asyncio.wait_for(http_task, timeout=5)
        sock.close()
        ledger_stop.set()
        ledger_thread.join(timeout=3)
        ledger_service.close()

    assert not ledger_thread.is_alive()
    assert ledger_errors == []


async def _pending_and_grant(
    client: Client,
    admin: SecurityLedgerAdminClient,
    tool: str,
    request: dict[str, object],
) -> str:
    pending = await client.call_tool(tool, request)
    assert pending.is_error is True
    approval_id = _approval_id(pending)
    granted = await admin.grant(approval_id)
    assert granted.state.value == "granted"
    return approval_id


@pytest.mark.asyncio
async def test_real_http_filesystem_approval_consume_and_outcome_semantics(
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

    transport_calls: list[tuple[str, str, int | None, bytes]] = []

    async def fake_run(
        _transport: StructuredSSHTransport,
        *,
        host: str,
        payload: bytes,
        request_id: str,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> SSHExecutionResult:
        del timeout_seconds, max_output_bytes
        envelope, body = decode_request(payload)
        max_bytes = getattr(envelope, "max_bytes", None)
        transport_calls.append(
            (envelope.operation, envelope.path, max_bytes, body)
        )
        if envelope.operation == "fs_read":
            return SSHExecutionResult(
                request_id=request_id,
                host=host,
                exit_status=0,
                stdout=b"\x00\xffAB",
                duration_ms=1,
            )
        if envelope.operation == "fs_mkdir":
            return SSHExecutionResult(
                request_id=request_id,
                host=host,
                exit_status=None,
                duration_ms=1,
                timed_out=True,
            )
        if envelope.operation == "fs_write":
            return SSHExecutionResult(
                request_id=request_id,
                host=host,
                exit_status=74,
                duration_ms=1,
            )
        raise AssertionError(f"unexpected transport operation: {envelope.operation}")

    monkeypatch.setattr(
        StructuredSSHTransport,
        "run",
        fake_run,
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

    try:
        for _ in range(500):
            if http_server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("uvicorn did not start")

        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            read_request: dict[str, object] = {
                "host": "host-a",
                "path": "/srv/app/data.bin",
                "max_bytes": 4096,
            }
            read_id = await _pending_and_grant(
                client,
                admin,
                "fs_read",
                read_request,
            )
            read_retry = dict(read_request)
            read_retry["approval_id"] = read_id
            read_result = await client.call_tool("fs_read", read_retry)

            assert read_result.is_error is False
            assert read_result.structured_content["data_base64"] == base64.b64encode(
                b"\x00\xffAB"
            ).decode("ascii")
            assert [call[0] for call in transport_calls] == ["fs_read"]

            read_status = await client.call_tool(
                "approval_status",
                {"approval_id": read_id},
            )
            assert read_status.is_error is False
            assert read_status.structured_content["state"] == "consumed"

            replay = await client.call_tool("fs_read", read_retry)
            assert replay.is_error is True
            assert _approval_id(replay) != read_id
            assert [call[0] for call in transport_calls] == ["fs_read"]

            bound_read: dict[str, object] = {
                "host": "host-a",
                "path": "/srv/app/bound.bin",
                "max_bytes": 4096,
            }
            bound_read_id = await _pending_and_grant(
                client,
                admin,
                "fs_read",
                bound_read,
            )
            changed_limit = dict(bound_read)
            changed_limit["max_bytes"] = 8192
            changed_limit["approval_id"] = bound_read_id
            rejected_limit = await client.call_tool(
                "fs_read",
                changed_limit,
            )
            assert rejected_limit.is_error is True
            assert [call[0] for call in transport_calls] == ["fs_read"]

            wrong_path = dict(bound_read)
            wrong_path["path"] = "/srv/app/other.bin"
            wrong_path["approval_id"] = bound_read_id
            rejected_path = await client.call_tool("fs_read", wrong_path)
            assert rejected_path.is_error is True
            assert [call[0] for call in transport_calls] == ["fs_read"]

            wrong_tool = await client.call_tool(
                "fs_stat",
                {
                    "host": "host-a",
                    "path": "/srv/app/bound.bin",
                    "approval_id": bound_read_id,
                },
            )
            assert wrong_tool.is_error is True
            assert [call[0] for call in transport_calls] == ["fs_read"]

            original_status = await client.call_tool(
                "approval_status",
                {"approval_id": bound_read_id},
            )
            assert original_status.is_error is False
            assert original_status.structured_content["state"] == "granted"

            mkdir_request: dict[str, object] = {
                "host": "host-a",
                "path": "/srv/app/new-directory",
            }
            mkdir_id = await _pending_and_grant(
                client,
                admin,
                "fs_mkdir",
                mkdir_request,
            )
            mkdir_retry = dict(mkdir_request)
            mkdir_retry["approval_id"] = mkdir_id
            mkdir_result = await client.call_tool(
                "fs_mkdir",
                mkdir_retry,
            )

            assert mkdir_result.is_error is True
            mkdir_text = _tool_text(mkdir_result)
            assert "mutation outcome is uncertain" in mkdir_text
            assert "do not retry blindly" in mkdir_text
            mkdir_status = await client.call_tool(
                "approval_status",
                {"approval_id": mkdir_id},
            )
            assert mkdir_status.is_error is False
            assert mkdir_status.structured_content["state"] == "consumed"

            write_request: dict[str, object] = {
                "host": "host-a",
                "path": "/srv/app/new.bin",
                "data_base64": base64.b64encode(b"WRITE_SECRET_A").decode("ascii"),
            }
            write_id = await _pending_and_grant(
                client,
                admin,
                "fs_write",
                write_request,
            )
            changed_content = dict(write_request)
            changed_content["data_base64"] = base64.b64encode(
                b"WRITE_SECRET_B"
            ).decode("ascii")
            changed_content["approval_id"] = write_id
            rejected_content = await client.call_tool(
                "fs_write",
                changed_content,
            )
            assert rejected_content.is_error is True
            assert [call[0] for call in transport_calls] == [
                "fs_read",
                "fs_mkdir",
            ]

            write_retry = dict(write_request)
            write_retry["approval_id"] = write_id
            write_result = await client.call_tool(
                "fs_write",
                write_retry,
            )
            assert write_result.is_error is True
            write_text = _tool_text(write_result)
            assert (
                "filesystem write committed; durability uncertain; "
                "do not retry blindly"
            ) in write_text
            assert "mutation outcome is uncertain" not in write_text
            write_status = await client.call_tool(
                "approval_status",
                {"approval_id": write_id},
            )
            assert write_status.is_error is False
            assert write_status.structured_content["state"] == "consumed"

        assert [call[0] for call in transport_calls] == [
            "fs_read",
            "fs_mkdir",
            "fs_write",
        ]
        write_transport = transport_calls[-1]
        assert write_transport[3] == b"WRITE_SECRET_A"
    finally:
        http_server.should_exit = True
        await asyncio.wait_for(http_task, timeout=5)
        sock.close()
        ledger_stop.set()
        ledger_thread.join(timeout=3)
        ledger_service.close()

    assert not ledger_thread.is_alive()
    assert ledger_errors == []
