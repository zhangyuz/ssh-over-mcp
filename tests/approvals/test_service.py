from __future__ import annotations

import asyncio
import os
import socket
import threading
from pathlib import Path

import pytest

from ssh_over_mcp.approvals.client import SecurityLedgerAdminClient, SecurityLedgerClient
from ssh_over_mcp.approvals.storage import LedgerDatabase
from ssh_over_mcp.approvals.transport import LedgerTransportError, UnixLedgerTransport
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    ContainmentManagerEndpointError,
)
from ssh_over_mcp.host_agent.containment_manager_identity import LinuxProcessIdentityError

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED required",
)


def _settings(tmp_path: Path, *, wrong_process: bool = False, wrong_exec_peer: bool = False):
    from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings

    uid = os.getuid()
    gid = os.getgid()
    data = tmp_path / "data"
    execution = tmp_path / "exec"
    admin = tmp_path / "admin"
    for directory in (data, execution, admin):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    key = data / "ledger.key"
    key.write_bytes(b"K" * 32)
    os.chmod(key, 0o600)

    return SecurityLedgerRuntimeSettings(
        db_path=data / "ledger.db",
        hmac_key_path=key,
        service_uid=uid + 1 if wrong_process else uid,
        service_gid=gid,
        execution_socket_path=execution / "ledger.sock",
        execution_socket_gid=gid,
        execution_socket_mode=0o660,
        execution_peer_uid=uid + 1 if wrong_exec_peer else uid,
        execution_peer_gid=gid,
        admin_socket_path=admin / "ledger.sock",
        admin_socket_gid=gid,
        admin_socket_mode=0o660,
        admin_peer_uid=uid,
        admin_peer_gid=gid,
    )


def _run_one(service) -> threading.Thread:
    thread = threading.Thread(target=service.serve_one)
    thread.start()
    return thread


def test_service_wrong_process_identity_fails_before_storage_or_sockets(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.service import SecurityLedgerService

    settings = _settings(tmp_path, wrong_process=True)
    with pytest.raises(LinuxProcessIdentityError):
        SecurityLedgerService.create(settings)

    assert not settings.db_path.exists()
    assert not settings.execution_socket_path.exists()
    assert not settings.admin_socket_path.exists()


def test_service_serves_execution_and_admin_on_separate_endpoints(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.service import SecurityLedgerService

    settings = _settings(tmp_path)
    service = SecurityLedgerService.create(settings)
    try:
        execution_client = SecurityLedgerClient(
            UnixLedgerTransport(
                settings.execution_socket_path,
                settings.ledger_server_peer_policy(),
                timeout_seconds=2.0,
            )
        )
        admin_client = SecurityLedgerAdminClient(
            UnixLedgerTransport(
                settings.admin_socket_path,
                settings.ledger_server_peer_policy(),
                timeout_seconds=2.0,
            )
        )

        thread = _run_one(service)
        asyncio.run(execution_client.ping())
        thread.join(timeout=3)
        assert not thread.is_alive()

        thread = _run_one(service)
        assert asyncio.run(admin_client.list_approvals()) == ()
        thread.join(timeout=3)
        assert not thread.is_alive()
    finally:
        service.close()


def test_service_rejects_wrong_execution_peer_before_dispatch(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.service import SecurityLedgerService

    settings = _settings(tmp_path, wrong_exec_peer=True)
    service = SecurityLedgerService.create(settings)
    event = AuditEventInput(
        event_type=AuditEventType.REQUEST_RECEIVED,
        request_id="req_" + "1" * 32,
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="ssh_exec",
    )
    client = SecurityLedgerClient(
        UnixLedgerTransport(
            settings.execution_socket_path,
            settings.ledger_server_peer_policy(),
            timeout_seconds=2.0,
        )
    )
    try:
        thread = _run_one(service)
        with pytest.raises(LedgerTransportError):
            asyncio.run(client.append_audit(event))
        thread.join(timeout=3)
        assert not thread.is_alive()
    finally:
        service.close()

    reopened = LedgerDatabase.open(settings.storage_settings())
    try:
        count = reopened.connection.execute(
            "SELECT count(*) FROM audit_events"
        ).fetchone()[0]
        assert count == 0
    finally:
        reopened.close()


def test_service_cleanup_refuses_replaced_socket_inode(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.service import SecurityLedgerService

    settings = _settings(tmp_path)
    service = SecurityLedgerService.create(settings)

    settings.execution_socket_path.unlink()
    settings.execution_socket_path.write_text("replacement")

    with pytest.raises(ContainmentManagerEndpointError):
        service.close()

    assert settings.execution_socket_path.read_text() == "replacement"
    assert not settings.admin_socket_path.exists()
