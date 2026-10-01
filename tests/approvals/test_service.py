from __future__ import annotations

import asyncio
import os
import socket
import threading
from pathlib import Path

import pytest

from ssh_over_mcp.approvals.binding import fingerprint_argv
from ssh_over_mcp.approvals.client import SecurityLedgerAdminClient, SecurityLedgerClient
from ssh_over_mcp.approvals.models import ApprovalBindingInput, ApprovalState
from ssh_over_mcp.approvals.storage import LedgerDatabase
from ssh_over_mcp.approvals.transport import LedgerTransportError, UnixLedgerTransport
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    ContainmentManagerEndpointError,
)
from ssh_over_mcp.host_agent.containment_manager_identity import LinuxProcessIdentityError
from ssh_over_mcp.policy.models import RiskLevel

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


def _binding(path: str) -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        privilege="user",
        policy_version="sha256:policy",
        normalized_path=path,
        argv_count=0,
        argv_fingerprint=fingerprint_argv(()),
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
    )


def _clients(settings):
    server = settings.ledger_server_peer_policy()
    execution = SecurityLedgerClient(
        UnixLedgerTransport(
            settings.execution_socket_path,
            server,
            timeout_seconds=2.0,
        )
    )
    admin = SecurityLedgerAdminClient(
        UnixLedgerTransport(
            settings.admin_socket_path,
            server,
            timeout_seconds=2.0,
        )
    )
    return execution, admin


def _serve_async(service, awaitable):
    thread = _run_one(service)
    try:
        result = asyncio.run(awaitable)
    finally:
        thread.join(timeout=3)
    assert not thread.is_alive()
    return result


def test_service_restart_preserves_approval_states_and_applies_expiry(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.service import SecurityLedgerService

    settings = _settings(tmp_path)
    service = SecurityLedgerService.create(settings)
    execution, admin = _clients(settings)
    statuses = {}
    try:
        for index, name in enumerate(
            ("pending", "granted", "denied", "consumed", "expired"),
            start=1,
        ):
            binding = _binding(f"/srv/app/{name}")
            statuses[name] = _serve_async(
                service,
                execution.ensure_approval(
                    binding=binding,
                    risk=RiskLevel.HIGH,
                    request_id=f"req_{index:032x}",
                ),
            )

        statuses["granted"] = _serve_async(
            service,
            admin.grant(statuses["granted"].approval_id),
        )
        statuses["denied"] = _serve_async(
            service,
            admin.deny(statuses["denied"].approval_id),
        )
        consumed_binding = _binding("/srv/app/consumed")
        _serve_async(
            service,
            admin.grant(statuses["consumed"].approval_id),
        )
        statuses["consumed"] = _serve_async(
            service,
            execution.consume_approval(
                approval_id=statuses["consumed"].approval_id,
                binding=consumed_binding,
                request_id="req_" + "9" * 32,
            ),
        )
    finally:
        service.close()

    database = LedgerDatabase.open(settings.storage_settings())
    try:
        database.connection.execute(
            "UPDATE approvals SET expires_at=? WHERE approval_id=?",
            (
                "2000-01-01T00:00:00+00:00",
                statuses["expired"].approval_id,
            ),
        )
        database.connection.commit()
    finally:
        database.close()

    restarted = SecurityLedgerService.create(settings)
    _execution2, admin2 = _clients(settings)
    try:
        expected = {
            "pending": ApprovalState.PENDING,
            "granted": ApprovalState.GRANTED,
            "denied": ApprovalState.DENIED,
            "consumed": ApprovalState.CONSUMED,
            "expired": ApprovalState.EXPIRED,
        }
        for name, state in expected.items():
            observed = _serve_async(
                restarted,
                admin2.show_approval(statuses[name].approval_id),
            )
            assert observed.state is state
    finally:
        restarted.close()

    final_db = LedgerDatabase.open(settings.storage_settings())
    try:
        expiry_count = final_db.connection.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE event_type='approval_expired' AND approval_id=?",
            (statuses["expired"].approval_id,),
        ).fetchone()[0]
        assert expiry_count == 1
    finally:
        final_db.close()
