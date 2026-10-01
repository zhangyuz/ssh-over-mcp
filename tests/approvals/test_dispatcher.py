from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from ssh_over_mcp.approvals.binding import fingerprint_argv
from ssh_over_mcp.approvals.models import ApprovalBindingInput, ApprovalState
from ssh_over_mcp.approvals.protocol import (
    ConsumeApprovalRequest,
    EnsureApprovalRequest,
    ErrorResponse,
    GrantApprovalRequest,
    ListApprovalsRequest,
    PingRequest,
)
from ssh_over_mcp.approvals.storage import LedgerDatabase, LedgerStorageSettings
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentials
from ssh_over_mcp.policy.models import RiskLevel


def _store(tmp_path: Path):
    from ssh_over_mcp.approvals.ledger import SecurityLedgerStore

    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    key = root / "ledger.key"
    key.write_bytes(b"K" * 32)
    os.chmod(key, 0o600)
    info = root.stat()
    db = LedgerDatabase.open(
        LedgerStorageSettings(
            db_path=root / "ledger.db",
            hmac_key_path=key,
            service_uid=info.st_uid,
            service_gid=info.st_gid,
        )
    )
    now = datetime(2026, 10, 1, 18, 0, tzinfo=UTC)
    return db, SecurityLedgerStore(db, b"K" * 32, clock=lambda: now)


def _binding() -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        privilege="user",
        policy_version="sha256:policy",
        normalized_path="/srv/app/new",
        argv_count=0,
        argv_fingerprint=fingerprint_argv(()),
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
    )


def _peer(uid: int = 1000, gid: int = 1000) -> LinuxPeerCredentials:
    return LinuxPeerCredentials(pid=1234, uid=uid, gid=gid)


def test_execution_dispatcher_rejects_admin_operations(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.dispatcher import ExecutionLedgerDispatcher

    db, store = _store(tmp_path)
    try:
        response = ExecutionLedgerDispatcher(store).dispatch(
            GrantApprovalRequest(
                message_id="msg_" + "1" * 32,
                approval_id="apr_" + "2" * 32,
            ),
            peer=_peer(),
        )
        assert isinstance(response, ErrorResponse)
        assert response.code == "not_authorized"
        assert response.message_id == "msg_" + "1" * 32
    finally:
        db.close()


def test_execution_ensure_derives_safe_summary_and_consume_is_bound(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.dispatcher import ExecutionLedgerDispatcher

    db, store = _store(tmp_path)
    dispatcher = ExecutionLedgerDispatcher(store)
    binding = _binding()
    try:
        ensured = dispatcher.dispatch(
            EnsureApprovalRequest(
                message_id="msg_" + "1" * 32,
                request_id="req_" + "2" * 32,
                binding=binding,
                risk=RiskLevel.HIGH,
            ),
            peer=_peer(),
        )
        status = ensured.status
        assert status.safe_summary.normalized_path == "/srv/app/new"
        assert status.safe_summary.argv_fingerprint == binding.argv_fingerprint
        assert status.safe_summary.risk is RiskLevel.HIGH

        store.grant(status.approval_id, operator_identity="uid:0:gid:0")
        consumed = dispatcher.dispatch(
            ConsumeApprovalRequest(
                message_id="msg_" + "3" * 32,
                request_id="req_" + "4" * 32,
                approval_id=status.approval_id,
                binding=binding,
            ),
            peer=_peer(),
        )
        assert consumed.status.state is ApprovalState.CONSUMED
    finally:
        db.close()


def test_admin_dispatcher_uses_peer_identity_and_rejects_consume(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.dispatcher import AdminLedgerDispatcher

    db, store = _store(tmp_path)
    binding = _binding()
    try:
        approval = store.ensure_approval(
            binding,
            __import__(
                "ssh_over_mcp.approvals.dispatcher",
                fromlist=["safe_summary_from_binding"],
            ).safe_summary_from_binding(binding, RiskLevel.HIGH),
            "req_" + "1" * 32,
        )
        dispatcher = AdminLedgerDispatcher(store)
        granted = dispatcher.dispatch(
            GrantApprovalRequest(
                message_id="msg_" + "2" * 32,
                approval_id=approval.approval_id,
            ),
            peer=_peer(uid=2001, gid=3001),
        )
        assert granted.status.state is ApprovalState.GRANTED
        operator = db.connection.execute(
            "SELECT operator_identity FROM approvals WHERE approval_id=?",
            (approval.approval_id,),
        ).fetchone()[0]
        assert operator == "uid:2001:gid:3001"

        rejected = dispatcher.dispatch(
            ConsumeApprovalRequest(
                message_id="msg_" + "3" * 32,
                request_id="req_" + "4" * 32,
                approval_id=approval.approval_id,
                binding=binding,
            ),
            peer=_peer(uid=2001, gid=3001),
        )
        assert isinstance(rejected, ErrorResponse)
        assert rejected.code == "not_authorized"
    finally:
        db.close()


def test_admin_list_is_bounded_and_execution_ping_is_supported(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.dispatcher import (
        AdminLedgerDispatcher,
        ExecutionLedgerDispatcher,
    )

    db, store = _store(tmp_path)
    try:
        pong = ExecutionLedgerDispatcher(store).dispatch(
            PingRequest(message_id="msg_" + "1" * 32),
            peer=_peer(),
        )
        assert pong.type == "pong"

        listed = AdminLedgerDispatcher(store).dispatch(
            ListApprovalsRequest(
                message_id="msg_" + "2" * 32,
                limit=100,
            ),
            peer=_peer(uid=2001, gid=3001),
        )
        assert listed.type == "approval_list"
        assert listed.approvals == ()
    finally:
        db.close()
