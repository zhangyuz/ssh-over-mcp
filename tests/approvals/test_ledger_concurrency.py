from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from ssh_over_mcp.approvals.binding import fingerprint_argv
from ssh_over_mcp.approvals.models import ApprovalBindingInput, ApprovalSafeSummary
from ssh_over_mcp.approvals.storage import LedgerDatabase, LedgerStorageSettings
from ssh_over_mcp.policy.models import RiskLevel


def _settings(tmp_path: Path) -> LedgerStorageSettings:
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    key = root / "ledger.key"
    key.write_bytes(b"K" * 32)
    os.chmod(key, 0o600)
    info = root.stat()
    return LedgerStorageSettings(
        db_path=root / "ledger.db",
        hmac_key_path=key,
        service_uid=info.st_uid,
        service_gid=info.st_gid,
    )


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


def _summary(binding: ApprovalBindingInput) -> ApprovalSafeSummary:
    return ApprovalSafeSummary(
        principal_id=binding.principal_id,
        profile=binding.profile,
        host=binding.host,
        tool=binding.tool,
        privilege=binding.privilege,
        policy_version=binding.policy_version,
        risk=RiskLevel.HIGH,
        normalized_path=binding.normalized_path,
        argv_count=0,
        argv_fingerprint=binding.argv_fingerprint,
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
    )


def test_concurrent_ensure_converges_on_one_active_approval(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.ledger import SecurityLedgerStore

    settings = _settings(tmp_path)
    seed = LedgerDatabase.open(settings)
    seed.close()
    binding = _binding()
    summary = _summary(binding)
    now = datetime(2026, 10, 1, 18, 0, tzinfo=UTC)

    def ensure(index: int) -> str:
        db = LedgerDatabase.open(settings)
        try:
            store = SecurityLedgerStore(db, b"K" * 32, clock=lambda: now)
            return store.ensure_approval(
                binding,
                summary,
                f"req_{index:032x}",
            ).approval_id
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = tuple(pool.map(ensure, range(1, 9)))

    assert len(set(ids)) == 1


def test_concurrent_consume_has_exactly_one_success(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.ledger import LedgerConflictError, SecurityLedgerStore

    settings = _settings(tmp_path)
    binding = _binding()
    summary = _summary(binding)
    now = datetime(2026, 10, 1, 18, 0, tzinfo=UTC)

    setup_db = LedgerDatabase.open(settings)
    setup_store = SecurityLedgerStore(setup_db, b"K" * 32, clock=lambda: now)
    approval = setup_store.ensure_approval(binding, summary, "req_" + "1" * 32)
    setup_store.grant(approval.approval_id, operator_identity="uid:0:gid:0")
    setup_db.close()

    def consume(index: int) -> str:
        db = LedgerDatabase.open(settings)
        try:
            store = SecurityLedgerStore(db, b"K" * 32, clock=lambda: now)
            try:
                store.consume(
                    approval.approval_id,
                    binding,
                    f"req_{index:032x}",
                )
            except LedgerConflictError:
                return "conflict"
            return "consumed"
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(pool.map(consume, range(2, 10)))

    assert results.count("consumed") == 1
    assert results.count("conflict") == 7
