from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ssh_over_mcp.approvals.binding import fingerprint_argv, fingerprint_bytes
from ssh_over_mcp.approvals.models import (
    ApprovalBindingInput,
    ApprovalSafeSummary,
    ApprovalState,
)
from ssh_over_mcp.approvals.storage import LedgerDatabase, LedgerStorageSettings
from ssh_over_mcp.policy.models import RiskLevel


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


def _settings(tmp_path: Path) -> LedgerStorageSettings:
    data_dir = tmp_path / "ledger"
    data_dir.mkdir(mode=0o700)
    os.chmod(data_dir, 0o700)
    key_path = data_dir / "ledger.key"
    key_path.write_bytes(b"K" * 32)
    os.chmod(key_path, 0o600)
    info = data_dir.stat()
    return LedgerStorageSettings(
        db_path=data_dir / "ledger.db",
        hmac_key_path=key_path,
        service_uid=info.st_uid,
        service_gid=info.st_gid,
    )


def _binding(*, path: str = "/srv/app/file", content: bytes = b"") -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_write",
        privilege="user",
        policy_version="sha256:policy",
        normalized_path=path,
        argv_count=0,
        argv_fingerprint=fingerprint_argv(()),
        content_length=len(content),
        content_fingerprint=fingerprint_bytes(content),
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
        effective_tool_bytes=65536,
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
        argv_count=binding.argv_count,
        argv_fingerprint=binding.argv_fingerprint,
        content_length=binding.content_length,
        content_fingerprint=binding.content_fingerprint,
        effective_timeout_seconds=binding.effective_timeout_seconds,
        effective_max_output_bytes=binding.effective_max_output_bytes,
        effective_tool_bytes=binding.effective_tool_bytes,
    )


def _store(tmp_path: Path, clock: Clock, **kwargs):
    from ssh_over_mcp.approvals.ledger import SecurityLedgerStore

    settings = _settings(tmp_path)
    database = LedgerDatabase.open(settings)
    return settings, database, SecurityLedgerStore(
        database,
        b"K" * 32,
        clock=clock,
        **kwargs,
    )


def _events(database: LedgerDatabase) -> list[str]:
    return [
        row[0]
        for row in database.connection.execute(
            "SELECT event_type FROM audit_events ORDER BY sequence"
        )
    ]


def test_ledger_ttl_is_service_owned_and_constructor_is_bounded(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.ledger import SecurityLedgerStore

    settings = _settings(tmp_path)
    database = LedgerDatabase.open(settings)
    try:
        with pytest.raises(ValueError):
            SecurityLedgerStore(database, b"K" * 32, default_ttl_seconds=0)
        with pytest.raises(ValueError):
            SecurityLedgerStore(
                database,
                b"K" * 32,
                default_ttl_seconds=601,
                max_ttl_seconds=600,
            )
        with pytest.raises(ValueError):
            SecurityLedgerStore(
                database,
                b"K" * 32,
                max_ttl_seconds=3601,
            )
    finally:
        database.close()


def test_ensure_reuses_one_active_approval_and_appends_per_request_event(
    tmp_path: Path,
) -> None:
    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(tmp_path, clock)
    binding = _binding(content=b"secret-bytes")
    summary = _summary(binding)
    try:
        first = store.ensure_approval(binding, summary, "req_" + "1" * 32)
        second = store.ensure_approval(binding, summary, "req_" + "2" * 32)

        assert first.approval_id == second.approval_id
        assert first.state is ApprovalState.PENDING
        assert first.expires_at == clock.value + timedelta(seconds=600)
        assert _events(database) == ["approval_required", "approval_required"]
    finally:
        database.close()


def test_deny_stays_active_until_expiry_then_binding_is_released(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(tmp_path, clock, default_ttl_seconds=60)
    binding = _binding()
    summary = _summary(binding)
    try:
        pending = store.ensure_approval(binding, summary, "req_" + "1" * 32)
        denied = store.deny(pending.approval_id, operator_identity="uid:0:gid:0")
        assert denied.state is ApprovalState.DENIED

        reused = store.ensure_approval(binding, summary, "req_" + "2" * 32)
        assert reused.approval_id == pending.approval_id
        assert reused.state is ApprovalState.DENIED

        clock.advance(seconds=61)
        replacement = store.ensure_approval(binding, summary, "req_" + "3" * 32)
        assert replacement.approval_id != pending.approval_id
        expired = store.get_approval(pending.approval_id)
        assert expired is not None
        assert expired.state is ApprovalState.EXPIRED
        assert _events(database).count("approval_expired") == 1
    finally:
        database.close()


def test_grant_and_deny_are_terminal_and_mutually_exclusive(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.ledger import LedgerConflictError

    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(tmp_path, clock)
    binding = _binding()
    summary = _summary(binding)
    try:
        pending = store.ensure_approval(binding, summary, "req_" + "1" * 32)
        granted = store.grant(pending.approval_id, operator_identity="uid:0:gid:0")
        assert granted.state is ApprovalState.GRANTED
        with pytest.raises(LedgerConflictError):
            store.deny(granted.approval_id, operator_identity="uid:0:gid:0")
        with pytest.raises(LedgerConflictError):
            store.grant(granted.approval_id, operator_identity="uid:0:gid:0")
    finally:
        database.close()


def test_status_filter_hides_other_principal_or_profile(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(tmp_path, clock)
    binding = _binding()
    try:
        status = store.ensure_approval(binding, _summary(binding), "req_" + "1" * 32)
        assert (
            store.get_approval(
                status.approval_id,
                principal_id="static:other",
                profile="developer",
            )
            is None
        )
        assert (
            store.get_approval(
                status.approval_id,
                principal_id=binding.principal_id,
                profile="ops",
            )
            is None
        )
    finally:
        database.close()


def test_consume_requires_exact_binding_and_is_single_use(tmp_path: Path) -> None:
    from ssh_over_mcp.approvals.ledger import (
        LedgerConflictError,
        LedgerNotAuthorizedError,
    )

    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(tmp_path, clock)
    binding = _binding(content=b"alpha")
    try:
        pending = store.ensure_approval(binding, _summary(binding), "req_" + "1" * 32)
        store.grant(pending.approval_id, operator_identity="uid:0:gid:0")

        with pytest.raises(LedgerNotAuthorizedError):
            store.consume(
                pending.approval_id,
                _binding(content=b"beta"),
                "req_" + "2" * 32,
            )

        consumed = store.consume(
            pending.approval_id,
            binding,
            "req_" + "3" * 32,
        )
        assert consumed.state is ApprovalState.CONSUMED
        with pytest.raises(LedgerConflictError):
            store.consume(
                pending.approval_id,
                binding,
                "req_" + "4" * 32,
            )
        events = _events(database)
        assert events.count("approval_consumed") == 1
        assert events.count("approval_required") == 2
        assert events[-2:] == ["approval_required", "approval_consumed"]
    finally:
        database.close()


def test_consumed_state_survives_restart_and_raw_secret_is_not_stored(
    tmp_path: Path,
) -> None:
    secret = b"SUPERSECRET-file-body"
    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    settings = _settings(tmp_path)
    binding = _binding(content=secret)

    database = LedgerDatabase.open(settings)
    from ssh_over_mcp.approvals.ledger import SecurityLedgerStore

    store = SecurityLedgerStore(database, b"K" * 32, clock=clock)
    pending = store.ensure_approval(binding, _summary(binding), "req_" + "1" * 32)
    store.grant(pending.approval_id, operator_identity="uid:0:gid:0")
    store.consume(pending.approval_id, binding, "req_" + "2" * 32)
    database.close()

    reopened = LedgerDatabase.open(settings)
    try:
        restarted = SecurityLedgerStore(reopened, b"K" * 32, clock=clock)
        status = restarted.get_approval(pending.approval_id)
        assert status is not None
        assert status.state is ApprovalState.CONSUMED
        dump = "\n".join(
            str(tuple(row))
            for table in ("approvals", "audit_events")
            for row in reopened.connection.execute(f"SELECT * FROM {table}")
        )
        assert secret.decode() not in dump
    finally:
        reopened.close()


def test_store_rejects_hmac_key_that_does_not_match_database(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.ledger import SecurityLedgerStore

    settings = _settings(tmp_path)
    database = LedgerDatabase.open(settings)
    try:
        with pytest.raises(ValueError, match="HMAC key does not match"):
            SecurityLedgerStore(database, b"Z" * 32)
    finally:
        database.close()


def test_list_active_fills_limit_after_expiring_older_rows(
    tmp_path: Path,
) -> None:
    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(
        tmp_path,
        clock,
        default_ttl_seconds=60,
    )
    try:
        first_binding = _binding(path="/srv/app/first")
        first = store.ensure_approval(
            first_binding,
            _summary(first_binding),
            "req_" + "1" * 32,
        )
        clock.advance(seconds=30)
        second_binding = _binding(path="/srv/app/second")
        second = store.ensure_approval(
            second_binding,
            _summary(second_binding),
            "req_" + "2" * 32,
        )
        clock.advance(seconds=31)

        active = store.list_active(limit=1)

        assert tuple(item.approval_id for item in active) == (
            second.approval_id,
        )
        expired = store.get_approval(first.approval_id)
        assert expired is not None
        assert expired.state is ApprovalState.EXPIRED
    finally:
        database.close()


def test_grant_after_expiry_persists_expired_state_and_event_once(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.ledger import LedgerExpiredError

    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(
        tmp_path,
        clock,
        default_ttl_seconds=10,
    )
    binding = _binding(path="/srv/app/grant-expired")
    try:
        pending = store.ensure_approval(
            binding,
            _summary(binding),
            "req_" + "1" * 32,
        )
        clock.advance(seconds=11)

        with pytest.raises(LedgerExpiredError):
            store.grant(
                pending.approval_id,
                operator_identity="uid:0:gid:0",
            )
        with pytest.raises(LedgerExpiredError):
            store.grant(
                pending.approval_id,
                operator_identity="uid:0:gid:0",
            )

        row = database.connection.execute(
            "SELECT state,active_binding_hmac FROM approvals "
            "WHERE approval_id=?",
            (pending.approval_id,),
        ).fetchone()
        assert row == (ApprovalState.EXPIRED.value, None)
        assert _events(database).count("approval_expired") == 1
    finally:
        database.close()


def test_consume_after_expiry_persists_expired_state_and_event_once(
    tmp_path: Path,
) -> None:
    from ssh_over_mcp.approvals.ledger import LedgerExpiredError

    clock = Clock(datetime(2026, 10, 1, 18, 0, tzinfo=UTC))
    _settings_obj, database, store = _store(
        tmp_path,
        clock,
        default_ttl_seconds=10,
    )
    binding = _binding(path="/srv/app/consume-expired")
    try:
        pending = store.ensure_approval(
            binding,
            _summary(binding),
            "req_" + "1" * 32,
        )
        store.grant(
            pending.approval_id,
            operator_identity="uid:0:gid:0",
        )
        clock.advance(seconds=11)

        with pytest.raises(LedgerExpiredError):
            store.consume(
                pending.approval_id,
                binding,
                "req_" + "2" * 32,
            )
        with pytest.raises(LedgerExpiredError):
            store.consume(
                pending.approval_id,
                binding,
                "req_" + "3" * 32,
            )

        row = database.connection.execute(
            "SELECT state,active_binding_hmac FROM approvals "
            "WHERE approval_id=?",
            (pending.approval_id,),
        ).fetchone()
        assert row == (ApprovalState.EXPIRED.value, None)
        assert _events(database).count("approval_expired") == 1
    finally:
        database.close()
