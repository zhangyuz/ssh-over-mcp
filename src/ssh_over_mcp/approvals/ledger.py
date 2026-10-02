from __future__ import annotations

import hashlib
import hmac
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.policy.models import Decision

from .binding import canonical_binding_bytes
from .models import (
    ApprovalBindingInput,
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from .storage import LedgerDatabase


class LedgerError(RuntimeError):
    """Base class for stable Security Ledger state failures."""


class LedgerNotFoundError(LedgerError):
    """The requested approval does not exist."""


class LedgerConflictError(LedgerError):
    """The requested approval transition is not permitted."""


class LedgerExpiredError(LedgerConflictError):
    """The requested approval has expired."""


class LedgerNotAuthorizedError(LedgerError):
    """The supplied approval binding does not match the stored grant."""


class LedgerPersistenceError(LedgerError):
    """The local Security Ledger could not persist a required operation."""


_APPROVAL_COLUMNS = (
    "approval_id,binding_hmac,active_binding_hmac,binding_version,"
    "principal_id,profile,host,tool,privilege,policy_version,risk,state,"
    "safe_summary_json,binding_fingerprint,first_request_id,created_at,"
    "expires_at,decided_at,consumed_at,operator_identity"
)


def _utc_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LedgerPersistenceError("Security Ledger timestamp is invalid")
    return parsed


class SecurityLedgerStore:
    def __init__(
        self,
        database: LedgerDatabase,
        hmac_key: bytes,
        *,
        clock: Callable[[], datetime] | None = None,
        default_ttl_seconds: int = 600,
        max_ttl_seconds: int = 3600,
    ) -> None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) != 32:
            raise ValueError("Security Ledger HMAC key must contain exactly 32 bytes")
        if (
            isinstance(default_ttl_seconds, bool)
            or not isinstance(default_ttl_seconds, int)
            or isinstance(max_ttl_seconds, bool)
            or not isinstance(max_ttl_seconds, int)
            or default_ttl_seconds < 1
            or max_ttl_seconds < 1
            or default_ttl_seconds > max_ttl_seconds
            or max_ttl_seconds > 3600
        ):
            raise ValueError("Security Ledger TTL configuration is invalid")

        try:
            stored_key_id_row = database.connection.execute(
                "SELECT value FROM meta WHERE key='hmac_key_id'"
            ).fetchone()
        except sqlite3.Error:
            raise LedgerPersistenceError(
                "Security Ledger key identity could not be verified"
            ) from None
        if (
            stored_key_id_row is None
            or not hmac.compare_digest(
                str(stored_key_id_row[0]),
                hashlib.sha256(hmac_key).hexdigest(),
            )
        ):
            raise ValueError(
                "Security Ledger HMAC key does not match database"
            )

        self._database = database
        self._hmac_key = hmac_key
        self._clock = clock or (lambda: datetime.now(UTC))
        self._default_ttl_seconds = default_ttl_seconds
        self._max_ttl_seconds = max_ttl_seconds

    @property
    def connection(self) -> sqlite3.Connection:
        return self._database.connection

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Security Ledger clock must return timezone-aware UTC")
        return value

    def _binding_hmac(self, binding: ApprovalBindingInput) -> str:
        digest = hmac.digest(
            self._hmac_key,
            canonical_binding_bytes(binding),
            "sha256",
        ).hex()
        return f"hmac-sha256:v1:{digest}"

    @staticmethod
    def _binding_fingerprint(binding_hmac: str) -> str:
        prefix, version, digest = binding_hmac.split(":", 2)
        if prefix != "hmac-sha256" or version != "v1" or len(digest) != 64:
            raise LedgerPersistenceError("Security Ledger binding HMAC is invalid")
        return f"hmac-sha256:v1:{digest[:16]}"

    @staticmethod
    def _validate_summary_matches_binding(
        binding: ApprovalBindingInput,
        summary: ApprovalSafeSummary,
    ) -> None:
        expected = {
            "principal_id": binding.principal_id,
            "profile": binding.profile,
            "host": binding.host,
            "tool": binding.tool,
            "privilege": binding.privilege,
            "policy_version": binding.policy_version,
            "normalized_executable": binding.normalized_executable,
            "normalized_cwd": binding.normalized_cwd,
            "normalized_path": binding.normalized_path,
            "argv_count": binding.argv_count,
            "argv_fingerprint": binding.argv_fingerprint,
            "env_names": tuple(item.name for item in binding.env_fingerprints),
            "stdin_length": binding.stdin_length,
            "stdin_fingerprint": binding.stdin_fingerprint,
            "content_length": binding.content_length,
            "content_fingerprint": binding.content_fingerprint,
            "effective_timeout_seconds": binding.effective_timeout_seconds,
            "effective_max_output_bytes": binding.effective_max_output_bytes,
            "effective_max_stdin_bytes": binding.effective_max_stdin_bytes,
            "effective_tool_bytes": binding.effective_tool_bytes,
        }
        for field, expected_value in expected.items():
            if getattr(summary, field) != expected_value:
                raise ValueError("approval safe summary does not match binding")

    def _begin(self) -> None:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise LedgerPersistenceError(
                "Security Ledger transaction could not start"
            ) from None

    def _commit(self) -> None:
        try:
            self.connection.commit()
        except sqlite3.Error:
            self.connection.rollback()
            raise LedgerPersistenceError(
                "Security Ledger transaction could not commit"
            ) from None

    def _rollback(self) -> None:
        try:
            self.connection.rollback()
        except sqlite3.Error:
            pass

    def _load_row_by_id(self, approval_id: str):
        try:
            return self.connection.execute(
                f"SELECT {_APPROVAL_COLUMNS} FROM approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
        except sqlite3.Error:
            raise LedgerPersistenceError(
                "Security Ledger approval lookup failed"
            ) from None

    def _load_row_by_active_hmac(self, binding_hmac: str):
        try:
            return self.connection.execute(
                f"SELECT {_APPROVAL_COLUMNS} FROM approvals "
                "WHERE active_binding_hmac=?",
                (binding_hmac,),
            ).fetchone()
        except sqlite3.Error:
            raise LedgerPersistenceError(
                "Security Ledger approval lookup failed"
            ) from None

    @staticmethod
    def _row_mapping(row) -> dict[str, object]:
        names = _APPROVAL_COLUMNS.split(",")
        return dict(zip(names, row, strict=True))

    def _status_from_row(self, row) -> ApprovalStatus:
        data = self._row_mapping(row)
        try:
            summary = ApprovalSafeSummary.model_validate_json(
                str(data["safe_summary_json"])
            )
            state = ApprovalState(str(data["state"]))
            return ApprovalStatus(
                approval_id=str(data["approval_id"]),
                state=state,
                expires_at=_parse_utc(str(data["expires_at"])),
                host=str(data["host"]),
                tool=str(data["tool"]),
                risk=str(data["risk"]),
                safe_summary=summary,
                binding_fingerprint=str(data["binding_fingerprint"]),
            )
        except (ValueError, TypeError):
            raise LedgerPersistenceError(
                "Security Ledger approval row is invalid"
            ) from None

    def _approval_event(
        self,
        *,
        event_type: AuditEventType,
        request_id: str,
        approval_id: str,
        summary: ApprovalSafeSummary,
        decision: Decision | None = None,
    ) -> AuditEventInput:
        return AuditEventInput(
            event_type=event_type,
            request_id=request_id,
            principal_id=summary.principal_id,
            profile=summary.profile,
            host=summary.host,
            tool=summary.tool,
            policy_version=summary.policy_version,
            decision=decision,
            risk=summary.risk,
            approval_id=approval_id,
            safe_summary=summary,
        )

    def _append_audit_locked(self, event: AuditEventInput) -> str:
        event_id = f"evt_{uuid.uuid4().hex}"
        try:
            self.connection.execute(
                """
                INSERT INTO audit_events(
                    event_id,request_id,timestamp,event_type,
                    principal_id,profile,host,tool,policy_version,
                    decision,risk,approval_id,safe_summary_json,
                    exit_status,exit_signal,duration_ms,stdout_bytes,
                    stderr_bytes,timed_out,truncated
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    event.request_id,
                    _utc_iso(self._now()),
                    event.event_type.value,
                    event.principal_id,
                    event.profile,
                    event.host,
                    event.tool,
                    event.policy_version,
                    event.decision.value if event.decision is not None else None,
                    event.risk.value if event.risk is not None else None,
                    event.approval_id,
                    (
                        event.safe_summary.model_dump_json()
                        if event.safe_summary is not None
                        else None
                    ),
                    event.exit_status,
                    event.exit_signal,
                    event.duration_ms,
                    event.stdout_bytes,
                    event.stderr_bytes,
                    (
                        int(event.timed_out)
                        if event.timed_out is not None
                        else None
                    ),
                    (
                        int(event.truncated)
                        if event.truncated is not None
                        else None
                    ),
                ),
            )
        except sqlite3.Error:
            raise LedgerPersistenceError(
                "Security Ledger audit append failed"
            ) from None
        return event_id

    def append_audit(self, event: AuditEventInput) -> str:
        self._begin()
        try:
            event_id = self._append_audit_locked(event)
            self._commit()
            return event_id
        except Exception:
            self._rollback()
            raise

    def _expire_row_if_needed(self, row, *, now: datetime):
        data = self._row_mapping(row)
        state = ApprovalState(str(data["state"]))
        expires_at = _parse_utc(str(data["expires_at"]))
        if (
            state not in {
                ApprovalState.PENDING,
                ApprovalState.GRANTED,
                ApprovalState.DENIED,
            }
            or expires_at > now
        ):
            return row

        approval_id = str(data["approval_id"])
        try:
            cursor = self.connection.execute(
                "UPDATE approvals SET state=?, active_binding_hmac=NULL "
                "WHERE approval_id=? AND state IN (?,?,?)",
                (
                    ApprovalState.EXPIRED.value,
                    approval_id,
                    ApprovalState.PENDING.value,
                    ApprovalState.GRANTED.value,
                    ApprovalState.DENIED.value,
                ),
            )
        except sqlite3.Error:
            raise LedgerPersistenceError(
                "Security Ledger approval expiry failed"
            ) from None

        if cursor.rowcount == 1:
            summary = ApprovalSafeSummary.model_validate_json(
                str(data["safe_summary_json"])
            )
            self._append_audit_locked(
                self._approval_event(
                    event_type=AuditEventType.APPROVAL_EXPIRED,
                    request_id=str(data["first_request_id"]),
                    approval_id=approval_id,
                    summary=summary,
                )
            )
        return self._load_row_by_id(approval_id)

    def ensure_approval(
        self,
        binding: ApprovalBindingInput,
        summary: ApprovalSafeSummary,
        request_id: str,
    ) -> ApprovalStatus:
        self._validate_summary_matches_binding(binding, summary)
        binding_hmac = self._binding_hmac(binding)
        now = self._now()

        self._begin()
        try:
            row = self._load_row_by_active_hmac(binding_hmac)
            if row is not None:
                row = self._expire_row_if_needed(row, now=now)
                if row is not None:
                    state = ApprovalState(str(self._row_mapping(row)["state"]))
                    if state in {
                        ApprovalState.PENDING,
                        ApprovalState.GRANTED,
                        ApprovalState.DENIED,
                    }:
                        status = self._status_from_row(row)
                        self._append_audit_locked(
                            self._approval_event(
                                event_type=AuditEventType.APPROVAL_REQUIRED,
                                request_id=request_id,
                                approval_id=status.approval_id,
                                summary=status.safe_summary,
                                decision=Decision.APPROVAL_REQUIRED,
                            )
                        )
                        self._commit()
                        return status

            approval_id = f"apr_{uuid.uuid4().hex}"
            expires_at = now + timedelta(seconds=self._default_ttl_seconds)
            fingerprint = self._binding_fingerprint(binding_hmac)
            try:
                self.connection.execute(
                    """
                    INSERT INTO approvals(
                        approval_id,binding_hmac,active_binding_hmac,
                        binding_version,principal_id,profile,host,tool,
                        privilege,policy_version,risk,state,
                        safe_summary_json,binding_fingerprint,
                        first_request_id,created_at,expires_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        approval_id,
                        binding_hmac,
                        binding_hmac,
                        binding.binding_version,
                        binding.principal_id,
                        binding.profile,
                        binding.host,
                        binding.tool,
                        binding.privilege,
                        binding.policy_version,
                        summary.risk.value,
                        ApprovalState.PENDING.value,
                        summary.model_dump_json(),
                        fingerprint,
                        request_id,
                        _utc_iso(now),
                        _utc_iso(expires_at),
                    ),
                )
            except sqlite3.IntegrityError:
                # BEGIN IMMEDIATE serializes writers. If a row appears despite
                # that guarantee, fail closed rather than guessing.
                raise LedgerConflictError(
                    "active approval already exists"
                ) from None
            except sqlite3.Error:
                raise LedgerPersistenceError(
                    "Security Ledger approval create failed"
                ) from None

            self._append_audit_locked(
                self._approval_event(
                    event_type=AuditEventType.APPROVAL_REQUIRED,
                    request_id=request_id,
                    approval_id=approval_id,
                    summary=summary,
                    decision=Decision.APPROVAL_REQUIRED,
                )
            )
            row = self._load_row_by_id(approval_id)
            if row is None:
                raise LedgerPersistenceError(
                    "Security Ledger approval create failed"
                )
            status = self._status_from_row(row)
            self._commit()
            return status
        except Exception:
            self._rollback()
            raise

    def get_approval(
        self,
        approval_id: str,
        *,
        principal_id: str | None = None,
        profile: str | None = None,
    ) -> ApprovalStatus | None:
        now = self._now()
        self._begin()
        try:
            row = self._load_row_by_id(approval_id)
            if row is None:
                self._commit()
                return None
            row = self._expire_row_if_needed(row, now=now)
            if row is None:
                self._commit()
                return None
            data = self._row_mapping(row)
            if principal_id is not None and data["principal_id"] != principal_id:
                self._commit()
                return None
            if profile is not None and data["profile"] != profile:
                self._commit()
                return None
            status = self._status_from_row(row)
            self._commit()
            return status
        except Exception:
            self._rollback()
            raise

    def _decide(
        self,
        approval_id: str,
        *,
        state: ApprovalState,
        operator_identity: str,
        event_type: AuditEventType,
    ) -> ApprovalStatus:
        if not operator_identity or len(operator_identity) > 256:
            raise ValueError("operator identity is invalid")
        now = self._now()
        self._begin()
        try:
            row = self._load_row_by_id(approval_id)
            if row is None:
                raise LedgerNotFoundError("approval not found")
            row = self._expire_row_if_needed(row, now=now)
            if row is None:
                raise LedgerNotFoundError("approval not found")
            data = self._row_mapping(row)
            current = ApprovalState(str(data["state"]))
            if current is ApprovalState.EXPIRED:
                self._commit()
                raise LedgerExpiredError("approval expired")
            if current is not ApprovalState.PENDING:
                raise LedgerConflictError("approval transition is not permitted")

            try:
                self.connection.execute(
                    "UPDATE approvals SET state=?,decided_at=?,operator_identity=? "
                    "WHERE approval_id=? AND state=?",
                    (
                        state.value,
                        _utc_iso(now),
                        operator_identity,
                        approval_id,
                        ApprovalState.PENDING.value,
                    ),
                )
            except sqlite3.Error:
                raise LedgerPersistenceError(
                    "Security Ledger approval decision failed"
                ) from None

            summary = ApprovalSafeSummary.model_validate_json(
                str(data["safe_summary_json"])
            )
            self._append_audit_locked(
                self._approval_event(
                    event_type=event_type,
                    request_id=str(data["first_request_id"]),
                    approval_id=approval_id,
                    summary=summary,
                )
            )
            updated = self._load_row_by_id(approval_id)
            if updated is None:
                raise LedgerPersistenceError(
                    "Security Ledger approval decision failed"
                )
            status = self._status_from_row(updated)
            self._commit()
            return status
        except Exception:
            self._rollback()
            raise

    def grant(
        self,
        approval_id: str,
        *,
        operator_identity: str,
    ) -> ApprovalStatus:
        return self._decide(
            approval_id,
            state=ApprovalState.GRANTED,
            operator_identity=operator_identity,
            event_type=AuditEventType.APPROVAL_GRANTED,
        )

    def deny(
        self,
        approval_id: str,
        *,
        operator_identity: str,
    ) -> ApprovalStatus:
        return self._decide(
            approval_id,
            state=ApprovalState.DENIED,
            operator_identity=operator_identity,
            event_type=AuditEventType.APPROVAL_DENIED,
        )

    def consume(
        self,
        approval_id: str,
        binding: ApprovalBindingInput,
        request_id: str,
    ) -> ApprovalStatus:
        now = self._now()
        supplied_hmac = self._binding_hmac(binding)

        self._begin()
        try:
            row = self._load_row_by_id(approval_id)
            if row is None:
                raise LedgerNotFoundError("approval not found")
            row = self._expire_row_if_needed(row, now=now)
            if row is None:
                raise LedgerNotFoundError("approval not found")
            data = self._row_mapping(row)
            state = ApprovalState(str(data["state"]))
            if state is ApprovalState.EXPIRED:
                self._commit()
                raise LedgerExpiredError("approval expired")
            if state is not ApprovalState.GRANTED:
                raise LedgerConflictError("approval is not consumable")
            stored_hmac = str(data["binding_hmac"])
            if not hmac.compare_digest(stored_hmac, supplied_hmac):
                raise LedgerNotAuthorizedError(
                    "approval binding does not match"
                )

            summary = ApprovalSafeSummary.model_validate_json(
                str(data["safe_summary_json"])
            )
            self._append_audit_locked(
                self._approval_event(
                    event_type=AuditEventType.APPROVAL_REQUIRED,
                    request_id=request_id,
                    approval_id=approval_id,
                    summary=summary,
                    decision=Decision.APPROVAL_REQUIRED,
                )
            )

            try:
                cursor = self.connection.execute(
                    "UPDATE approvals SET state=?,active_binding_hmac=NULL,"
                    "consumed_at=? WHERE approval_id=? AND state=?",
                    (
                        ApprovalState.CONSUMED.value,
                        _utc_iso(now),
                        approval_id,
                        ApprovalState.GRANTED.value,
                    ),
                )
            except sqlite3.Error:
                raise LedgerPersistenceError(
                    "Security Ledger approval consume failed"
                ) from None
            if cursor.rowcount != 1:
                raise LedgerConflictError("approval is not consumable")

            self._append_audit_locked(
                self._approval_event(
                    event_type=AuditEventType.APPROVAL_CONSUMED,
                    request_id=request_id,
                    approval_id=approval_id,
                    summary=summary,
                )
            )
            updated = self._load_row_by_id(approval_id)
            if updated is None:
                raise LedgerPersistenceError(
                    "Security Ledger approval consume failed"
                )
            status = self._status_from_row(updated)
            self._commit()
            return status
        except Exception:
            self._rollback()
            raise

    def list_active(self, limit: int = 100) -> tuple[ApprovalStatus, ...]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("approval list limit must be in [1, 100]")
        now = self._now()
        self._begin()
        try:
            try:
                rows = self.connection.execute(
                    f"SELECT {_APPROVAL_COLUMNS} FROM approvals "
                    "WHERE active_binding_hmac IS NOT NULL "
                    "AND expires_at > ? "
                    "ORDER BY created_at LIMIT ?",
                    (_utc_iso(now), limit),
                ).fetchall()
            except sqlite3.Error:
                raise LedgerPersistenceError(
                    "Security Ledger approval list failed"
                ) from None

            statuses: list[ApprovalStatus] = []
            for row in rows:
                current = self._expire_row_if_needed(row, now=now)
                if current is None:
                    continue
                state = ApprovalState(str(self._row_mapping(current)["state"]))
                if state in {
                    ApprovalState.PENDING,
                    ApprovalState.GRANTED,
                    ApprovalState.DENIED,
                }:
                    statuses.append(self._status_from_row(current))
            self._commit()
            return tuple(statuses)
        except Exception:
            self._rollback()
            raise
