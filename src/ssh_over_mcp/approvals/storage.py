from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Self

_SCHEMA_VERSION = "1"
_KEY_BYTES = 32
_ALLOWED_KEY_MODES = frozenset({0o400, 0o600})
_DATABASE_MODE = 0o600
_MAX_BUSY_TIMEOUT_MS = 60_000
_MAX_KERNEL_ID = (1 << 32) - 1


class LedgerStorageError(RuntimeError):
    """Security Ledger storage configuration or persistence is unsafe."""


@dataclass(frozen=True, slots=True)
class LedgerStorageSettings:
    db_path: Path
    hmac_key_path: Path
    service_uid: int
    service_gid: int
    busy_timeout_ms: int = 2000

    def __post_init__(self) -> None:
        db_path = _validate_absolute_canonical_path(
            Path(self.db_path),
            "database",
        )
        key_path = _validate_absolute_canonical_path(
            Path(self.hmac_key_path),
            "HMAC key",
        )
        object.__setattr__(self, "db_path", db_path)
        object.__setattr__(self, "hmac_key_path", key_path)
        _validate_kernel_id(self.service_uid, "service_uid")
        _validate_kernel_id(self.service_gid, "service_gid")
        if (
            isinstance(self.busy_timeout_ms, bool)
            or not isinstance(self.busy_timeout_ms, int)
            or not 1 <= self.busy_timeout_ms <= _MAX_BUSY_TIMEOUT_MS
        ):
            raise ValueError(
                "busy_timeout_ms must be an integer in [1, 60000]"
            )


def _validate_absolute_canonical_path(path: Path, label: str) -> Path:
    raw = os.fspath(path)
    if "\x00" in raw:
        raise ValueError(f"{label} path must not contain NUL")
    if not path.is_absolute() or raw.startswith("//"):
        raise ValueError(f"{label} path must be absolute")
    if os.path.normpath(raw) != raw:
        raise ValueError(f"{label} path must be lexically canonical")
    if path.name in {"", ".", ".."}:
        raise ValueError(f"{label} path must include a filename")
    return path


def _validate_kernel_id(value: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_KERNEL_ID
    ):
        raise ValueError(f"{label} must be a valid Linux uid/gid value")


def _validate_parent(
    path: Path,
    *,
    service_uid: int,
    service_gid: int,
) -> None:
    parent = path.parent
    try:
        resolved = parent.resolve(strict=True)
        info = parent.lstat()
    except OSError:
        raise LedgerStorageError(
            "Security Ledger parent directory is unsafe"
        ) from None

    if resolved != parent or not stat.S_ISDIR(info.st_mode):
        raise LedgerStorageError(
            "Security Ledger parent directory is unsafe"
        )
    if info.st_uid != service_uid or info.st_gid != service_gid:
        raise LedgerStorageError(
            "Security Ledger parent directory is unsafe"
        )
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise LedgerStorageError(
            "Security Ledger parent directory is unsafe"
        )

    current = parent.parent
    while True:
        try:
            ancestor = current.lstat()
        except OSError:
            raise LedgerStorageError(
                "Security Ledger parent directory is unsafe"
            ) from None
        if not stat.S_ISDIR(ancestor.st_mode):
            raise LedgerStorageError(
                "Security Ledger parent directory is unsafe"
            )
        if ancestor.st_uid not in {0, service_uid}:
            raise LedgerStorageError(
                "Security Ledger parent directory is unsafe"
            )
        writable = ancestor.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky = ancestor.st_mode & stat.S_ISVTX
        if writable and not sticky:
            raise LedgerStorageError(
                "Security Ledger parent directory is unsafe"
            )
        if current == current.parent:
            return
        current = current.parent


def _secure_file_info(
    path: Path,
    *,
    uid: int,
    gid: int,
    allowed_modes: frozenset[int],
    error_message: str,
) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise LedgerStorageError(error_message) from None
    if not stat.S_ISREG(info.st_mode):
        raise LedgerStorageError(error_message)
    if info.st_uid != uid or info.st_gid != gid:
        raise LedgerStorageError(error_message)
    if stat.S_IMODE(info.st_mode) not in allowed_modes:
        raise LedgerStorageError(error_message)
    return info


def load_ledger_hmac_key(settings: LedgerStorageSettings) -> bytes:
    _validate_parent(
        settings.hmac_key_path,
        service_uid=settings.service_uid,
        service_gid=settings.service_gid,
    )
    before = _secure_file_info(
        settings.hmac_key_path,
        uid=settings.service_uid,
        gid=settings.service_gid,
        allowed_modes=_ALLOWED_KEY_MODES,
        error_message="Security Ledger key file is unsafe",
    )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(settings.hmac_key_path, flags)
    except OSError:
        raise LedgerStorageError(
            "Security Ledger key file is unsafe"
        ) from None

    try:
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_uid != settings.service_uid
            or after.st_gid != settings.service_gid
            or stat.S_IMODE(after.st_mode) not in _ALLOWED_KEY_MODES
        ):
            raise LedgerStorageError(
                "Security Ledger key file is unsafe"
            )
        key = os.read(fd, _KEY_BYTES + 1)
    except OSError:
        raise LedgerStorageError(
            "Security Ledger key file is unsafe"
        ) from None
    finally:
        os.close(fd)

    if len(key) != _KEY_BYTES:
        raise LedgerStorageError(
            "Security Ledger HMAC key must contain exactly 32 bytes"
        )
    return key


def _prepare_database_file(settings: LedgerStorageSettings) -> None:
    _validate_parent(
        settings.db_path,
        service_uid=settings.service_uid,
        service_gid=settings.service_gid,
    )
    try:
        settings.db_path.lstat()
    except FileNotFoundError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(
                settings.db_path,
                flags,
                _DATABASE_MODE,
            )
        except OSError:
            raise LedgerStorageError(
                "Security Ledger database file is unsafe"
            ) from None
        else:
            os.close(fd)
    except OSError:
        raise LedgerStorageError(
            "Security Ledger database file is unsafe"
        ) from None

    _secure_file_info(
        settings.db_path,
        uid=settings.service_uid,
        gid=settings.service_gid,
        allowed_modes=frozenset({_DATABASE_MODE}),
        error_message="Security Ledger database file is unsafe",
    )


_SCHEMA_SQL = """
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    binding_hmac TEXT NOT NULL,
    active_binding_hmac TEXT UNIQUE,
    binding_version INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    host TEXT NOT NULL,
    tool TEXT NOT NULL,
    privilege TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    risk TEXT NOT NULL,
    state TEXT NOT NULL,
    safe_summary_json TEXT NOT NULL,
    binding_fingerprint TEXT NOT NULL,
    first_request_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    consumed_at TEXT,
    operator_identity TEXT
);

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    host TEXT,
    tool TEXT,
    policy_version TEXT,
    decision TEXT,
    risk TEXT,
    approval_id TEXT,
    safe_summary_json TEXT,
    exit_status INTEGER,
    exit_signal TEXT,
    duration_ms INTEGER,
    stdout_bytes INTEGER,
    stderr_bytes INTEGER,
    timed_out INTEGER,
    truncated INTEGER
);
"""


def _user_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _initialize_or_validate_schema(
    connection: sqlite3.Connection,
    *,
    key_id: str,
) -> None:
    existing = _user_tables(connection)
    if not existing:
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executescript(_SCHEMA_SQL)
            connection.executemany(
                "INSERT INTO meta(key, value) VALUES (?, ?)",
                (
                    ("schema_version", _SCHEMA_VERSION),
                    ("hmac_key_id", key_id),
                ),
            )
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise LedgerStorageError(
                "cannot initialize Security Ledger schema"
            ) from None
        return

    required = {"meta", "approvals", "audit_events"}
    if not required.issubset(existing):
        raise LedgerStorageError(
            "Security Ledger schema version is unsupported"
        )
    try:
        meta = dict(connection.execute("SELECT key, value FROM meta"))
    except sqlite3.Error:
        raise LedgerStorageError(
            "Security Ledger schema version is unsupported"
        ) from None

    if meta.get("schema_version") != _SCHEMA_VERSION:
        raise LedgerStorageError(
            "Security Ledger schema version is unsupported"
        )
    stored_key_id = meta.get("hmac_key_id")
    if (
        not isinstance(stored_key_id, str)
        or not hmac.compare_digest(stored_key_id, key_id)
    ):
        raise LedgerStorageError(
            "Security Ledger HMAC key does not match database"
        )


class LedgerDatabase:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._closed = False

    @classmethod
    def open(cls, settings: LedgerStorageSettings) -> Self:
        key = load_ledger_hmac_key(settings)
        _prepare_database_file(settings)
        try:
            connection = sqlite3.connect(
                settings.db_path,
                isolation_level=None,
                timeout=settings.busy_timeout_ms / 1000,
                check_same_thread=False,
            )
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                f"PRAGMA busy_timeout={settings.busy_timeout_ms}"
            )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            _initialize_or_validate_schema(
                connection,
                key_id=hashlib.sha256(key).hexdigest(),
            )
        except LedgerStorageError:
            try:
                connection.close()
            except UnboundLocalError:
                pass
            raise
        except sqlite3.Error:
            try:
                connection.close()
            except UnboundLocalError:
                pass
            raise LedgerStorageError(
                "cannot open Security Ledger database"
            ) from None
        return cls(connection)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._closed:
            raise LedgerStorageError(
                "Security Ledger database is closed"
            )
        return self._connection

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
