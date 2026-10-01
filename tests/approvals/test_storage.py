from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
import sqlite3
import stat
import traceback
from pathlib import Path

import pytest


def _storage():
    spec = importlib.util.find_spec("ssh_over_mcp.approvals.storage")
    assert spec is not None, "Security Ledger storage module is not implemented"
    return importlib.import_module("ssh_over_mcp.approvals.storage")


def _secure_paths(tmp_path: Path, *, key: bytes = b"k" * 32):
    data_dir = tmp_path / "ledger"
    data_dir.mkdir(mode=0o700)
    os.chmod(data_dir, 0o700)
    key_path = data_dir / "ledger.key"
    key_path.write_bytes(key)
    os.chmod(key_path, 0o600)
    db_path = data_dir / "ledger.db"
    return data_dir, db_path, key_path


def _settings(tmp_path: Path, *, key: bytes = b"k" * 32):
    storage = _storage()
    data_dir, db_path, key_path = _secure_paths(tmp_path, key=key)
    parent = data_dir.lstat()
    return storage.LedgerStorageSettings(
        db_path=db_path,
        hmac_key_path=key_path,
        service_uid=parent.st_uid,
        service_gid=parent.st_gid,
        busy_timeout_ms=1375,
    )


def test_storage_settings_require_absolute_canonical_paths(tmp_path: Path) -> None:
    storage = _storage()
    _data_dir, db_path, key_path = _secure_paths(tmp_path)

    with pytest.raises(ValueError, match="absolute"):
        storage.LedgerStorageSettings(
            db_path=Path("ledger.db"),
            hmac_key_path=key_path,
            service_uid=os.getuid(),
            service_gid=os.getgid(),
        )

    noncanonical = db_path.parent / ".." / db_path.parent.name / db_path.name
    with pytest.raises(ValueError, match="canonical"):
        storage.LedgerStorageSettings(
            db_path=noncanonical,
            hmac_key_path=key_path,
            service_uid=os.getuid(),
            service_gid=os.getgid(),
        )


def test_load_hmac_key_requires_secure_regular_exact_32_bytes(
    tmp_path: Path,
) -> None:
    storage = _storage()
    settings = _settings(tmp_path, key=b"S" * 32)

    assert storage.load_ledger_hmac_key(settings) == b"S" * 32

    settings.hmac_key_path.write_bytes(b"SUPERSECRET-short")
    os.chmod(settings.hmac_key_path, 0o600)
    try:
        storage.load_ledger_hmac_key(settings)
    except storage.LedgerStorageError as exc:
        rendered = traceback.format_exc()
        assert "SUPERSECRET" not in str(exc)
        assert "SUPERSECRET" not in rendered
        assert str(settings.hmac_key_path) not in str(exc)
    else:
        raise AssertionError("short key must fail closed")

    settings.hmac_key_path.write_bytes(b"K" * 32)
    os.chmod(settings.hmac_key_path, 0o644)
    with pytest.raises(storage.LedgerStorageError, match="key file is unsafe"):
        storage.load_ledger_hmac_key(settings)


def test_database_rejects_unsafe_parent_and_symlink(tmp_path: Path) -> None:
    storage = _storage()
    settings = _settings(tmp_path)

    os.chmod(settings.db_path.parent, 0o770)
    with pytest.raises(storage.LedgerStorageError, match="parent directory is unsafe"):
        storage.LedgerDatabase.open(settings)

    os.chmod(settings.db_path.parent, 0o700)
    target = settings.db_path.parent / "target.db"
    target.write_bytes(b"")
    os.chmod(target, 0o600)
    settings.db_path.symlink_to(target)
    with pytest.raises(storage.LedgerStorageError, match="database file is unsafe"):
        storage.LedgerDatabase.open(settings)


def test_database_rejects_wrong_service_identity(tmp_path: Path) -> None:
    storage = _storage()
    _data_dir, db_path, key_path = _secure_paths(tmp_path)

    settings = storage.LedgerStorageSettings(
        db_path=db_path,
        hmac_key_path=key_path,
        service_uid=os.getuid() + 1,
        service_gid=os.getgid(),
    )
    with pytest.raises(storage.LedgerStorageError, match="parent directory is unsafe"):
        storage.LedgerDatabase.open(settings)


def test_database_creates_secure_schema_and_pragmas(tmp_path: Path) -> None:
    storage = _storage()
    settings = _settings(tmp_path, key=b"A" * 32)

    database = storage.LedgerDatabase.open(settings)
    try:
        assert stat.S_IMODE(settings.db_path.lstat().st_mode) == 0o600

        pragmas = {
            "journal_mode": database.connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0],
            "synchronous": database.connection.execute(
                "PRAGMA synchronous"
            ).fetchone()[0],
            "foreign_keys": database.connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0],
            "busy_timeout": database.connection.execute(
                "PRAGMA busy_timeout"
            ).fetchone()[0],
        }
        assert str(pragmas["journal_mode"]).lower() == "wal"
        assert pragmas["synchronous"] == 2
        assert pragmas["foreign_keys"] == 1
        assert pragmas["busy_timeout"] == 1375

        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"meta", "approvals", "audit_events"}.issubset(tables)

        meta = dict(database.connection.execute("SELECT key, value FROM meta"))
        assert meta["schema_version"] == "1"
        assert meta["hmac_key_id"] == hashlib.sha256(b"A" * 32).hexdigest()
    finally:
        database.close()


def test_existing_database_must_be_regular_owned_mode_0600(
    tmp_path: Path,
) -> None:
    storage = _storage()
    settings = _settings(tmp_path)
    settings.db_path.write_bytes(b"not sqlite")
    os.chmod(settings.db_path, 0o644)

    with pytest.raises(storage.LedgerStorageError, match="database file is unsafe"):
        storage.LedgerDatabase.open(settings)


def test_reopen_rejects_unknown_schema_version(tmp_path: Path) -> None:
    storage = _storage()
    settings = _settings(tmp_path)

    database = storage.LedgerDatabase.open(settings)
    database.close()

    raw = sqlite3.connect(settings.db_path)
    raw.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
    raw.commit()
    raw.close()

    with pytest.raises(storage.LedgerStorageError, match="schema version is unsupported"):
        storage.LedgerDatabase.open(settings)


def test_reopen_rejects_hmac_key_mismatch(tmp_path: Path) -> None:
    storage = _storage()
    settings = _settings(tmp_path, key=b"A" * 32)

    database = storage.LedgerDatabase.open(settings)
    database.close()

    settings.hmac_key_path.write_bytes(b"B" * 32)
    os.chmod(settings.hmac_key_path, 0o600)

    with pytest.raises(storage.LedgerStorageError, match="HMAC key does not match"):
        storage.LedgerDatabase.open(settings)
