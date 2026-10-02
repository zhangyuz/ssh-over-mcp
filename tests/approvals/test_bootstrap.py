from __future__ import annotations

import os
import stat
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

from ssh_over_mcp.approvals.bootstrap import (
    LedgerBootstrapError,
    prepare_ledger_runtime,
    run,
)
from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings


def _settings(tmp_path: Path) -> SecurityLedgerRuntimeSettings:
    uid = os.getuid()
    gid = os.getgid()
    return SecurityLedgerRuntimeSettings(
        db_path=tmp_path / "data" / "ledger" / "ledger.db",
        hmac_key_path=tmp_path / "data" / "ledger" / "ledger.key",
        service_uid=uid,
        service_gid=gid,
        execution_socket_path=tmp_path / "exec" / "ledger" / "ledger.sock",
        execution_socket_gid=gid,
        execution_socket_mode=0o660,
        execution_peer_uid=uid,
        execution_peer_gid=gid,
        admin_socket_path=tmp_path / "admin" / "ledger" / "ledger.sock",
        admin_socket_gid=gid,
        admin_socket_mode=0o660,
        admin_peer_uid=uid,
        admin_peer_gid=gid,
    )


def _prepare_mount_roots(tmp_path: Path) -> None:
    for name in ("data", "exec", "admin"):
        (tmp_path / name).mkdir(mode=0o755)


def test_first_initialization_creates_only_trusted_children_and_key(
    tmp_path: Path,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)

    prepare_ledger_runtime(settings)

    for child in (
        settings.db_path.parent,
        settings.execution_socket_path.parent,
        settings.admin_socket_path.parent,
    ):
        info = child.lstat()
        assert stat.S_ISDIR(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o700
        assert info.st_uid == settings.service_uid

    key_info = settings.hmac_key_path.lstat()
    assert stat.S_ISREG(key_info.st_mode)
    assert stat.S_IMODE(key_info.st_mode) == 0o600
    assert key_info.st_uid == settings.service_uid
    assert key_info.st_gid == settings.service_gid
    assert len(settings.hmac_key_path.read_bytes()) == 32

    assert not settings.db_path.exists()
    assert not settings.execution_socket_path.exists()
    assert not settings.admin_socket_path.exists()


def test_second_initialization_preserves_key_and_existing_database(
    tmp_path: Path,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    prepare_ledger_runtime(settings)
    key_before = settings.hmac_key_path.read_bytes()
    settings.db_path.write_bytes(b"DATABASE_SENTINEL")
    os.chmod(settings.db_path, 0o600)

    prepare_ledger_runtime(settings)

    assert settings.hmac_key_path.read_bytes() == key_before
    assert settings.db_path.read_bytes() == b"DATABASE_SENTINEL"


@pytest.mark.parametrize(
    ("mutation", "expected_mode"),
    [
        ("key-short", 0o600),
        ("key-mode", 0o644),
        ("data-mode", 0o750),
        ("exec-mode", 0o750),
        ("admin-mode", 0o750),
    ],
)
def test_existing_unsafe_state_fails_without_repair(
    tmp_path: Path,
    mutation: str,
    expected_mode: int,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    prepare_ledger_runtime(settings)

    target = settings.hmac_key_path
    if mutation == "key-short":
        target.write_bytes(b"BAD")
        os.chmod(target, 0o600)
    elif mutation == "key-mode":
        os.chmod(target, expected_mode)
    else:
        target = {
            "data-mode": settings.db_path.parent,
            "exec-mode": settings.execution_socket_path.parent,
            "admin-mode": settings.admin_socket_path.parent,
        }[mutation]
        os.chmod(target, expected_mode)

    before = target.lstat()
    before_bytes = target.read_bytes() if target.is_file() else None

    with pytest.raises(LedgerBootstrapError):
        prepare_ledger_runtime(settings)

    after = target.lstat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert after.st_uid == before.st_uid
    assert after.st_gid == before.st_gid
    if before_bytes is not None:
        assert target.read_bytes() == before_bytes


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_existing_non_directory_child_fails_without_replacement(
    tmp_path: Path,
    kind: str,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    child = settings.execution_socket_path.parent
    if kind == "file":
        child.write_bytes(b"NOT_A_DIRECTORY")
    else:
        target = tmp_path / "symlink-target"
        target.mkdir()
        child.symlink_to(target, target_is_directory=True)

    with pytest.raises(LedgerBootstrapError):
        prepare_ledger_runtime(settings)

    if kind == "file":
        assert child.is_file()
        assert child.read_bytes() == b"NOT_A_DIRECTORY"
    else:
        assert child.is_symlink()


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_existing_non_regular_hmac_key_fails_without_replacement(
    tmp_path: Path,
    kind: str,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    for child in (
        settings.db_path.parent,
        settings.execution_socket_path.parent,
        settings.admin_socket_path.parent,
    ):
        child.mkdir(mode=0o700)
    key = settings.hmac_key_path
    if kind == "symlink":
        target = tmp_path / "key-target"
        target.write_bytes(b"K" * 32)
        key.symlink_to(target)
    else:
        os.mkfifo(key)

    with pytest.raises(LedgerBootstrapError):
        prepare_ledger_runtime(settings)

    if kind == "symlink":
        assert key.is_symlink()
    else:
        assert stat.S_ISFIFO(key.lstat().st_mode)


def _env(settings: SecurityLedgerRuntimeSettings) -> dict[str, str]:
    return {
        "SSH_OVER_MCP_LEDGER_DB_PATH": str(settings.db_path),
        "SSH_OVER_MCP_LEDGER_HMAC_KEY_PATH": str(settings.hmac_key_path),
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": str(settings.service_uid),
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": str(settings.service_gid),
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": str(settings.execution_socket_path),
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_GID": str(settings.execution_socket_gid),
        "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_MODE": "0660",
        "SSH_OVER_MCP_LEDGER_EXEC_PEER_UID": str(settings.execution_peer_uid),
        "SSH_OVER_MCP_LEDGER_EXEC_PEER_GID": str(settings.execution_peer_gid),
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": str(settings.admin_socket_path),
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_GID": str(settings.admin_socket_gid),
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_MODE": "0660",
        "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID": str(settings.admin_peer_uid),
        "SSH_OVER_MCP_LEDGER_ADMIN_PEER_GID": str(settings.admin_peer_gid),
    }


def test_run_hides_invalid_key_content_behind_stable_error(
    tmp_path: Path,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    prepare_ledger_runtime(settings)
    secret_marker = b"SUPERSECRET_BOOTSTRAP_MARKER"
    settings.hmac_key_path.write_bytes(secret_marker)
    os.chmod(settings.hmac_key_path, 0o600)
    stderr = StringIO()

    result = run(_env(settings), stderr=stderr)

    assert result == 1
    assert stderr.getvalue() == "Security Ledger bootstrap failed\n"
    assert secret_marker.decode() not in stderr.getvalue()


def test_bootstrap_rejects_database_and_key_in_different_parents(
    tmp_path: Path,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    settings = replace(
        settings,
        hmac_key_path=tmp_path / "other-data" / "ledger.key",
    )
    (tmp_path / "other-data").mkdir()

    with pytest.raises(LedgerBootstrapError):
        prepare_ledger_runtime(settings)


def test_bootstrap_rejects_overlapping_runtime_directories(
    tmp_path: Path,
) -> None:
    _prepare_mount_roots(tmp_path)
    settings = _settings(tmp_path)
    settings = replace(
        settings,
        admin_socket_path=settings.execution_socket_path.parent / "admin.sock",
    )

    with pytest.raises(LedgerBootstrapError):
        prepare_ledger_runtime(settings)
