from __future__ import annotations

import os
import secrets
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from .runtime import SecurityLedgerRuntimeSettings
from .storage import LedgerStorageError, load_ledger_hmac_key


class LedgerBootstrapError(RuntimeError):
    """Security Ledger bootstrap state is unsafe."""


def _bootstrap_error() -> LedgerBootstrapError:
    return LedgerBootstrapError("Security Ledger bootstrap failed")


def _require_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError:
        raise _bootstrap_error() from None
    if (
        resolved != path
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise _bootstrap_error()


def _prepare_directory(path: Path, *, uid: int, gid: int) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
            os.chown(path, uid, gid, follow_symlinks=False)
            os.chmod(path, 0o700, follow_symlinks=False)
        except OSError:
            raise _bootstrap_error() from None
    except OSError:
        raise _bootstrap_error() from None
    _require_directory(path, uid=uid, gid=gid)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _create_hmac_key(path: Path, *, uid: int, gid: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    except OSError:
        raise _bootstrap_error() from None

    try:
        _write_all(fd, secrets.token_bytes(32))
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except OSError:
        raise _bootstrap_error() from None
    finally:
        os.close(fd)


def prepare_ledger_runtime(settings: SecurityLedgerRuntimeSettings) -> None:
    storage = settings.storage_settings()
    data_dir = storage.db_path.parent
    if storage.hmac_key_path.parent != data_dir:
        raise _bootstrap_error()

    execution_dir = settings.execution_socket_path.parent
    admin_dir = settings.admin_socket_path.parent
    if len({data_dir, execution_dir, admin_dir}) != 3:
        raise _bootstrap_error()

    _prepare_directory(
        data_dir,
        uid=settings.service_uid,
        gid=settings.service_gid,
    )
    _prepare_directory(
        execution_dir,
        uid=settings.service_uid,
        gid=settings.execution_socket_gid,
    )
    _prepare_directory(
        admin_dir,
        uid=settings.service_uid,
        gid=settings.admin_socket_gid,
    )

    _create_hmac_key(
        storage.hmac_key_path,
        uid=settings.service_uid,
        gid=settings.service_gid,
    )
    try:
        load_ledger_hmac_key(storage)
    except LedgerStorageError:
        raise _bootstrap_error() from None


def run(
    env: Mapping[str, str] | None = None,
    *,
    stderr: TextIO | None = None,
) -> int:
    errors = sys.stderr if stderr is None else stderr
    try:
        settings = SecurityLedgerRuntimeSettings.from_env(env)
        prepare_ledger_runtime(settings)
    except (LedgerBootstrapError, ValueError):
        errors.write("Security Ledger bootstrap failed\n")
        return 1
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
