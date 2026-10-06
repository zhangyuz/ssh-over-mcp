"""Shared descriptor-only HMAC key writer using only the standard library."""

from __future__ import annotations

import os
import secrets
import stat


class KeyFileError(RuntimeError):
    """Writing or validating the new key failed."""


def write_hmac_key(fd: int, *, uid: int, gid: int, mode: int) -> None:
    """Write and sync a fresh, exclusively created regular-file descriptor.

    The caller validates the canonical parent, creates and closes the descriptor,
    establishes a secure creation mode, and syncs the parent directory as needed.
    Existing keys must be validated separately, never passed here for repair.
    """
    try:
        view = memoryview(secrets.token_bytes(32))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size != 32
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode
        ):
            raise OSError("invalid key metadata")
        os.fsync(fd)
    except OSError:
        raise KeyFileError("Security Ledger key write failed") from None
