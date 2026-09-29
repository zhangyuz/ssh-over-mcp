from __future__ import annotations

import errno
import hashlib
import os

_HASH_CHUNK_BYTES = 64 * 1024


def sha256_fd(fd: int, *, expected_size: int) -> str:
    """Hash exactly expected_size bytes from fd without changing its offset."""
    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
        raise ValueError("expected_size must be a nonnegative integer")
    if not hasattr(os, "pread"):
        raise OSError(errno.ENOSYS, "pread is unavailable")

    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(fd, min(_HASH_CHUNK_BYTES, expected_size - offset), offset)
        if not chunk:
            raise OSError(errno.EIO, "executable changed while hashing")
        digest.update(chunk)
        offset += len(chunk)

    if os.pread(fd, 1, expected_size):
        raise OSError(errno.EIO, "executable changed while hashing")

    return digest.hexdigest()
