#!/usr/bin/env python3
"""Synthetic-only Ed25519 proof, never B0 source approval."""
import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

PREFIX = b'SOM-B0A-SYNTHETIC-V1\x00'
OPENSSL = '/usr/bin/openssl'


def read_bounded(path, limit):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('invalid input type or size')
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_ino, before.st_mtime_ns) != (after.st_ino, after.st_mtime_ns):
            raise ValueError('input changed')
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('payload', 'signature', 'public-key'):
        parser.add_argument('--' + field, required=True)
    args = parser.parse_args()
    try:
        if sys.platform != 'linux' or not Path(OPENSSL).is_file():
            raise ValueError('fixed Linux verifier unavailable')
        payload = read_bounded(args.payload, 4096)
        signature = read_bounded(args.signature, 64)
        public_key = read_bounded(args.public_key, 512)
        if not payload.startswith(PREFIX) or len(signature) != 64:
            raise ValueError('synthetic format invalid')
        # The public key is supplied by the test: mathematical proof ONLY.
        # Private temporary copies prevent reopening the caller's mutable files.
        with tempfile.TemporaryDirectory(prefix='som-b0a-synthetic-') as directory:
            paths = [Path(directory) / name for name in ('payload', 'signature', 'public.pem')]
            for path, data in zip(paths, (payload, signature, public_key), strict=True):
                path.write_bytes(data)
            result = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(paths[2]), '-sigfile', str(paths[1]), '-in', str(paths[0])], capture_output=True, timeout=4, check=False)
            if result.returncode != 0:
                raise ValueError('signature invalid')
        print(json.dumps({'status': 'SYNTHETIC_ONLY', 'source_approved': False, 'signature_verified_test_only': True}, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f'B0A_SYNTHETIC_REFUSED: {type(exc).__name__}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
