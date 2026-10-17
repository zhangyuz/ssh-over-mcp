#!/usr/bin/env python3
"""Offline, non-authorizing B0 policy completeness preflight."""
import argparse
import json
import os
import re
import stat
from pathlib import Path

FIELDS = ('artifact_name', 'artifact_sha256', 'artifact_size', 'signer_identity',
          'oidc_issuer', 'fulcio_roots_sha256', 'rekor_log_ids',
          'trust_config_sha256', 'max_root_age_seconds', 'max_clock_skew_seconds',
          'revocation_rule', 'trusted_clock', 'verifier_sha256',
          'verifier_version', 'handoff_mode', 'policy_revision')

def preflight(data):
    if not isinstance(data, dict):
        return ('B0_POLICY_INCOMPLETE', ['policy_object'])
    placeholders = {'UNVERIFIED', 'PENDING', 'TODO', 'TBD', 'UNKNOWN', 'PLACEHOLDER'}
    digest_fields = {'artifact_sha256', 'trust_config_sha256', 'verifier_sha256'}
    positive_fields = {'artifact_size', 'max_root_age_seconds'}
    nonnegative_fields = {'max_clock_skew_seconds'}

    def valid(key, value):
        if value is None or value == '' or value == [] or value == {}:
            return False
        if isinstance(value, str) and value.strip().upper() in placeholders:
            return False
        if key in digest_fields:
            return isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{64}', value) is not None
        if key == 'fulcio_roots_sha256':
            return isinstance(value, list) and bool(value) and all(
                isinstance(v, str) and re.fullmatch(r'[0-9a-fA-F]{64}', v) for v in value
            )
        if key == 'rekor_log_ids':
            return isinstance(value, list) and bool(value) and all(
                isinstance(v, str) and v.strip() and v.strip().upper() not in placeholders
                for v in value
            )
        if key in positive_fields | nonnegative_fields:
            return type(value) is int and value >= (0 if key in nonnegative_fields else 1)
        if key == 'handoff_mode':
            return value in ('direct-sealed-FD', 'digest-from-sealed-bytes')
        return isinstance(value, str) and bool(value.strip())

    missing = [k for k in FIELDS if k not in data or not valid(k, data[k])]
    # Never turn a document completeness check into source authorization.
    return ('B0_POLICY_INCOMPLETE' if missing else 'B0_POLICY_CANDIDATE_ONLY', missing)

MAX_POLICY_BYTES = 65536
MAX_JSON_DEPTH = 32


def read_policy(path):
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES:
            raise ValueError('not a bounded regular file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES:
            raise ValueError('oversized input')
        obj = json.loads(raw)
        def check_depth(node, depth=0):
            if depth > MAX_JSON_DEPTH:
                raise ValueError('JSON nesting exceeds bound')
            if isinstance(node, dict):
                for value in node.values():
                    check_depth(value, depth + 1)
            elif isinstance(node, list):
                for value in node:
                    check_depth(value, depth + 1)
        check_depth(obj)
        return obj
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('policy', type=Path)
    args = p.parse_args()
    try:
        data = read_policy(args.policy)
    except (OSError, ValueError, RecursionError) as exc:
        print(f'B0_POLICY_REFUSED: {type(exc).__name__}')
        return 2
    status, missing = preflight(data)
    print(json.dumps({'status': status, 'missing_fields': missing}, sort_keys=True))
    return 2 if missing else 0

if __name__ == '__main__':
    raise SystemExit(main())
