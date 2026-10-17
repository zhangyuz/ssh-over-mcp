#!/usr/bin/env python3
"""Offline, non-authorizing B0 policy completeness preflight."""
import argparse
import json
from pathlib import Path

FIELDS = ('artifact_name', 'artifact_sha256', 'artifact_size', 'signer_identity',
          'oidc_issuer', 'fulcio_roots_sha256', 'rekor_log_ids',
          'trust_config_sha256', 'max_root_age_seconds', 'max_clock_skew_seconds',
          'revocation_rule', 'trusted_clock', 'verifier_sha256',
          'verifier_version', 'handoff_mode', 'policy_revision')

def preflight(data):
    if not isinstance(data, dict):
        return ('B0_POLICY_INCOMPLETE', ['policy_object'])
    missing = [k for k in FIELDS if k not in data or data[k] in (None, '', [], {})]
    # Never turn a document completeness check into source authorization.
    return ('B0_POLICY_INCOMPLETE' if missing else 'B0_POLICY_CANDIDATE_ONLY', missing)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('policy', type=Path)
    args = p.parse_args()
    try:
        data = json.loads(args.policy.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print(f'B0_POLICY_REFUSED: {type(exc).__name__}')
        return 2
    status, missing = preflight(data)
    print(json.dumps({'status': status, 'missing_fields': missing}, sort_keys=True))
    return 2 if missing else 0

if __name__ == '__main__':
    raise SystemExit(main())
