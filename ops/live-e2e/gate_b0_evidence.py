"""Bounded non-authorizing B0a synthetic CLI refusal records."""
from __future__ import annotations

import json

_REASONS = frozenset({
    "CLI_ARGS_REJECTED",
    "FIXTURE_NOT_APPROVED",
    "T5_POLICY_UNAPPROVED",
    "SEALED_SNAPSHOT_REFUSED",
})


def format_refusal(reason_code: str) -> bytes:
    """No claimed digest, signer, approval or host authority on refusal."""
    if type(reason_code) is not str or reason_code not in _REASONS:
        reason_code = "CLI_ARGS_REJECTED"
    record = {
        "schema": "som.b0a.synthetic.v1",
        "status": "B0A_REFUSED",
        "reason_code": reason_code,
        "evidence_class": "NON_AUTHORIZING_SYNTHETIC",
    }
    result = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert len(result) < 16384
    return result + b"\n"
