"""Read-only, nonce-bound attestation of a v5 host's running state (ADR0028).

Run by the operator inside the running node container, e.g.
``python -m ssh_over_mcp.host_agent.attest_v5 --policy PATH --nonce HEX``.
Nothing here is reachable over SSH, opens a socket, reads stdin or writes a
file; it prints one JSON line and never any key material.

The proof is HMAC-SHA256 under the host's own verifier key over a fixed set of
fields plus the controller's fresh nonce. The central authority computes the
same proof from the key it holds, so the controller can require the two to be
EQUAL without ever seeing a key: equal proofs under a new nonce can only come
from two parties holding the same key bytes. A key ID alone would not do, since
it is public and could simply be echoed.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from .visibility_runtime_v5 import (
    VisibilityRuntimeError,
    load_host_visibility_runtime,
    load_trusted_visibility_key,
)
from .visibility_snapshot_v5 import visibility_key_id

ATTEST_DOMAIN = b"ssh-over-mcp/v5/attestation/v1\x00"
ATTEST_VERSION = 1
_NONCE = re.compile(r"^[0-9a-f]{32}$")

EX_OK = 0
EX_USAGE = 64
EX_UNAVAILABLE = 69


def require_nonce(nonce: object) -> str:
    if type(nonce) is not str or _NONCE.fullmatch(nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hex characters")
    return nonce


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def attestation_proof(key: bytes, fields: Mapping[str, object]) -> str:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("v5 HMAC key must be exactly 32 bytes")
    return hmac.new(key, ATTEST_DOMAIN + _canonical(dict(fields)), hashlib.sha256).hexdigest()


def attestation_fields(
    *,
    host: str,
    host_key_sha256: str,
    profile: str,
    policy_epoch: int,
    central_policy_sha256: str,
    key: bytes,
    nonce: str,
) -> dict[str, object]:
    """The exact field set both sides must agree on; the key ID is derived here."""

    return {
        "version": ATTEST_VERSION,
        "host": host,
        "host_key_sha256": host_key_sha256,
        "profile": profile,
        "policy_epoch": policy_epoch,
        "central_policy_sha256": central_policy_sha256,
        "verifier_key_id": visibility_key_id(key),
        "nonce": require_nonce(nonce),
    }


def attest_host_state(policy_path: Path | str, nonce: str) -> dict[str, object]:
    """Report this host's state, read only through the protected loaders."""

    require_nonce(nonce)
    config = load_host_visibility_runtime(policy_path)
    key = load_trusted_visibility_key(config.signer_key_path)
    fields = attestation_fields(
        host=config.host,
        host_key_sha256=config.host_key_sha256,
        profile=config.visibility.profile,
        policy_epoch=config.visibility.policy_epoch,
        central_policy_sha256=config.visibility.central_policy_sha256,
        key=key,
        nonce=nonce,
    )
    return {
        **fields,
        # Not part of the proof: the central side cannot know the host's file.
        "config_sha256": hashlib.sha256(_canonical(config.model_dump(mode="json"))).hexdigest(),
        "proof": attestation_proof(key, fields),
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        # Never echo untrusted argv back.
        raise ValueError("usage")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = _Parser(prog="attest_v5", add_help=False)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--nonce", required=True)
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
        require_nonce(args.nonce)
    except (ValueError, SystemExit):
        print("attest_v5: invalid arguments", file=err)
        return EX_USAGE
    try:
        report = attest_host_state(args.policy, args.nonce)
    except (VisibilityRuntimeError, ValueError, OSError):
        print("attest_v5: trusted state unavailable", file=err)
        return EX_UNAVAILABLE
    out.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return EX_OK


if __name__ == "__main__":
    sys.exit(main())
