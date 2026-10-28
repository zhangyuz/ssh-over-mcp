"""Independent, disabled-by-default SMCP v2 Host Agent candidate.

No live launcher, packaging script, or ForceCommand currently references this.
Authentication and trust material are strictly host-local, and a future
deployment must supply a separate, reviewed epoch/revocation ACK protocol.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from ssh_over_mcp.ssh.protocol_v2 import (
    ProtocolV2Error,
    read_request_v2,
    validate_force_command_v2,
)

from .cli import OutputDeliveryError, _deliver_execution_output
from .filesystem import FilesystemAccessError
from .visibility_listing_candidate import list_verified_directory_candidate
from .visibility_runtime_v5 import (
    PersistentSnapshotNonces,
    VisibilityRuntimeError,
    load_host_visibility_runtime,
    load_trusted_visibility_key,
)
from .visibility_snapshot_v5 import (
    SnapshotBinding,
    SnapshotVerificationError,
    verify_snapshot,
)

EX_SUCCESS_V2 = 0
EX_PROTOCOL_V2 = 65
EX_UNAVAILABLE_V2 = 69
EX_DENIED_V2 = 77
DEFAULT_POLICY_V2 = Path("/etc/ssh-over-mcp/v5/host-visibility.json")


def run_v2(
    *,
    env: Mapping[str, str],
    stdin: BinaryIO,
    stdout: BinaryIO,
    stderr: TextIO,
    execution_stderr: BinaryIO,
    policy_path: Path = DEFAULT_POLICY_V2,
    now: Callable[[], int] = lambda: int(time.time()),
) -> int:
    """Process one bounded request, refusing all untrusted or stale state."""

    try:
        validate_force_command_v2(env)
        request = read_request_v2(stdin)
    except ProtocolV2Error:
        print("ssh-over-mcp-host-agent-v2: invalid request", file=stderr)
        return EX_PROTOCOL_V2

    try:
        config = load_host_visibility_runtime(policy_path)
        key = load_trusted_visibility_key(config.signer_key_path)
        snap = request.signed_snapshot.payload
        expected = SnapshotBinding(
            request_id=request.request_id,
            host=config.host,
            host_key_sha256=config.host_key_sha256,
            principal=snap.principal,
            profile=config.visibility.profile,
            operation=request.operation,
            root=request.root,
            policy_epoch=config.visibility.policy_epoch,
            central_policy_sha256=config.visibility.central_policy_sha256,
            snapshot_id=snap.snapshot_id,
            max_entries=request.max_entries,
        )
        instant = now()
        verified = verify_snapshot(
            request.signed_snapshot,
            trusted_key=key,
            expected=expected,
            active_host_policy=config.visibility,
            now=instant,
            consume_snapshot_id=lambda nonce: PersistentSnapshotNonces(
                config.nonce_db_path
            ).consume(nonce, expires_at=snap.expires_at, now=instant),
        )
    except VisibilityRuntimeError:
        print("ssh-over-mcp-host-agent-v2: trusted state unavailable", file=stderr)
        return EX_UNAVAILABLE_V2
    except (SnapshotVerificationError, ValueError):
        print("ssh-over-mcp-host-agent-v2: policy denied", file=stderr)
        return EX_DENIED_V2

    def epoch_live() -> bool:
        try:
            current = load_host_visibility_runtime(policy_path)
            clock = now()
            return (
                current == config
                and type(clock) is int
                and snap.issued_at <= clock < snap.expires_at
            )
        except Exception:  # noqa: BLE001 — policy/clock failure must fail closed
            return False

    try:
        entries = list_verified_directory_candidate(verified, is_epoch_active=epoch_live)
        if not epoch_live():
            raise FilesystemAccessError("stale policy")
        result = {
            "request_id": request.request_id,
            "host": config.host,
            "root": request.root,
            "policy_epoch": snap.policy_epoch,
            "snapshot_id": snap.snapshot_id,
            "entries": [
                {
                    "path": item.path,
                    "kind": item.kind,
                    "size": item.size,
                    "mode": item.mode,
                    "uid": item.uid,
                    "gid": item.gid,
                    "mtime_ns": item.mtime_ns,
                }
                for item in entries
            ],
        }
        data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(data) > 64 * 1024:
            raise FilesystemAccessError("listing result exceeds limit")
        _deliver_execution_output(stdout, execution_stderr, data, b"")
        return EX_SUCCESS_V2
    except FilesystemAccessError:
        print("ssh-over-mcp-host-agent-v2: request denied", file=stderr)
        return EX_DENIED_V2
    except (OutputDeliveryError, OSError):
        return EX_UNAVAILABLE_V2


def main_v2() -> int:
    if len(sys.argv) != 1:
        return EX_PROTOCOL_V2
    return run_v2(
        env=dict(os.environ),
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr,
        execution_stderr=sys.stderr.buffer,
    )
