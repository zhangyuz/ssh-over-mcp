"""Injected into an ephemeral real OpenSSH OCI test node over stdin.

This is NOT the production control plane. The test-only signer runs inside
the disposable node to prove the real SMCP v2 ForceCommand and kernel path.
Never print or upload key bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

SOURCE = "/opt/ssh-over-mcp-e2e/workspace/src"
sys.path.insert(0, SOURCE)

from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    VisibilitySnapshotV5,
    sign_snapshot,
)
from ssh_over_mcp.ssh.protocol_v2 import FSListRequestV2, encode_request_v2


def call(frame: bytes, command: str = "mcp-v2") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "CheckHostIP=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UserKnownHostsFile=/tmp/known_hosts",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-i",
            "/tmp/client",
            "-p",
            "2222",
            "ssh-over-mcp-e2e-host@127.0.0.1",
            command,
        ],
        input=frame,
        capture_output=True,
        timeout=16,
        check=False,
    )


def main() -> None:
    assert len(sys.argv) == 2 and sys.argv[1] in {"1", "2"}
    host = "node0" + sys.argv[1]
    pub = Path("/etc/ssh/hostkeys/ssh_host_ed25519_key.pub").read_text().split()
    assert len(pub) >= 2 and pub[0] == "ssh-ed25519"
    digest = hashlib.sha256(base64.b64decode(pub[1], validate=True)).hexdigest()
    key = Path("/etc/ssh-over-mcp/v5/signer.key").read_bytes()
    assert len(key) == 32
    now = int(time.time())
    snapshot = VisibilitySnapshotV5.model_validate(
        {
            "version": 5,
            "request_id": f"v2-real-host-{sys.argv[1]}",
            "host": host,
            "host_key_sha256": digest,
            "principal": "ephemeral-test-principal",
            "profile": "rw-operator",
            "operation": "fs_list",
            "root": "/srv/data",
            "policy_epoch": 11,
            "central_policy_sha256": "a" * 64,
            "snapshot_id": uuid.uuid4().hex,
            "issued_at": now - 2,
            "expires_at": now + 25,
            "max_entries": 64,
            "rules": {
                "allow_roots": ("/srv/data",),
                "deny_subtrees": ("/srv/data/secret",),
            },
        }
    )
    frame = encode_request_v2(
        FSListRequestV2(
            request_id=snapshot.request_id,
            profile=snapshot.profile,
            root=snapshot.root,
            max_entries=snapshot.max_entries,
            signed_snapshot=sign_snapshot(snapshot, key=key),
        )
    )
    good = call(frame)
    assert good.returncode == 0, ("v2 real positive rejected", good.returncode, good.stderr[-250:])
    response = json.loads(good.stdout)
    assert response["host"] == host
    assert response["request_id"] == snapshot.request_id
    assert response["policy_epoch"] == 11
    assert response["snapshot_id"] == snapshot.snapshot_id
    assert [entry["path"] for entry in response["entries"]] == ["/srv/data/public.txt"]
    assert b"secret" not in good.stdout
    print(f"REAL_OPENSSH_SMCP_V2_FS_LIST_{host}_PASS", flush=True)

    replay = call(frame)
    assert replay.returncode == 77 and not replay.stdout, (
        "v2 replay not denied",
        replay.returncode,
    )
    downgraded = call(frame, "mcp-v1")
    assert downgraded.returncode != 0 and not downgraded.stdout
    unexpected = call(frame, "not-a-protocol")
    assert unexpected.returncode != 0 and not unexpected.stdout
    stale = snapshot.model_copy(update={"snapshot_id": uuid.uuid4().hex, "policy_epoch": 10})
    invalid = encode_request_v2(
        FSListRequestV2(
            request_id=stale.request_id,
            profile=stale.profile,
            root=stale.root,
            max_entries=stale.max_entries,
            signed_snapshot=sign_snapshot(stale, key=key),
        )
    )
    stale_result = call(invalid)
    assert stale_result.returncode != 0 and not stale_result.stdout
    print(f"REAL_OPENSSH_SMCP_V2_DENIAL_REPLAY_DOWNGRADE_{host}_PASS", flush=True)


if __name__ == "__main__":
    main()
