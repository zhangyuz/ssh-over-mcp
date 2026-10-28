"""Disposable hosted OCI-only proof using actual project SSH connection+transport.

This script is piped via stdin to Python inside a throwaway, network-none
OpenSSH test container. It is NOT the central MCP service or Ledger approval.
The container has synthetic client credentials and no external network.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, "/opt/ssh-over-mcp-e2e/workspace/src")

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.ssh.connection import SSHConnectionManager
from ssh_over_mcp.ssh.credentials import SSHCredential, StaticCredentialProvider
from ssh_over_mcp.ssh.protocol import (
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    encode_request,
)
from ssh_over_mcp.ssh.transport import StructuredSSHTransport

PROFILE = "rw-operator"


async def prove(index: int, known: list[str]) -> None:
    node = f"node{index:02}"
    path = f"/srv/data/mvp-node-{index}/probe.bin"
    expected = f"oci-openssh-fs-node-{index}\x00".encode()
    # OpenSSH public-key lines can contain an optional trailing comment.
    # Pin the exact key-type and key bytes; never use comment text as key data.
    assert len(known) >= 3 and known[1] == "ssh-ed25519"
    inventory = Inventory(
        hosts={
            node: Host(
                address="127.0.0.1",
                port=2222,
                ssh_user="ssh-over-mcp-e2e-host",
                credential_ref="ephemeral-oci-client",
                host_key=f"{known[1]} {known[2]}",
            )
        }
    )
    manager = SSHConnectionManager(
        inventory=inventory,
        credentials=StaticCredentialProvider(
            {"ephemeral-oci-client": SSHCredential(client_keys=("/tmp/client",))}
        ),
    )
    transport = StructuredSSHTransport(connections=manager)
    try:
        for i, (envelope, data, expected_status) in enumerate(
            (
                (
                    FsStatEnvelope(
                        request_id=f"oci_{index}_async_stat", profile=PROFILE, path=path
                    ),
                    b"",
                    0,
                ),
                (
                    FsReadEnvelope(
                        request_id=f"oci_{index}_async_read",
                        profile=PROFILE,
                        path=path,
                        max_bytes=4096,
                    ),
                    b"",
                    0,
                ),
                (
                    FsWriteEnvelope(
                        request_id=f"oci_{index}_async_overwrite",
                        profile=PROFILE,
                        path=path,
                        content_length=6,
                    ),
                    b"DENIED",
                    69,
                ),
            )
        ):
            result = await transport.run(
                host=node,
                payload=encode_request(envelope, data),
                request_id=envelope.request_id,
                timeout_seconds=10,
                max_output_bytes=8192,
            )
            assert result.exit_signal is None, (i, result.exit_signal)
            assert result.exit_status == expected_status, (
                i,
                result.exit_status,
                result.stderr[-250:],
            )
            assert not result.timed_out and not result.truncated
            if i == 0:
                assert json.loads(result.stdout)["size"] == len(expected)
            elif i == 1:
                assert result.stdout == expected
            else:
                assert result.stdout == b""
        assert len(manager._pool) == 1, "expected reuse of one pinned connection"
    finally:
        await manager.close()
    print(f"PROJECT_ASYNCSSH_TRANSPORT_TYPED_FS_NODE_{index}_PASS", flush=True)


if __name__ == "__main__":
    assert len(sys.argv) == 2 and sys.argv[1] in {"1", "2"}
    known = Path("/tmp/known_hosts").read_text(encoding="ascii").strip().split()
    asyncio.run(prove(int(sys.argv[1]), known))
