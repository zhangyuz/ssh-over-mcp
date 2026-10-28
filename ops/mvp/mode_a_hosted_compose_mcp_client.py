"""CI-only MCP client executed *inside* the running Compose control service.

The operator harness injects only a fixed operation and node alias. Token,
credential mapping, policy, SSH trust and approval authority stay server-side.
No keys or tokens are emitted into test logs or return values.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sys
from pathlib import Path

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

_APPROVAL = re.compile(r"apr_[0-9a-f]{32}")


async def main() -> None:
    assert len(sys.argv) == 3
    stage, host = sys.argv[1:]
    assert stage in {
        "unauthorized",
        "mkdir_pending",
        "mkdir_granted",
        "write_pending",
        "write_granted",
        "read",
    }
    assert host in {"node01", "node02"}
    base = f"/srv/data/mvp-node-{host[-1]}"
    target = base + "/approved.bin"
    data = f"compose-real-mcp-ledger-{host}".encode("ascii")
    origin = os.environ["SSH_OVER_MCP_BIND_HOST"]
    assert origin.startswith("172.30.253.")
    if stage == "unauthorized":
        async with httpx2.AsyncClient(trust_env=False, timeout=4) as anonymous:
            response = await anonymous.post(
                f"http://{origin}:8000/mcp",
                content=b"{}",
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 401, "MCP accepted request without origin bearer"
            assert "origin authentication failed" in response.text
        print(json.dumps({"stage": "unauthorized", "denied": True}))
        return
    token = Path("/run/secrets/origin-bearer").read_text().strip()
    assert len(token) >= 32
    args: dict[str, str | int] = {
        "host": host,
        "path": target if stage.startswith("write") else base,
    }
    if stage.startswith("write"):
        args["data_base64"] = base64.b64encode(data).decode("ascii")
    if stage == "read":
        args["path"] = target
        args["max_bytes"] = 4096
    tool = (
        "fs_mkdir"
        if stage.startswith("mkdir")
        else "fs_write"
        if stage.startswith("write")
        else "fs_read"
    )
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token},
        trust_env=False,
    ) as http:
        transport = streamable_http_client(
            f"http://{origin}:8000/mcp",
            http_client=http,
            terminate_on_close=False,
        )
        async with Client(transport) as client:
            assert (await client.call_tool("hosts_list", {})).is_error is False
            response = await client.call_tool(tool, args)
            if stage.endswith("_pending"):
                assert response.is_error, (stage, "missing approval challenge")
                pending = _APPROVAL.search(repr(response))
                assert pending is not None, "no pending approval"
                approval = pending.group()
                state = await client.call_tool("approval_status", {"approval_id": approval})
                assert not state.is_error and state.structured_content["state"] == "pending"
                print(json.dumps({"stage": stage, "approval_id": approval}))
                return
            if stage.endswith("_granted"):
                # Approval is supplied as the 3rd CLI argument by the trusted
                # operator only, not by an MCP client's authority source.
                raise AssertionError("grant stage requires approval argument")
            assert stage == "read"
            assert not response.is_error, "approved FS payload not readable"
            assert (
                base64.b64decode(response.structured_content["data_base64"], validate=True) == data
            )
            print(json.dumps({"stage": "read", "readback": True}))


async def granted(stage: str, host: str, approval: str) -> None:
    assert _APPROVAL.fullmatch(approval) and host in {"node01", "node02"}
    origin = os.environ["SSH_OVER_MCP_BIND_HOST"]
    token = Path("/run/secrets/origin-bearer").read_text().strip()
    base = f"/srv/data/mvp-node-{host[-1]}"
    data = f"compose-real-mcp-ledger-{host}".encode("ascii")
    tool = "fs_mkdir" if stage == "mkdir_granted" else "fs_write"
    args = {"host": host, "path": base if tool == "fs_mkdir" else base + "/approved.bin"}
    if tool == "fs_write":
        args["data_base64"] = base64.b64encode(data).decode("ascii")
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token},
        trust_env=False,
    ) as http:
        transport = streamable_http_client(
            f"http://{origin}:8000/mcp",
            http_client=http,
            terminate_on_close=False,
        )
        async with Client(transport) as client:
            result = await client.call_tool(tool, {**args, "approval_id": approval})
            assert not result.is_error, f"{tool} did not commit"
            assert result.structured_content["host"] == host
            status = await client.call_tool("approval_status", {"approval_id": approval})
            assert not status.is_error and status.structured_content["state"] == "consumed"
            replay = await client.call_tool(tool, {**args, "approval_id": approval})
            assert replay.is_error, "approval replay was incorrectly allowed"
            print(json.dumps({"stage": stage, "consumed_once": True, "replay_denied": True}))


if __name__ == "__main__":
    if len(sys.argv) == 4:
        assert sys.argv[1] in {"mkdir_granted", "write_granted"}
        asyncio.run(granted(sys.argv[1], sys.argv[2], sys.argv[3]))
    else:
        asyncio.run(main())
