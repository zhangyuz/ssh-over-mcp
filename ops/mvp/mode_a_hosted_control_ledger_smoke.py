"""TEST ONLY: real MCP HTTP + Security Ledger to two isolated OpenSSH nodes.

Fed to Python inside a disposable, private-network control container.
No production daemon, no persistent keys, no shell/ssh_exec or mocks.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import socket
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, "/opt/ssh-over-mcp-e2e/workspace/src")

import httpx2
import uvicorn
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from ssh_over_mcp.api.app import build_application
from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.approvals.runtime import SecurityLedgerRuntimeSettings
from ssh_over_mcp.approvals.service import SecurityLedgerService
from ssh_over_mcp.ssh.transport import StructuredSSHTransport

# Diagnostic-only observer: delegates unmodified to the real SSH transport.
# It records no request bodies, secrets or file content.
_REAL_RUN = StructuredSSHTransport.run


async def _observe_real_transport(
    self, *, host, payload, request_id, timeout_seconds, max_output_bytes
):
    result = await _REAL_RUN(
        self,
        host=host,
        payload=payload,
        request_id=request_id,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    if b'"operation":"fs_mkdir"' in payload or b'"operation":"fs_write"' in payload:
        print(
            f"FS_MUTATION_TRANSPORT_OBSERVED host={host} status={result.exit_status}"
            f" signal={result.exit_signal} timeout={result.timed_out}"
            f" truncated={result.truncated} stdout_length={len(result.stdout)}"
            f" stderr_length={len(result.stderr)}"
            f" stderr_bounded={result.stderr[:180]!r}",
            file=sys.stderr,
            flush=True,
        )
    return result


StructuredSSHTransport.run = _observe_real_transport

NODES = ("node01", "node02")
_APPROVAL = re.compile(r"apr_[0-9a-f]{32}")


def success(result: object, label: str) -> dict:
    assert not result.is_error, (label, repr(result)[:550])
    data = result.structured_content
    assert isinstance(data, dict), (label, repr(result)[:250])
    return data


def error(result: object, label: str) -> str:
    assert result.is_error, (label, repr(result)[:450])
    blob = repr(result)
    assert len(blob) < 6000
    return blob


async def grant(approval_id: str, setting: SecurityLedgerRuntimeSettings) -> None:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "ssh_over_mcp.approvals.cli",
        "grant",
        approval_id,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": "/opt/ssh-over-mcp-e2e/workspace/src",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": str(setting.admin_socket_path),
            "SSH_OVER_MCP_LEDGER_SERVICE_UID": str(setting.service_uid),
            "SSH_OVER_MCP_LEDGER_SERVICE_GID": str(setting.service_gid),
        },
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(process.communicate(), 8)
    assert process.returncode == 0, ("ledger approval grant", err[-300:])
    assert json.loads(out)["state"] == "granted"


def policy_config() -> dict:
    hosts = {}
    for index, node in enumerate(NODES, 1):
        public = Path(f"/tmp/hostkey{index}.pub").read_text().split()
        assert len(public) >= 2 and public[0] == "ssh-ed25519"
        hosts[node] = {
            "address": node,
            "port": 2222,
            "ssh_user": "ssh-over-mcp-e2e-host",
            "credential_ref": f"client{index}",
            "host_key": " ".join(public[:2]),
            "allowed_roles": ["rw-operator"],
        }
    paths = [f"/srv/data/mvp-node-{i}" for i in (1, 2)]
    return {
        "inventory": {"hosts": hosts},
        "policy": {
            "version": 1,
            "default": "deny",
            "roles": {"rw-operator": {}},
            "risk": {"approval_required": ["medium", "high", "critical"]},
            "rules": [
                {
                    "id": "oci.two-node.fs-only",
                    "effect": "allow",
                    "roles": ["rw-operator"],
                    "hosts": list(NODES),
                    "tools": ["fs_stat", "fs_read", "fs_mkdir", "fs_write"],
                    "paths": [
                        *paths,
                        *(f"{p}/seed.bin" for p in paths),
                        *(f"{p}/approved.bin" for p in paths),
                    ],
                }
            ],
        },
    }


async def prove(root: Path, ledger: SecurityLedgerRuntimeSettings) -> None:
    cfg = root / "config.yaml"
    cfg.write_text(yaml.safe_dump(policy_config()))
    os.chmod(cfg, 0o600)
    creds = root / "credentials.yaml"
    creds.write_text(
        yaml.safe_dump({"credentials": {f"client{i}": f"/tmp/client{i}" for i in (1, 2)}})
    )
    os.chmod(creds, 0o600)
    bearer = root / "origin.token"
    token = secrets.token_urlsafe(32)
    bearer.write_text(token)
    os.chmod(bearer, 0o600)
    app = build_application(
        MCPRuntimeSettings(
            config_path=cfg,
            credential_map_path=creds,
            profile="rw-operator",
            ledger_socket_path=ledger.execution_socket_path,
            ledger_server_uid=ledger.service_uid,
            ledger_server_gid=ledger.service_gid,
            bind_host="127.0.0.1",
            origin_bearer_token_file=bearer,
        )
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(64)
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", access_log=False)
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(500):
            if server.started:
                break
            if task.done():
                raise AssertionError("central MCP exited before startup")
            await asyncio.sleep(0.01)
        assert server.started
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + token}, trust_env=False
        ) as http:
            transport = streamable_http_client(
                f"http://127.0.0.1:{port}/mcp",
                http_client=http,
                terminate_on_close=False,
            )
            async with Client(transport) as client:
                visible = success(await client.call_tool("hosts_list", {}), "hosts_list")
                assert {item["alias"] for item in visible["hosts"]} == set(NODES)
                tools = {x.name for x in (await client.list_tools()).tools}
                assert {"fs_stat", "fs_read", "fs_mkdir", "fs_write", "approval_status"} <= tools
                assert "approval_grant" not in tools and "approval_deny" not in tools

                # First prove real central MCP HTTP typed reads on BOTH SSH
                # nodes, with no approval or write privilege consumed here.
                # Fixtures were explicitly created by test setup via SSH.
                for index, node in enumerate(NODES, 1):
                    seed = f"/srv/data/mvp-node-{index}/seed.bin"
                    expected = f"central-mcp-oci-readonly-node-{index}".encode()
                    stat = success(
                        await client.call_tool("fs_stat", {"host": node, "path": seed}),
                        f"readonly stat {node}",
                    )
                    assert stat["size"] == len(expected)
                    actual = success(
                        await client.call_tool(
                            "fs_read", {"host": node, "path": seed, "max_bytes": 4096}
                        ),
                        f"readonly read {node}",
                    )
                    assert base64.b64decode(actual["data_base64"], validate=True) == expected
                    other_node = NODES[1 if index == 1 else 0]
                    denied = error(
                        await client.call_tool(
                            "fs_read",
                            {"host": other_node, "path": seed, "max_bytes": 4096},
                        ),
                        f"cross-node readonly {node}",
                    )
                    assert "denied" in denied.lower() or "failed" in denied.lower()
                    print(f"CENTRAL_MCP_READONLY_REAL_OPENSSH_{node}_PASS", flush=True)
                print("CENTRAL_MCP_READONLY_TWO_OPENSSH_NODES_PASS", flush=True)

                for i, node in enumerate(NODES, 1):
                    base = f"/srv/data/mvp-node-{i}"
                    target = f"{base}/approved.bin"
                    payload = f"mcp-ledger-oci-node-{i}".encode()
                    for tool, arguments in (
                        ("fs_mkdir", {"host": node, "path": base}),
                        (
                            "fs_write",
                            {
                                "host": node,
                                "path": target,
                                "data_base64": base64.b64encode(payload).decode(),
                            },
                        ),
                    ):
                        pending = error(await client.call_tool(tool, arguments), tool)
                        match = _APPROVAL.search(pending)
                        assert match, (tool, pending[:420])
                        approval = match.group()
                        before = success(
                            await client.call_tool("approval_status", {"approval_id": approval}),
                            "pending status",
                        )
                        assert before["state"] == "pending"
                        await grant(approval, ledger)
                        done = success(
                            await client.call_tool(tool, {**arguments, "approval_id": approval}),
                            tool + " granted",
                        )
                        assert done["host"] == node and done["path"] == arguments["path"]
                        after = success(
                            await client.call_tool("approval_status", {"approval_id": approval}),
                            "consumed status",
                        )
                        assert after["state"] == "consumed"
                        replay = error(
                            await client.call_tool(tool, {**arguments, "approval_id": approval}),
                            tool + " replay",
                        )
                        assert "approval" in replay.lower() or "denied" in replay.lower()
                    stat = success(
                        await client.call_tool("fs_stat", {"host": node, "path": target}), "stat"
                    )
                    assert stat["size"] == len(payload)
                    read = success(
                        await client.call_tool(
                            "fs_read", {"host": node, "path": target, "max_bytes": 4096}
                        ),
                        "read",
                    )
                    assert base64.b64decode(read["data_base64"], validate=True) == payload
                    other = NODES[1 - (i - 1)]
                    wrong = error(
                        await client.call_tool(
                            "fs_read", {"host": other, "path": target, "max_bytes": 4096}
                        ),
                        "sibling data",
                    )
                    assert "denied" in wrong.lower() or "failed" in wrong.lower()
                    print(f"CENTRAL_MCP_LEDGER_ONCE_ONLY_REAL_SSH_{node}_PASS", flush=True)
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 6)
        sock.close()


async def main() -> None:
    assert os.getuid() == 2201 and os.getgid() == 3201
    assert Path("/tmp/client1").is_file() and Path("/tmp/client2").is_file()
    with tempfile.TemporaryDirectory(prefix="som342-central-", dir="/tmp") as td:
        root = Path(td)
        os.chmod(root, 0o700)
        for sub in ("data", "exec", "admin"):
            (root / sub).mkdir(mode=0o700)
        key = root / "data" / "hmac"
        key.write_bytes(secrets.token_bytes(32))
        os.chmod(key, 0o600)
        setting = SecurityLedgerRuntimeSettings(
            db_path=root / "data" / "ledger.db",
            hmac_key_path=key,
            service_uid=2201,
            service_gid=3201,
            execution_socket_path=root / "exec" / "ledger.sock",
            execution_socket_gid=3201,
            execution_socket_mode=0o600,
            execution_peer_uid=2201,
            execution_peer_gid=3201,
            admin_socket_path=root / "admin" / "ledger.sock",
            admin_socket_gid=3201,
            admin_socket_mode=0o600,
            admin_peer_uid=2201,
            admin_peer_gid=3201,
        )
        ledger = SecurityLedgerService.create(setting)
        stop = threading.Event()
        thread = threading.Thread(
            target=ledger.serve_forever, kwargs={"stop_requested": stop.is_set}, daemon=True
        )
        thread.start()
        try:
            await prove(root, setting)
        finally:
            stop.set()
            thread.join(timeout=4)
            assert not thread.is_alive()
            ledger.close()
    print("CENTRAL_MCP_LEDGER_TWO_OPENSSH_NODES_TEST_ONLY_PASS", flush=True)
    print("NETWORK_DIRECTIONAL_ACL_PROVEN=false SIGNED_MEDIA=false DEPLOYED=false")


if __name__ == "__main__":
    asyncio.run(main())
