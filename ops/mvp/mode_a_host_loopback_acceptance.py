"""Read-only acceptance of the operator-approved Yuz.local Mode A loopback pilot.

This deliberately checks one fixed Mac-local listener and two fixed data fixtures.
It never grants an approval, changes a file, or prints the private bearer.
"""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

LOOPBACK_URL = "http://127.0.0.1:18801/mcp"
PILOT_VM = "som-mode-a-netpilot-oct27"
BEARER_PATH = "/var/lib/ssh-over-mcp/mode-a-fs-pilot/control/origin-bearer"
MAX_RESPONSE = 128 * 1024
REQUEST_TIMEOUT = 18


class ProbeError(Exception):
    """An acceptance failure, without origin-supplied text or bearer values."""


def validate_token(raw: bytes) -> str:
    try:
        token = raw.rstrip(b"\r\n").decode("ascii")
    except UnicodeDecodeError:
        raise ProbeError("bearer is not ASCII") from None
    if not (32 <= len(token) <= 256) or not all(33 <= ord(ch) <= 126 for ch in token):
        raise ProbeError("bearer has invalid length or characters")
    return token


def fetch_guest_token() -> str:
    # Do not pass the secret on argv, through an environment variable or to logs.
    try:
        result = subprocess.run(
            ["limactl", "shell", PILOT_VM, "--", "sudo", "-n", "cat", BEARER_PATH],
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeError("cannot read guest bearer through approved Lima transport") from None
    if result.returncode != 0:
        raise ProbeError("guest bearer is unavailable") from None
    return validate_token(result.stdout)


class RpcClient:
    def __init__(self, token: str, opener: Any = None):
        self.token = token
        self.session: str | None = None
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _post(self, payload: dict[str, Any], authenticated: bool) -> dict[str, Any] | None:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(
            LOOPBACK_URL,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with self.opener.open(request, timeout=REQUEST_TIMEOUT) as response:
                session = response.headers.get("Mcp-Session-Id")
                if session:
                    self.session = session
                content_type = response.headers.get("Content-Type", "")
                body = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            raise ProbeError(f"unexpected MCP HTTP status {exc.code}") from None
        except (OSError, TimeoutError):
            raise ProbeError("MCP local listener is unavailable") from None
        if len(body) > MAX_RESPONSE:
            raise ProbeError("MCP response exceeds fixed size bound")
        if not body:
            return None
        try:
            if "text/event-stream" in content_type:
                events = [
                    json.loads(line[6:])
                    for line in body.decode("utf-8").splitlines()
                    if line.startswith("data: {")
                ]
                if not events:
                    raise ProbeError("MCP event response lacks JSON data")
                response_value = next(
                    (event for event in events if event.get("id") == payload.get("id")),
                    events[-1],
                )
            else:
                response_value = json.loads(body)
        except (UnicodeDecodeError, ValueError, AttributeError, TypeError):
            raise ProbeError("MCP response is not valid bounded JSON") from None
        if not isinstance(response_value, dict):
            raise ProbeError("MCP response is not an object")
        return response_value

    def assert_anonymous_denied(self) -> None:
        request = urllib.request.Request(
            LOOPBACK_URL,
            data=b'{"jsonrpc":"2.0","method":"initialize","id":0}',
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=REQUEST_TIMEOUT) as response:
                response.read(1)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return
            raise ProbeError(f"anonymous MCP HTTP expected 401, got {exc.code}") from None
        except (OSError, TimeoutError):
            raise ProbeError("anonymous MCP request could not reach localhost") from None
        raise ProbeError("anonymous MCP request did not receive 401")

    def rpc(self, method: str, params: dict[str, Any] | None = None, request_id: int | None = 1):
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if request_id is not None:
            payload["id"] = request_id
        if params is not None:
            payload["params"] = params
        result = self._post(payload, authenticated=True)
        if request_id is None:
            return None
        if result is None or result.get("id") != request_id or "error" in result:
            raise ProbeError(f"MCP method {method} returned error or wrong request ID")
        if not isinstance(result.get("result"), dict):
            raise ProbeError(f"MCP method {method} did not return a result object")
        return result["result"]


def _read_result_bytes(result: Mapping[str, Any]) -> bytes:
    if result.get("isError"):
        raise ProbeError("MCP fs_read was rejected")
    content = result.get("structuredContent") or {}
    if not isinstance(content, dict):
        raise ProbeError("MCP fs_read content is invalid")
    if "data_base64" not in content:
        for item in result.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                try:
                    candidate = json.loads(item.get("text", ""))
                except (ValueError, TypeError):
                    continue
                if isinstance(candidate, dict) and "data_base64" in candidate:
                    content = candidate
                    break
    try:
        return base64.b64decode(content["data_base64"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        raise ProbeError("MCP fs_read did not return valid base64") from None


def verify_live(client: RpcClient) -> list[str]:
    """No mutation: anonymous 401, authenticated initialization, and two exact readbacks."""
    client.assert_anonymous_denied()
    init = client.rpc(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "som-mode-a-live-probe", "version": "1"},
        },
        1,
    )
    if "capabilities" not in init:
        raise ProbeError("MCP initialization lacks capabilities")
    client.rpc("notifications/initialized", request_id=None)
    hosts = client.rpc("tools/call", {"name": "hosts_list", "arguments": {}}, 2)
    if hosts.get("isError"):
        raise ProbeError("MCP hosts_list was rejected")
    markers = [
        "HOST_LOOPBACK_ANONYMOUS_401_PASS",
        "HOST_LOOPBACK_AUTHENTICATED_MCP_INITIALIZE_PASS",
        "HOST_LOOPBACK_AUTHENTICATED_MCP_HOSTS_LIST_PASS",
    ]
    for request_id, host in enumerate(("node01", "node02"), start=3):
        path = f"/srv/data/mvp-node-{host[-1]}/approved.bin"
        result = client.rpc(
            "tools/call",
            {"name": "fs_read", "arguments": {"host": host, "path": path, "max_bytes": 4096}},
            request_id,
        )
        if _read_result_bytes(result) != ("compose-real-mcp-ledger-" + host).encode():
            raise ProbeError(f"{host} readback does not match the known approved fixture")
        markers.append(f"MAC_LOOPBACK_MCP_REAL_SSH_FILE_READBACK_PASS {host}")
    markers.append("YUZ_LOCAL_HOST_LOOPBACK_AUTH_MCP_FS_TWO_NODES_PASS")
    return markers


def main() -> int:
    try:
        client = RpcClient(fetch_guest_token())
        for line in verify_live(client):
            print(line)
        return 0
    except ProbeError as exc:
        print(f"MODE_A_LOCAL_ACCEPTANCE_REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
