#!/usr/bin/env python3
"""Read-only MCP smoke for two *real* SSH-backed target aliases; no shell or writes."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import posixpath
import re
import stat
import sys
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class SmokeRefused(ValueError):
    """A read-only multi-target acceptance gate did not pass."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Never forward the origin bearer through ambient proxy settings or redirects.
urlopen = build_opener(ProxyHandler({}), _NoRedirects()).open
_MAX_REPLY = 32 * 1024
_ALIASES = ("node01", "node02")


def validate_endpoint(url: str, *, allow_loopback: bool = False) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise SmokeRefused("INVALID_ENDPOINT") from exc
    if (
        not host
        or port == 0
        or parsed.path != "/mcp"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or (
            parsed.scheme != "https"
            and not (allow_loopback and parsed.scheme == "http" and host in {"127.0.0.1", "::1"})
        )
    ):
        raise SmokeRefused("INVALID_ENDPOINT")
    return url


def _read_token(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SmokeRefused("INVALID_TOKEN_FILE")
            token = os.read(fd, 4097)
        finally:
            os.close(fd)
    except OSError:
        raise SmokeRefused("INVALID_TOKEN_FILE") from None
    if not 1 <= len(token) <= 4096 or any(c < 33 or c > 126 for c in token):
        raise SmokeRefused("INVALID_TOKEN_FILE")
    return token


class MCPHTTPClient:
    """Tiny HTTP/JSON transport for the project's stateless JSON MCP endpoint."""

    def __init__(self, endpoint: str, token: bytes) -> None:
        self.endpoint = endpoint
        self.token = token
        self.number = 0
        self.protocol_version = "2025-06-18"

    def _post(self, payload: dict) -> dict | None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.endpoint,
            data=encoded,
            method="POST",
            headers={
                "Authorization": "Bearer " + self.token.decode("ascii"),
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": self.protocol_version,
            },
        )
        try:
            with urlopen(request, timeout=8) as reply:
                content_type = reply.headers.get("Content-Type", "").split(";", 1)[0]
                data = reply.read(_MAX_REPLY + 1)
        except (HTTPError, URLError, HTTPException, OSError, TimeoutError, ValueError):
            raise SmokeRefused("MCP_TRANSPORT_FAILED") from None
        if not data and "id" not in payload:
            return None
        if content_type != "application/json" or len(data) > _MAX_REPLY:
            raise SmokeRefused("INVALID_RESULT")
        try:
            document = json.loads(data)
        except (ValueError, UnicodeError, RecursionError):
            raise SmokeRefused("INVALID_RESULT") from None
        if not isinstance(document, dict) or document.get("jsonrpc") != "2.0":
            raise SmokeRefused("INVALID_RESULT")
        if document.get("id") != payload.get("id") or "error" in document:
            raise SmokeRefused("MCP_CALL_DENIED")
        return document.get("result")

    def initialize(self) -> None:
        self.number += 1
        result = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.number,
                "method": "initialize",
                "params": {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "som-dual-host-smoke", "version": "1"},
                },
            }
        )
        if not isinstance(result, dict) or result.get("protocolVersion") != self.protocol_version:
            raise SmokeRefused("MCP_HANDSHAKE_FAILED")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool: str, args: dict) -> dict:
        self.number += 1
        result = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.number,
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            }
        )
        if not isinstance(result, dict) or result.get("isError") is True:
            raise SmokeRefused("TOOL_DENIED")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise SmokeRefused("INVALID_RESULT")
        return structured


def verify_two_nodes(rpc, *, path: str, expected: dict[str, str]) -> dict[str, str]:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\x00" in path
        or path != posixpath.normpath(path)
        or len(path.encode("utf-8")) > 4096
    ):
        raise SmokeRefused("INVALID_PATH")
    if (
        set(expected) != set(_ALIASES)
        or any(re.fullmatch("[0-9a-f]{64}", sha) is None for sha in expected.values())
        or expected["node01"] == expected["node02"]
    ):
        raise SmokeRefused("INVALID_EXPECTED_DIGESTS")

    visible = rpc("hosts_list", {})
    try:
        aliases = {host["alias"] for host in visible["hosts"]}
    except (KeyError, TypeError, ValueError):
        raise SmokeRefused("INVALID_RESULT") from None
    if not set(_ALIASES) <= aliases:
        raise SmokeRefused("HOST_NOT_VISIBLE")

    passed = {}
    for alias in _ALIASES:
        args = {"host": alias, "path": path}
        metadata = rpc("fs_stat", args)
        data = rpc("fs_read", {**args, "max_bytes": 4096})
        if not isinstance(metadata, dict) or not isinstance(data, dict):
            raise SmokeRefused("INVALID_RESULT")
        if any(
            result.get("host") != alias or result.get("path") != path for result in (metadata, data)
        ):
            raise SmokeRefused("WRONG_TARGET")
        if metadata.get("kind") != "regular" or type(metadata.get("size")) is not int:
            raise SmokeRefused("INVALID_RESULT")
        try:
            decoded = base64.b64decode(data["data_base64"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error):
            raise SmokeRefused("INVALID_RESULT") from None
        if len(decoded) != metadata["size"] or len(decoded) > 4096:
            raise SmokeRefused("CONTENT_MISMATCH")
        digest = hashlib.sha256(decoded).hexdigest()
        if digest != expected[alias]:
            raise SmokeRefused("CONTENT_MISMATCH")
        passed[alias] = digest
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="private MCP HTTPS URL ending /mcp")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--path", required=True, help="existing regular file on both targets")
    parser.add_argument("--node01-sha256", required=True)
    parser.add_argument("--node02-sha256", required=True)
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help="local test fixture only, never public HTTP",
    )
    args = parser.parse_args()
    try:
        endpoint = validate_endpoint(args.endpoint, allow_loopback=args.allow_loopback_http)
        token = _read_token(args.token_file)
        client = MCPHTTPClient(endpoint, token)
        client.initialize()
        verified = verify_two_nodes(
            client.call,
            path=args.path,
            expected={"node01": args.node01_sha256, "node02": args.node02_sha256},
        )
    except SmokeRefused as exc:
        print(json.dumps({"status": "REFUSED", "code": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "status": "PASS",
                "verified_hosts": list(verified),
                "content_sha256": verified,
                "live_read_only": True,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
