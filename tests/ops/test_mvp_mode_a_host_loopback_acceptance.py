"""Purely synthetic checks for the operator's read-only, Mac-local live probe."""

from __future__ import annotations

import base64
import io
import json
import urllib.error

import pytest

from ops.mvp.mode_a_host_loopback_acceptance import (
    LOOPBACK_URL,
    ProbeError,
    RpcClient,
    validate_token,
    verify_live,
)


class _Response:
    def __init__(self, body: dict, session: bool = False):
        self.stream = io.BytesIO(json.dumps(body).encode())
        self.headers = {"Content-Type": "application/json"}
        if session:
            self.headers["Mcp-Session-Id"] = "session-synthetic"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1):
        return self.stream.read(size)


class _FakeOpener:
    def __init__(self, corrupt: str | None = None, anonymous_rejected: bool = True):
        self.calls: list[dict] = []
        self.corrupt = corrupt
        self.anonymous_rejected = anonymous_rejected

    def open(self, req, timeout):
        assert req.full_url == LOOPBACK_URL
        assert timeout <= 20
        payload = json.loads(req.data)
        self.calls.append({"payload": payload, "headers": dict(req.headers)})
        auth = req.get_header("Authorization")
        if not auth:
            if self.anonymous_rejected:
                raise urllib.error.HTTPError(LOOPBACK_URL, 401, "Unauthorized", {}, None)
            return _Response({"jsonrpc": "2.0", "result": {}, "id": 0})
        assert auth == "Bearer " + "x" * 48
        if len(self.calls) > 2:
            assert req.get_header("Mcp-session-id") == "session-synthetic"
        method = payload["method"]
        mid = payload.get("id")
        if method == "notifications/initialized":
            return _Response({})
        if method == "initialize":
            return _Response({"jsonrpc": "2.0", "result": {"capabilities": {}}, "id": mid}, True)
        if method != "tools/call":
            raise AssertionError(method)
        name = payload["params"]["name"]
        if name == "hosts_list":
            return _Response({"jsonrpc": "2.0", "result": {"content": []}, "id": mid})
        assert name == "fs_read"
        args = payload["params"]["arguments"]
        host = args["host"]
        assert args["path"] == f"/srv/data/mvp-node-{host[-1]}/approved.bin"
        content = ("compose-real-mcp-ledger-" + (self.corrupt or host)).encode()
        return _Response(
            {
                "jsonrpc": "2.0",
                "result": {
                    "structuredContent": {"data_base64": base64.b64encode(content).decode()}
                },
                "id": mid,
            }
        )


@pytest.mark.parametrize("bad", [b"", b"x" * 31, b"x" * 257, b"x" * 34 + b" ", b"\xff" * 50])
def test_token_validation_rejects_weak_or_malformed(bad):
    with pytest.raises(ProbeError):
        validate_token(bad)


def test_end_to_end_synthetic_loopback_readback_without_mutation_or_secret_output():
    opener = _FakeOpener()
    client = RpcClient("x" * 48, opener)
    lines = verify_live(client)
    assert lines[-1] == "YUZ_LOCAL_HOST_LOOPBACK_AUTH_MCP_FS_TWO_NODES_PASS"
    assert len(opener.calls) == 6
    assert {c["payload"]["method"] for c in opener.calls} == {
        "initialize",
        "notifications/initialized",
        "tools/call",
    }
    assert [
        c["payload"]["params"]["name"]
        for c in opener.calls
        if c["payload"]["method"] == "tools/call"
    ] == [
        "hosts_list",
        "fs_read",
        "fs_read",
    ]
    assert "x" * 48 not in "\n".join(lines)


def test_host_data_crossed_is_not_accepted():
    with pytest.raises(ProbeError, match="node01"):
        verify_live(RpcClient("x" * 48, _FakeOpener(corrupt="node02")))


def test_anonymous_origin_must_return_401():
    with pytest.raises(ProbeError, match="401"):
        verify_live(RpcClient("x" * 48, _FakeOpener(anonymous_rejected=False)))


def test_response_size_is_bounded_without_leaking_secret():
    class TooLargeOpener:
        def open(self, _req, timeout):
            class BigResponse:
                def __init__(self):
                    self.headers = {"Content-Type": "application/json"}

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def read(self, size=-1):
                    return b"a" * size

            return BigResponse()

    with pytest.raises(ProbeError):
        RpcClient("x" * 48, TooLargeOpener()).rpc("initialize", {"a": 1}, 1)
