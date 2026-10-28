"""Executable MCP read-only smoke for two separately pinned SSH hosts."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "ops/mvp/dual_host_read_smoke.py"
SPEC = importlib.util.spec_from_file_location("dual_host_read_smoke", SCRIPT)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)

DATA = {"node01": b"node-01\n", "node02": b"node-02\n"}


def _response(tool: str, args: dict) -> dict:
    import base64

    if tool == "hosts_list":
        return {"hosts": [{"alias": "node01"}, {"alias": "node02"}]}
    assert args["host"] in DATA
    assert args["path"] == "/srv/data/probe.txt"
    if tool == "fs_stat":
        return {
            "request_id": "req-stat-" + args["host"],
            "host": args["host"],
            "path": args["path"],
            "kind": "regular",
            "size": len(DATA[args["host"]]),
        }
    assert tool == "fs_read"
    assert args["max_bytes"] == 4096
    return {
        "request_id": "req-read-" + args["host"],
        "host": args["host"],
        "path": args["path"],
        "data_base64": base64.b64encode(DATA[args["host"]]).decode("ascii"),
    }


def _samples():
    import hashlib

    return {alias: hashlib.sha256(payload).hexdigest() for alias, payload in DATA.items()}


def test_both_real_mcp_tool_paths_and_content_pins_have_distinct_host_routing():
    calls = []

    def rpc(tool, args):
        calls.append((tool, args))
        return _response(tool, args)

    outcome = smoke.verify_two_nodes(rpc, path="/srv/data/probe.txt", expected=_samples())
    assert outcome == {"node01": _samples()["node01"], "node02": _samples()["node02"]}
    assert [tool for tool, _ in calls] == [
        "hosts_list",
        "fs_stat",
        "fs_read",
        "fs_stat",
        "fs_read",
    ]
    assert calls[1][1]["host"] == "node01"
    assert calls[3][1]["host"] == "node02"


@pytest.mark.parametrize(
    "fault", ["hidden", "wrong_host", "denied", "bad_bytes", "bad_sha", "same_sha"]
)
def test_verification_refuses_hidden_wrong_host_denied_or_wrong_content(fault):
    expected = _samples()
    if fault == "bad_sha":
        expected["node02"] = "a" * 64
    if fault == "same_sha":
        expected["node02"] = expected["node01"]

    def rpc(tool, args):
        if fault == "denied" and tool == "fs_read":
            raise smoke.SmokeRefused("TOOL_DENIED")
        result = _response(tool, args)
        if fault == "hidden" and tool == "hosts_list":
            result["hosts"] = [{"alias": "node01"}]
        if fault == "wrong_host" and tool == "fs_read":
            result["host"] = "node01"
        if fault == "bad_bytes" and tool == "fs_read":
            result["data_base64"] = "@@!"
        return result

    with pytest.raises(smoke.SmokeRefused):
        smoke.verify_two_nodes(rpc, path="/srv/data/probe.txt", expected=expected)


def test_http_source_must_be_private_tls_or_explicit_loopback_only():
    for url in [
        "http://example.com/mcp",
        "https://example.com/mcp?x=y",
        "https://user@example.com/mcp",
        "https://example.com/other",
    ]:
        with pytest.raises(smoke.SmokeRefused):
            smoke.validate_endpoint(url)
    assert (
        smoke.validate_endpoint("https://mcp.internal.example/mcp")
        == "https://mcp.internal.example/mcp"
    )
    assert smoke.validate_endpoint("http://127.0.0.1:8000/mcp", allow_loopback=True)
    with pytest.raises(smoke.SmokeRefused):
        smoke.validate_endpoint("http://127.0.0.1:8000/mcp")


def test_rpc_refuses_transport_tool_error_or_unstructured_data():
    import io
    import json
    from unittest.mock import patch

    client = smoke.MCPHTTPClient("https://mcp.internal.example/mcp", b"test-token")

    class FakeResponse:
        def __init__(self, body):
            self.body = io.BytesIO(json.dumps(body).encode())
            self.status = 200
            self.headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, length):
            return self.body.read(length)

    with (
        patch.object(
            smoke,
            "urlopen",
            return_value=FakeResponse(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"isError": True, "content": [{"text": "SECRET"}]},
                }
            ),
        ),
        pytest.raises(smoke.SmokeRefused, match="TOOL_DENIED"),
    ):
        client.call("hosts_list", {})
    with (
        patch.object(
            smoke,
            "urlopen",
            return_value=FakeResponse(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"content": []},
                }
            ),
        ),
        pytest.raises(smoke.SmokeRefused, match="INVALID_RESULT"),
    ):
        client.call("hosts_list", {})


def test_malformed_http_and_recursive_json_fail_without_leaking_error_text():
    import io
    from http.client import BadStatusLine
    from unittest.mock import patch

    client = smoke.MCPHTTPClient("https://mcp.internal.example/mcp", b"private-token")
    with (
        patch.object(smoke, "urlopen", side_effect=BadStatusLine("PRIVATE-SERVER-ERROR")),
        pytest.raises(smoke.SmokeRefused, match="^MCP_TRANSPORT_FAILED$"),
    ):
        client.call("hosts_list", {})

    class Nested:
        def __init__(self):
            self.headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, length):
            return io.BytesIO(b"[" * 1200 + b"0" + b"]" * 1200).read(length)

    with (
        patch.object(smoke, "urlopen", return_value=Nested()),
        pytest.raises(smoke.SmokeRefused, match="^INVALID_RESULT$"),
    ):
        client.call("hosts_list", {})


def test_cli_sanitizes_malformed_remote_status_without_leaking_sensitive_response(
    tmp_path, monkeypatch, capsys
):
    import sys
    from http.client import BadStatusLine

    token = tmp_path / "origin.token"
    token.write_bytes(b"synthetic-secret")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "smoke",
            "--endpoint",
            "https://mcp.internal.example/mcp",
            "--token-file",
            str(token),
            "--path",
            "/srv/data/probe.txt",
            "--node01-sha256",
            _samples()["node01"],
            "--node02-sha256",
            _samples()["node02"],
        ],
    )

    def malformed(*args, **kwargs):
        raise BadStatusLine("SENSITIVE_RESPONSE_MARKER")

    monkeypatch.setattr(smoke, "urlopen", malformed)
    assert smoke.main() == 1
    visible = capsys.readouterr()
    assert '"code": "MCP_TRANSPORT_FAILED"' in visible.out
    assert "SENSITIVE_RESPONSE_MARKER" not in visible.out + visible.err
    assert "Traceback" not in visible.out + visible.err


def test_real_json_rpc_wire_sequence_for_stateless_mcp_session():
    import io
    import json

    client = smoke.MCPHTTPClient("https://mcp.internal.example/mcp", b"synthetic-secret")
    methods = []

    class Reply:
        def __init__(self, value):
            self.headers = {"Content-Type": "application/json"}
            self.body = io.BytesIO(b"" if value is None else json.dumps(value).encode())

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return self.body.read(size)

    def fake_open(request, *, timeout):
        payload = json.loads(request.data)
        methods.append(payload["method"])
        assert request.get_header("Authorization") == "Bearer synthetic-secret"
        if payload["method"] == "notifications/initialized":
            return Reply(None)
        if payload["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18"}
        else:
            result = {
                "isError": False,
                "structuredContent": _response(
                    payload["params"]["name"], payload["params"]["arguments"]
                ),
            }
        return Reply({"jsonrpc": "2.0", "id": payload["id"], "result": result})

    from unittest.mock import patch

    with patch.object(smoke, "urlopen", side_effect=fake_open):
        client.initialize()
        assert (
            smoke.verify_two_nodes(client.call, path="/srv/data/probe.txt", expected=_samples())
            == _samples()
        )
    assert methods == [
        "initialize",
        "notifications/initialized",
        "tools/call",
        "tools/call",
        "tools/call",
        "tools/call",
        "tools/call",
    ]
