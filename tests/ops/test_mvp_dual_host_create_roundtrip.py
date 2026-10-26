"""Operator-only create-once then read-back through the public MCP API."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ops/mvp"))
import dual_host_create_roundtrip as create


def fixture() -> dict:
    return {
        "path": "/srv/data/unique-create-smoke.txt",
        "node01": {
            "data_base64": base64.b64encode(b"one").decode(),
            "approval_id": "apr_" + "a" * 32,
        },
        "node02": {
            "data_base64": base64.b64encode(b"two").decode(),
            "approval_id": "apr_" + "b" * 32,
        },
    }


def test_two_create_only_writes_followed_by_independent_readbacks():
    body = fixture()
    calls = []

    def rpc(tool, args):
        calls.append((tool, dict(args)))
        if tool == "hosts_list":
            return {"hosts": [{"alias": "node01"}, {"alias": "node02"}]}
        if tool == "fs_write":
            return {
                "host": args["host"],
                "path": args["path"],
                "content_length": len(base64.b64decode(args["data_base64"])),
                "request_id": "req-write-" + args["host"],
            }
        if tool == "fs_stat":
            value = base64.b64decode(body[args["host"]]["data_base64"])
            return {
                "request_id": "req-stat-" + args["host"],
                "host": args["host"],
                "path": args["path"],
                "kind": "regular",
                "size": len(value),
            }
        assert tool == "fs_read"
        return {
            "request_id": "req-read-" + args["host"],
            "host": args["host"],
            "path": args["path"],
            "data_base64": body[args["host"]]["data_base64"],
        }

    digests = create.create_and_verify(rpc, body)
    assert digests == {
        host: hashlib.sha256(base64.b64decode(body[host]["data_base64"])).hexdigest()
        for host in ("node01", "node02")
    }
    assert [item[0] for item in calls] == [
        "hosts_list",
        "fs_write",
        "fs_write",
        "hosts_list",
        "fs_stat",
        "fs_read",
        "fs_stat",
        "fs_read",
    ]
    assert calls[1][1]["approval_id"] == body["node01"]["approval_id"]
    assert calls[2][1]["approval_id"] == body["node02"]["approval_id"]
    assert all(item[0] != "ssh_exec" for item in calls)


@pytest.mark.parametrize(
    "kind",
    [
        "missing_grant",
        "duplicate_grant",
        "same_payload",
        "oversize",
        "invalid_base64",
        "invalid_path",
        "extra_field",
        "wrong_node",
    ],
)
def test_invalid_manifest_never_calls_remote(kind):
    body = fixture()
    if kind == "missing_grant":
        del body["node02"]["approval_id"]
    if kind == "duplicate_grant":
        body["node02"]["approval_id"] = body["node01"]["approval_id"]
    if kind == "same_payload":
        body["node02"]["data_base64"] = body["node01"]["data_base64"]
    if kind == "oversize":
        body["node01"]["data_base64"] = base64.b64encode(b"x" * 4097).decode()
    if kind == "invalid_base64":
        body["node01"]["data_base64"] = "@@"
    if kind == "invalid_path":
        body["path"] = "/srv/data/../oops"
    if kind == "extra_field":
        body["node01"]["mode"] = "replace"
    if kind == "wrong_node":
        body["node03"] = body.pop("node02")
    rpc = Mock()
    with pytest.raises(create.SmokeRefused):
        create.create_and_verify(rpc, body)
    rpc.assert_not_called()


@pytest.mark.parametrize(
    "phase",
    [
        "missing",
        "first_write_denied",
        "first_write_wrong_host",
        "second_write_denied",
        "mismatched_read",
    ],
)
def test_fail_closed_never_retries_a_create_after_uncertain_outcome(phase):
    body = fixture()
    calls = []

    def rpc(tool, args):
        calls.append((tool, args.get("host")))
        if tool == "hosts_list":
            return (
                {"hosts": []}
                if phase == "missing"
                else {
                    "hosts": [{"alias": "node01"}, {"alias": "node02"}],
                }
            )
        if tool == "fs_write":
            if (
                phase == "first_write_denied"
                or phase == "second_write_denied"
                and args["host"] == "node02"
            ):
                raise create.SmokeRefused("MCP_TRANSPORT_FAILED")
            return {
                "host": "node02" if phase == "first_write_wrong_host" else args["host"],
                "path": args["path"],
                "content_length": 3,
                "request_id": "req",
            }
        if tool == "fs_stat":
            return {"host": args["host"], "path": args["path"], "kind": "regular", "size": 3}
        if tool == "fs_read":
            return {
                "host": args["host"],
                "path": args["path"],
                "data_base64": base64.b64encode(b"bad").decode(),
            }
        raise AssertionError(tool)

    with pytest.raises(create.SmokeRefused):
        create.create_and_verify(rpc, body)
    writes = [host for tool, host in calls if tool == "fs_write"]
    assert len(writes) == len(set(writes))
    if phase in {"first_write_denied", "first_write_wrong_host", "missing"}:
        assert "node02" not in writes


def test_private_manifest_rejects_world_readable_or_symlink(tmp_path):
    manifest = tmp_path / "approvals.json"
    manifest.write_text(json.dumps(fixture()))
    os.chmod(manifest, 0o644)
    with pytest.raises(create.SmokeRefused):
        create.read_manifest(manifest)
    os.chmod(manifest, 0o600)
    assert create.read_manifest(manifest) == fixture()
    link = tmp_path / "symlink"
    link.symlink_to(manifest)
    with pytest.raises(create.SmokeRefused):
        create.read_manifest(link)


def test_execution_requires_explicit_optin_before_transport(tmp_path, monkeypatch, capsys):
    manifest = tmp_path / "approvals.json"
    manifest.write_text(json.dumps(fixture()))
    os.chmod(manifest, 0o600)
    monkeypatch.setattr(
        "sys.argv",
        [
            "smoke",
            "--endpoint",
            "https://mcp.internal.example/mcp",
            "--token-file",
            str(tmp_path / "absent-token"),
            "--manifest",
            str(manifest),
        ],
    )
    assert create.main() == 1
    assert "WRITE_OPTIN_REQUIRED" in capsys.readouterr().out
