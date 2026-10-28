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


def mkdir_fixture() -> dict:
    body = fixture()
    body["path"] = "/srv/data/new-session-001/result.txt"
    body["mkdir"] = {
        "node01": "apr_" + "c" * 32,
        "node02": "apr_" + "d" * 32,
    }
    return body


def test_two_create_only_mkdirs_are_verified_before_file_writes():
    body = mkdir_fixture()
    calls = []

    def rpc(tool, args):
        calls.append((tool, dict(args)))
        alias = args.get("host")
        if tool == "hosts_list":
            return {"hosts": [{"alias": "node01"}, {"alias": "node02"}]}
        if tool == "fs_mkdir":
            return {"host": alias, "path": args["path"], "request_id": "mk-" + alias}
        if tool == "fs_stat" and args["path"].endswith("/new-session-001"):
            return {
                "host": alias,
                "path": args["path"],
                "request_id": "st-" + alias,
                "kind": "directory",
                "size": 0,
            }
        if tool == "fs_write":
            return {
                "host": alias,
                "path": args["path"],
                "request_id": "write-" + alias,
                "content_length": len(base64.b64decode(args["data_base64"])),
            }
        if tool == "fs_stat":
            value = base64.b64decode(body[alias]["data_base64"])
            return {
                "host": alias,
                "path": args["path"],
                "request_id": "file-" + alias,
                "kind": "regular",
                "size": len(value),
            }
        if tool == "fs_read":
            return {
                "host": alias,
                "path": args["path"],
                "request_id": "read-" + alias,
                "data_base64": body[alias]["data_base64"],
            }
        raise AssertionError(tool)

    result = create.create_and_verify(rpc, body)
    assert set(result) == {"node01", "node02"}
    assert [name for name, _ in calls] == [
        "hosts_list",
        "fs_mkdir",
        "fs_mkdir",
        "fs_stat",
        "fs_stat",
        "fs_write",
        "fs_write",
        "hosts_list",
        "fs_stat",
        "fs_read",
        "fs_stat",
        "fs_read",
    ]
    assert [args["path"] for name, args in calls if name == "fs_mkdir"] == [
        "/srv/data/new-session-001",
        "/srv/data/new-session-001",
    ]
    assert [args["approval_id"] for name, args in calls if name == "fs_mkdir"] == [
        body["mkdir"]["node01"],
        body["mkdir"]["node02"],
    ]


@pytest.mark.parametrize(
    "kind",
    [
        "missing_mkdir_grant",
        "duplicated_mkdir_grant",
        "reuse_write_grant",
        "wrong_alias",
        "injected_mkdir_path",
        "root_parent",
    ],
)
def test_bad_mkdir_manifest_fails_before_any_rpc(kind):
    body = mkdir_fixture()
    if kind == "missing_mkdir_grant":
        del body["mkdir"]["node01"]
    elif kind == "duplicated_mkdir_grant":
        body["mkdir"]["node02"] = body["mkdir"]["node01"]
    elif kind == "reuse_write_grant":
        body["mkdir"]["node01"] = body["node01"]["approval_id"]
    elif kind == "wrong_alias":
        body["mkdir"]["node03"] = body["mkdir"].pop("node02")
    elif kind == "injected_mkdir_path":
        body["mkdir"]["path"] = "/tmp/other"
    else:
        body["path"] = "/file.txt"
    rpc = Mock()
    with pytest.raises(create.SmokeRefused, match="INVALID_MANIFEST"):
        create.create_and_verify(rpc, body)
    rpc.assert_not_called()


@pytest.mark.parametrize(
    "fault", ["first_denied", "first_wrong_host", "second_denied", "stat_not_directory"]
)
def test_failed_mkdir_never_performs_a_write_and_never_retries(fault):
    body = mkdir_fixture()
    calls = []

    def rpc(tool, args):
        calls.append((tool, args.get("host")))
        if tool == "hosts_list":
            return {"hosts": [{"alias": "node01"}, {"alias": "node02"}]}
        if tool == "fs_mkdir":
            if fault in {"first_denied", "second_denied"} and (
                fault == "first_denied" or args["host"] == "node02"
            ):
                raise create.SmokeRefused("MCP_TRANSPORT_FAILED")
            return {
                "request_id": "mk",
                "host": "node02" if fault == "first_wrong_host" else args["host"],
                "path": args["path"],
            }
        if tool == "fs_stat":
            return {
                "host": args["host"],
                "path": args["path"],
                "kind": "regular" if fault == "stat_not_directory" else "directory",
            }
        raise AssertionError(tool)

    with pytest.raises(create.SmokeRefused):
        create.create_and_verify(rpc, body)
    assert "fs_write" not in [name for name, _ in calls]
    checked_mkdir = [host for name, host in calls if name == "fs_mkdir"]
    assert len(checked_mkdir) == len(set(checked_mkdir))


def approval_result(
    approval_id: str,
    *,
    alias: str,
    tool: str,
    path: str,
    payload: bytes | None = None,
) -> dict:
    from datetime import UTC, datetime, timedelta

    return {
        "approval_id": approval_id,
        "state": "granted",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "host": alias,
        "tool": tool,
        "safe_summary": {
            "host": alias,
            "tool": tool,
            "normalized_path": path,
            "privilege": "user",
            "content_length": len(payload) if payload is not None else None,
            "content_fingerprint": (
                "sha256:" + hashlib.sha256(payload).hexdigest() if payload is not None else None
            ),
        },
    }


def valid_approval_rpc(body, calls):
    import posixpath

    grants = {}
    for alias in ("node01", "node02"):
        grants[body[alias]["approval_id"]] = approval_result(
            body[alias]["approval_id"],
            alias=alias,
            tool="fs_write",
            path=body["path"],
            payload=base64.b64decode(body[alias]["data_base64"]),
        )
        if "mkdir" in body:
            grants[body["mkdir"][alias]] = approval_result(
                body["mkdir"][alias],
                alias=alias,
                tool="fs_mkdir",
                path=posixpath.dirname(body["path"]),
            )

    def rpc(tool, args):
        calls.append((tool, dict(args)))
        assert tool == "approval_status"
        return dict(grants[args["approval_id"]])

    return rpc


@pytest.mark.parametrize("with_mkdir", [False, True])
def test_grant_preflight_verifies_all_binding_summaries_without_mutation(with_mkdir):
    body = mkdir_fixture() if with_mkdir else fixture()
    calls = []
    checked = create.preflight_approvals(valid_approval_rpc(body, calls), body)
    assert checked == (4 if with_mkdir else 2)
    assert len(calls) == checked
    assert all(name == "approval_status" for name, _ in calls)


@pytest.mark.parametrize(
    "fault",
    [
        "pending",
        "consumed",
        "wrong_host",
        "wrong_tool",
        "wrong_path",
        "wrong_content",
        "wrong_length",
        "stale",
        "wrong_identity",
    ],
)
def test_grant_preflight_rejects_wrong_or_expired_approval_before_mutation(fault):
    body = mkdir_fixture()
    calls = []
    rpc = valid_approval_rpc(body, calls)

    def corrupted(tool, args):
        record = rpc(tool, args)
        if args["approval_id"] == body["node02"]["approval_id"]:
            if fault == "pending":
                record["state"] = "pending"
            elif fault == "consumed":
                record["state"] = "consumed"
            elif fault == "wrong_host":
                record["host"] = "node01"
            elif fault == "wrong_tool":
                record["safe_summary"]["tool"] = "fs_mkdir"
            elif fault == "wrong_path":
                record["safe_summary"]["normalized_path"] = "/other"
            elif fault == "wrong_content":
                record["safe_summary"]["content_fingerprint"] = "sha256:" + "0" * 64
            elif fault == "wrong_length":
                record["safe_summary"]["content_length"] = 999
            elif fault == "stale":
                record["expires_at"] = "2020-01-01T00:00:00+00:00"
            else:
                record["approval_id"] = body["node01"]["approval_id"]
        return record

    with pytest.raises(create.SmokeRefused, match="APPROVAL_PREFLIGHT_FAILED"):
        create.preflight_approvals(corrupted, body)
    assert all(name == "approval_status" for name, _ in calls)


def test_real_operator_preflight_only_mode_never_calls_mutating_mcp(tmp_path, monkeypatch, capsys):
    import sys
    from unittest.mock import patch

    body = mkdir_fixture()
    file = tmp_path / "private.json"
    file.write_text(json.dumps(body))
    os.chmod(file, 0o600)
    token = tmp_path / "token"
    token.write_bytes(b"synthetic-token")
    calls = []
    rpc = valid_approval_rpc(body, calls)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "smoke",
            "--endpoint",
            "https://mcp.example.invalid/mcp",
            "--token-file",
            str(token),
            "--manifest",
            str(file),
            "--preflight-only",
        ],
    )

    class FakeClient:
        def __init__(self, *args):
            pass

        def initialize(self):
            calls.append(("initialize", {}))

        def call(self, tool, args):
            return rpc(tool, args)

    with patch.object(create, "MCPHTTPClient", FakeClient):
        assert create.main() == 0
    assert [tool for tool, _ in calls] == ["initialize"] + ["approval_status"] * 4
    assert '"mutations_executed": false' in capsys.readouterr().out.lower()


def test_execute_mode_validates_all_grants_before_first_mutation(tmp_path, monkeypatch, capsys):
    import sys
    from unittest.mock import patch

    body = mkdir_fixture()
    file = tmp_path / "private.json"
    file.write_text(json.dumps(body))
    os.chmod(file, 0o600)
    token = tmp_path / "token"
    token.write_bytes(b"synthetic-token")
    calls = []
    rpc = valid_approval_rpc(body, calls)

    def bad_last_grant(tool, args):
        if tool == "approval_status":
            record = rpc(tool, args)
            if args["approval_id"] == body["node02"]["approval_id"]:
                record["safe_summary"]["normalized_path"] = "/invalid"
            return record
        calls.append((tool, dict(args)))
        raise AssertionError("MUTATION MUST NOT OCCUR")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "smoke",
            "--endpoint",
            "https://mcp.example.invalid/mcp",
            "--token-file",
            str(token),
            "--manifest",
            str(file),
            "--execute-create-once",
        ],
    )

    class FakeClient:
        def __init__(self, *args):
            pass

        def initialize(self):
            pass

        def call(self, tool, args):
            return bad_last_grant(tool, args)

    with patch.object(create, "MCPHTTPClient", FakeClient):
        assert create.main() == 1
    assert all(name == "approval_status" for name, _ in calls)
    assert "APPROVAL_PREFLIGHT_FAILED" in capsys.readouterr().out
