"""Test the independent typed v2 Host Agent entrypoint against trusted local files."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.cli_v2 import (
    EX_DENIED_V2,
    EX_PROTOCOL_V2,
    EX_SUCCESS_V2,
    EX_UNAVAILABLE_V2,
    run_v2,
)
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    VisibilitySnapshotV5,
    sign_snapshot,
)
from ssh_over_mcp.ssh.protocol_v2 import FSListRequestV2, encode_request_v2

_KEY = bytes(range(32))
_CLOCK = 1_800_000_015


@pytest.fixture(autouse=True)
def test_only_admin_owner(monkeypatch):
    """Simulate root-owned trust files without giving test processes root."""
    import ssh_over_mcp.host_agent.visibility_runtime_v5 as module

    monkeypatch.setattr(module, "_TRUSTED_ADMIN_UID", os.geteuid())


def _replace_policy(policy_path: Path, raw: dict) -> None:
    os.chmod(policy_path, 0o600)
    policy_path.write_text(json.dumps(raw), encoding="utf-8")
    os.chmod(policy_path, 0o400)


def _fixture(tmp_path: Path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    root = tmp_path / "data"
    root.mkdir()
    (root / "public.txt").write_bytes(b"data")
    (root / "secret").mkdir()
    (root / "secret" / "password").write_bytes(b"secret")
    key_file = trusted / "signer.key"
    key_file.write_bytes(_KEY)
    os.chmod(key_file, 0o400)
    policy_path = trusted / "host-v5.json"
    policy = {
        "version": 5,
        "enabled": True,
        "host": "node01",
        "host_key_sha256": hashlib.sha256(b"pinned test hostkey").hexdigest(),
        "signer_key_path": str(key_file),
        "nonce_db_path": str(private / "nonces.sqlite"),
        "visibility": {
            "version": 5,
            "enabled": True,
            "host": "node01",
            "profile": "operator",
            "policy_epoch": 11,
            "central_policy_sha256": "a" * 64,
            "operations": {
                "fs_list": {"allow_roots": [str(root)], "deny_subtrees": []},
                "fs_search": {"allow_roots": [str(root)], "deny_subtrees": []},
            },
        },
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    os.chmod(policy_path, 0o400)
    snap = VisibilitySnapshotV5.model_validate(
        {
            "version": 5,
            "request_id": "request-0123456789",
            "host": "node01",
            "host_key_sha256": policy["host_key_sha256"],
            "principal": "alice",
            "profile": "operator",
            "operation": "fs_list",
            "root": str(root),
            "policy_epoch": 11,
            "central_policy_sha256": "a" * 64,
            "snapshot_id": "b" * 32,
            "issued_at": _CLOCK - 5,
            "expires_at": _CLOCK + 25,
            "max_entries": 64,
            "rules": {
                "allow_roots": (str(root),),
                "deny_subtrees": (str(root / "secret"),),
            },
        }
    )
    req = FSListRequestV2(
        request_id=snap.request_id,
        profile=snap.profile,
        root=snap.root,
        max_entries=snap.max_entries,
        signed_snapshot=sign_snapshot(snap, key=_KEY),
    )
    return policy_path, policy, req


def _run(config: Path, payload: bytes, *, clock=_CLOCK, env=None):
    output = io.BytesIO()
    err = io.StringIO()
    code = run_v2(
        env=env or {"SSH_ORIGINAL_COMMAND": "mcp-v2"},
        stdin=io.BytesIO(payload),
        stdout=output,
        stderr=err,
        execution_stderr=io.BytesIO(),
        policy_path=config,
        now=lambda: clock,
    )
    return code, output.getvalue(), err.getvalue()


def test_v2_legacy_force_command_and_wrong_magic_rejected(tmp_path):
    policy, _, request = _fixture(tmp_path)
    assert (
        _run(policy, encode_request_v2(request), env={"SSH_ORIGINAL_COMMAND": "mcp-v1"})[0]
        == EX_PROTOCOL_V2
    )
    assert _run(policy, b"SMCP\x00\x01")[0] == EX_PROTOCOL_V2


def test_v2_rejects_any_stdin_suffix_before_touching_files(tmp_path):
    policy, _, req = _fixture(tmp_path)
    status, output, _ = _run(policy, encode_request_v2(req) + b"X")
    assert status == EX_PROTOCOL_V2
    assert output == b""


@pytest.mark.skipif(__import__("sys").platform != "linux", reason="requires Linux O_PATH")
def test_v2_linux_real_directory_listing_and_durable_replay(tmp_path):
    policy, _, req = _fixture(tmp_path)
    code, output, err = _run(policy, encode_request_v2(req))
    assert code == EX_SUCCESS_V2, err
    result = json.loads(output)
    assert result["request_id"] == req.request_id
    assert result["host"] == "node01"
    assert result["root"] == req.root
    assert [entry["path"] for entry in result["entries"]] == [req.root + "/public.txt"]
    assert "secret" not in output.decode()
    code, repeated_output, _ = _run(policy, encode_request_v2(req))
    assert code == EX_DENIED_V2
    assert repeated_output == b""


def test_host_v5_unsigned_policy_mutation_is_rejected_before_listing(tmp_path):
    policy, raw, req = _fixture(tmp_path)
    raw["visibility"]["policy_epoch"] = 12
    _replace_policy(policy, raw)
    code, output, _ = _run(policy, encode_request_v2(req))
    assert code == EX_DENIED_V2
    assert output == b""


def test_insecure_policy_mode_fails_closed(tmp_path):
    policy, _, req = _fixture(tmp_path)
    os.chmod(policy, 0o666)
    code, output, _ = _run(policy, encode_request_v2(req))
    assert code == EX_UNAVAILABLE_V2
    assert output == b""


def test_config_changed_during_read_invalidates_result(tmp_path, monkeypatch):
    policy, raw, req = _fixture(tmp_path)
    import ssh_over_mcp.host_agent.cli_v2 as mod

    original = mod.list_verified_directory_candidate

    def mutate(*args, **kwargs):
        raw["visibility"]["policy_epoch"] = 12
        _replace_policy(policy, raw)
        return original(*args, **kwargs)

    monkeypatch.setattr(mod, "list_verified_directory_candidate", mutate)
    code, output, _ = _run(policy, encode_request_v2(req))
    assert code in {EX_DENIED_V2, EX_UNAVAILABLE_V2}
    assert not output


def test_nonce_store_failure_is_unavailable_not_policy_denial(tmp_path):
    policy, raw, req = _fixture(tmp_path)
    db = Path(raw["nonce_db_path"])
    db.write_bytes(b"this is not a sqlite database" * 64)
    os.chmod(db, 0o600)
    status, output, _ = _run(policy, encode_request_v2(req))
    assert status == EX_UNAVAILABLE_V2
    assert output == b""


def test_host_epoch_rollback_remains_a_policy_denial(tmp_path):
    from ssh_over_mcp.host_agent.visibility_runtime_v5 import PersistentSnapshotNonces

    policy, raw, req = _fixture(tmp_path)
    assert PersistentSnapshotNonces(raw["nonce_db_path"]).consume_bound(
        "c" * 32,
        expires_at=_CLOCK + 30,
        now=_CLOCK,
        policy_epoch=12,
        central_policy_sha256="b" * 64,
    )
    status, output, _ = _run(policy, encode_request_v2(req))
    assert status == EX_DENIED_V2
    assert output == b""
