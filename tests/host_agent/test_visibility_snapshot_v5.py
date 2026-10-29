"""Contract-first tests; these snapshots do not enable an MCP/SSH capability."""

from __future__ import annotations

import hashlib
import os
import sys

import pytest
from pydantic import ValidationError

from ssh_over_mcp.host_agent.visibility_policy_v5 import VisibilityPolicyV5
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    SignedVisibilitySnapshot,
    SnapshotBinding,
    SnapshotVerificationError,
    VisibilitySnapshotV5,
    sign_snapshot,
    verify_snapshot,
)

_TEST_KEY = bytes(range(32))
_OTHER_KEY = bytes(reversed(range(32)))


def _snapshot(**changes):
    raw = {
        "version": 5,
        "request_id": "req-0123456789",
        "host": "node01",
        "host_key_sha256": hashlib.sha256(b"node01 pinned SSH host key").hexdigest(),
        "principal": "operator@example.test",
        "profile": "rw-operator",
        "operation": "fs_list",
        "root": "/srv/data/team",
        "policy_epoch": 17,
        "central_policy_sha256": "a" * 64,
        "snapshot_id": "b" * 32,
        "issued_at": 1_800_000_000,
        "expires_at": 1_800_000_030,
        "max_entries": 64,
        "rules": {
            "allow_roots": ("/srv/data/team",),
            "deny_subtrees": ("/srv/data/team/secrets",),
        },
    }
    raw.update(changes)
    return VisibilitySnapshotV5.model_validate(raw)


def _policy(**changes):
    raw = {
        "version": 5,
        "host": "node01",
        "profile": "rw-operator",
        "policy_epoch": 17,
        "central_policy_sha256": "a" * 64,
        "enabled": True,
        "operations": {
            "fs_list": {
                "allow_roots": ("/srv/data/team",),
                "deny_subtrees": ("/srv/data/team/local-deny",),
            },
            "fs_search": {
                "allow_roots": ("/srv/data/team",),
                "deny_subtrees": (),
            },
        },
    }
    raw.update(changes)
    return VisibilityPolicyV5.model_validate(raw)


def _binding(**changes):
    raw = {
        "request_id": "req-0123456789",
        "host": "node01",
        "host_key_sha256": hashlib.sha256(b"node01 pinned SSH host key").hexdigest(),
        "principal": "operator@example.test",
        "profile": "rw-operator",
        "operation": "fs_list",
        "root": "/srv/data/team",
        "policy_epoch": 17,
        "central_policy_sha256": "a" * 64,
        "snapshot_id": "b" * 32,
        "max_entries": 64,
    }
    raw.update(changes)
    return SnapshotBinding.model_validate(raw)


def _verify(signed, *, key=_TEST_KEY, binding=None, policy=None, consume=None, now=1_800_000_015):
    return verify_snapshot(
        signed,
        trusted_key=key,
        expected=binding or _binding(),
        active_host_policy=policy or _policy(),
        now=now,
        consume_snapshot_id=consume or (lambda _: True),
    )


def test_authenticated_snapshot_intersects_central_and_host_denies():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    calls = []
    verified = _verify(signed, consume=lambda sid: calls.append(sid) or True)
    assert calls == ["b" * 32]
    assert verified.may_inspect("/srv/data/team/report.txt")
    assert not verified.may_inspect("/srv/data/team/secrets")
    assert not verified.may_inspect("/srv/data/team/secrets/hidden")
    assert not verified.may_inspect("/srv/data/team/local-deny/a")
    assert not verified.may_inspect("/srv/data/team2")
    assert not verified.may_inspect("/srv/data/team/private/../a")
    assert not verified.may_inspect("/etc/passwd")


@pytest.mark.parametrize(
    "changed",
    [
        "request_id",
        "host",
        "host_key_sha256",
        "principal",
        "profile",
        "operation",
        "root",
        "policy_epoch",
        "central_policy_sha256",
        "snapshot_id",
        "max_entries",
    ],
)
def test_every_security_binding_is_enforced(changed):
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    raw = _binding().model_dump()
    raw[changed] = {
        "host_key_sha256": "c" * 64,
        "policy_epoch": 18,
        "max_entries": 63,
    }.get(changed, "wrong-value")
    # For unknown-operation, malformed bindings are still refused.
    try:
        different = SnapshotBinding.model_validate(raw)
    except ValidationError:
        return
    with pytest.raises(SnapshotVerificationError):
        _verify(signed, binding=different)


@pytest.mark.parametrize("field", ["host", "root", "profile", "principal", "policy_epoch", "rules"])
def test_attacker_cannot_edit_signed_fields(field):
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    forged = signed.model_dump(mode="json")
    forged["payload"][field] = (
        {"allow_roots": ["/srv/data/team"], "deny_subtrees": []}
        if field == "rules"
        else 18
        if field == "policy_epoch"
        else "/srv/data/team/other"
        if field == "root"
        else "attacker"
    )
    with pytest.raises((SnapshotVerificationError, ValidationError)):
        _verify(SignedVisibilitySnapshot.model_validate(forged))


def test_attacker_cannot_replace_signature_or_key():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    with pytest.raises(SnapshotVerificationError):
        _verify(signed, key=_OTHER_KEY)
    forged = signed.model_dump()
    forged["mac_sha256"] = "0" * 64
    with pytest.raises(SnapshotVerificationError):
        _verify(SignedVisibilitySnapshot.model_validate(forged))


@pytest.mark.parametrize("now", [1_799_999_995, 1_800_000_030, 1_800_000_040])
def test_snapshot_cannot_be_future_or_expired(now):
    with pytest.raises(SnapshotVerificationError):
        _verify(sign_snapshot(_snapshot(), key=_TEST_KEY), now=now)


@pytest.mark.parametrize(
    "raw",
    [
        {"expires_at": 1_800_000_061},
        {"expires_at": 1_800_000_000},
        {"issued_at": 1_800_000_030},
        {"max_entries": 65},
        {"max_entries": True},
        {"root": "/srv/data/team/../private"},
        {"root": "/srv/data/team/secrets"},
    ],
)
def test_schema_rejects_unsafe_duration_bounds_and_unallowed_root(raw):
    with pytest.raises((ValidationError, ValueError)):
        _snapshot(**raw)


def test_host_local_disabled_or_stale_policy_fails_before_nonce_consumption():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    for modified in (
        {"enabled": False},
        {"policy_epoch": 18},
        {"central_policy_sha256": "f" * 64},
        {"host": "node02"},
        {"profile": "guest"},
    ):
        called = []
        with pytest.raises(SnapshotVerificationError):
            _verify(
                signed,
                policy=_policy(**modified),
                consume=lambda v, log=called: log.append(v) or True,
            )
        assert called == []


def test_replay_is_refused_when_trusted_nonce_store_refuses():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    observed = set()

    def consume(value):
        if value in observed:
            return False
        observed.add(value)
        return True

    _verify(signed, consume=consume)
    with pytest.raises(SnapshotVerificationError, match="replay"):
        _verify(signed, consume=consume)


def test_no_nonce_or_failure_to_consume_is_fail_closed():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    with pytest.raises(SnapshotVerificationError):
        _verify(signed, consume=lambda _: None)

    def broken(_):
        raise OSError("secret cache failure")

    with pytest.raises(SnapshotVerificationError):
        _verify(signed, consume=broken)


def test_bad_signature_does_not_consume_valid_nonce():
    signed = sign_snapshot(_snapshot(), key=_OTHER_KEY)
    called = []
    with pytest.raises(SnapshotVerificationError):
        _verify(signed, consume=lambda n: called.append(n) or True)
    assert called == []


def test_sign_and_verify_demand_32_byte_independent_key():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    with pytest.raises((ValueError, SnapshotVerificationError)):
        sign_snapshot(_snapshot(), key=b"tiny")
    with pytest.raises(SnapshotVerificationError):
        _verify(signed, key=b"tiny")


def test_explicitly_deny_unknown_fields_and_invalid_operation():
    data = _snapshot().model_dump()
    data["extra_bypass"] = True
    with pytest.raises(ValidationError):
        VisibilitySnapshotV5.model_validate(data)
    data = _snapshot().model_dump()
    data["operation"] = "exec"
    with pytest.raises(ValidationError):
        VisibilitySnapshotV5.model_validate(data)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux O_PATH required")
def test_authenticated_snapshot_never_opens_denied_child(tmp_path, monkeypatch):
    from ssh_over_mcp.host_agent.visibility_listing_candidate import (
        list_verified_directory_candidate,
    )

    (tmp_path / "public").write_bytes(b"safe")
    (tmp_path / "central-deny").write_bytes(b"secret")
    (tmp_path / "host-deny").write_bytes(b"secret")
    root = str(tmp_path)
    rule = {"allow_roots": (root,), "deny_subtrees": (root + "/central-deny",)}
    local_policy = _policy(
        operations={
            "fs_list": {"allow_roots": (root,), "deny_subtrees": (root + "/host-deny",)},
            "fs_search": {"allow_roots": (root,), "deny_subtrees": ()},
        }
    )
    signed = sign_snapshot(_snapshot(root=root, rules=rule), key=_TEST_KEY)
    verified = _verify(signed, binding=_binding(root=root), policy=local_policy)
    real_open = os.open
    observed = []

    def capture(path, flags, *args, **kwargs):
        observed.append(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", capture)
    result = list_verified_directory_candidate(verified, is_epoch_active=lambda: True)
    assert tuple(x.path for x in result) == (root + "/public",)
    assert "central-deny" not in observed
    assert "host-deny" not in observed


@pytest.mark.skipif(sys.platform != "linux", reason="Linux O_PATH required")
def test_epoch_revocation_before_and_during_scan_is_fail_closed(tmp_path, monkeypatch):
    from ssh_over_mcp.host_agent.filesystem import FilesystemAccessError
    from ssh_over_mcp.host_agent.visibility_listing_candidate import (
        list_verified_directory_candidate,
    )

    (tmp_path / "good").write_bytes(b"okay")
    root = str(tmp_path)
    rules = {"allow_roots": (root,), "deny_subtrees": ()}
    verified = _verify(
        sign_snapshot(_snapshot(root=root, rules=rules), key=_TEST_KEY),
        binding=_binding(root=root),
        policy=_policy(operations={"fs_list": rules, "fs_search": rules}),
    )
    with pytest.raises(FilesystemAccessError):
        list_verified_directory_candidate(verified, is_epoch_active=lambda: False)

    real_open = os.open
    active = True

    def revoke_on_child(path, flags, *args, **kwargs):
        nonlocal active
        result = real_open(path, flags, *args, **kwargs)
        if path == "good":
            active = False
        return result

    monkeypatch.setattr(os, "open", revoke_on_child)
    with pytest.raises(FilesystemAccessError):
        list_verified_directory_candidate(verified, is_epoch_active=lambda: active)


def test_verified_token_refuses_any_path_outside_original_query_root():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    verified = _verify(signed)
    assert verified.may_inspect("/srv/data/team/file")
    assert not verified.may_inspect("/srv/data/public/file")
    assert not verified.may_inspect("/srv")
    assert verified.may_traverse("/srv")
    assert verified.may_traverse("/srv/data")
    assert not verified.may_traverse("/srv/data/team/secrets")


def test_canonical_signed_wire_round_trip_survives_json_reencoding():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    wire = signed.model_dump_json()
    parsed = SignedVisibilitySnapshot.model_validate_json(wire)
    assert _verify(parsed).snapshot == signed.payload


def test_wrong_or_missing_nonce_consumer_does_not_grant():
    signed = sign_snapshot(_snapshot(), key=_TEST_KEY)
    with pytest.raises(SnapshotVerificationError):
        verify_snapshot(
            signed,
            trusted_key=_TEST_KEY,
            expected=_binding(),
            active_host_policy=_policy(),
            now=1_800_000_015,
            consume_snapshot_id=None,
        )
