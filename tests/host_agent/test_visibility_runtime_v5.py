"""Host-side v5 runtime must fail closed unless trusted local state is present."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from ssh_over_mcp.host_agent.visibility_runtime_v5 import (
    HostVisibilityRuntimeV5,
    PersistentSnapshotNonces,
    VisibilityRuntimeError,
    load_trusted_visibility_key,
)


def _config(tmp_path: Path, **changes):
    base = {
        "version": 5,
        "enabled": True,
        "host": "node01",
        "host_key_sha256": "a" * 64,
        "signer_key_path": str(tmp_path / "signer.key"),
        "nonce_db_path": str(tmp_path / "nonce-storage" / "nonce.sqlite"),
        "visibility": {
            "version": 5,
            "host": "node01",
            "profile": "operator",
            "policy_epoch": 4,
            "central_policy_sha256": "b" * 64,
            "enabled": True,
            "operations": {
                "fs_list": {
                    "allow_roots": (str(tmp_path / "list"),),
                    "deny_subtrees": (),
                },
                "fs_search": {
                    "allow_roots": (str(tmp_path / "list"),),
                    "deny_subtrees": (),
                },
            },
        },
    }
    base.update(changes)
    return HostVisibilityRuntimeV5.model_validate(base)


def test_v5_runtime_config_matches_local_host_and_has_no_escape_hatches(tmp_path):
    conf = _config(tmp_path)
    assert conf.host == conf.visibility.host
    assert conf.visibility.enabled
    for k, val in (
        ("host", "node02"),
        ("enabled", False),
        ("extra", True),
        ("signer_key_path", "/var/../tmp/key"),
        ("nonce_db_path", "relative.sqlite"),
    ):
        raw = conf.model_dump(mode="json")
        raw[k] = val
        with pytest.raises((ValueError, ValidationError)):
            HostVisibilityRuntimeV5.model_validate(raw)


def test_host_signer_key_requires_exact_32_bytes_and_mode(tmp_path, monkeypatch):
    import ssh_over_mcp.host_agent.visibility_runtime_v5 as module

    monkeypatch.setattr(module, "_TRUSTED_ADMIN_UID", os.geteuid())
    path = tmp_path / "signer.key"
    path.write_bytes(bytes(range(32)))
    os.chmod(path, 0o400)
    assert load_trusted_visibility_key(path) == bytes(range(32))
    os.chmod(path, 0o644)
    with pytest.raises(VisibilityRuntimeError):
        load_trusted_visibility_key(path)
    os.chmod(path, 0o600)
    path.write_bytes(b"too-short")
    os.chmod(path, 0o400)
    with pytest.raises(VisibilityRuntimeError):
        load_trusted_visibility_key(path)


def test_signer_key_symlink_is_rejected(tmp_path, monkeypatch):
    import ssh_over_mcp.host_agent.visibility_runtime_v5 as module

    monkeypatch.setattr(module, "_TRUSTED_ADMIN_UID", os.geteuid())
    real = tmp_path / "real.key"
    real.write_bytes(bytes(range(32)))
    os.chmod(real, 0o600)
    linked = tmp_path / "signer.key"
    linked.symlink_to(real)
    with pytest.raises(VisibilityRuntimeError):
        load_trusted_visibility_key(linked)


def test_signed_nonce_must_be_durable_atomic_and_single_use(tmp_path):
    db = tmp_path / "nonces.sqlite"
    store = PersistentSnapshotNonces(db)
    assert store.consume("a" * 32, expires_at=1_900_000_000, now=1_800_000_000)
    assert not store.consume("a" * 32, expires_at=1_900_000_000, now=1_800_000_000)
    reopened = PersistentSnapshotNonces(db)
    assert not reopened.consume("a" * 32, expires_at=1_900_000_000, now=1_800_000_000)
    assert reopened.consume("b" * 32, expires_at=1_900_000_000, now=1_800_000_000)


def test_nonce_refuses_untrusted_id_and_invalid_expiry(tmp_path):
    store = PersistentSnapshotNonces(tmp_path / "nonces.sqlite")
    for nonce, expiry, now in (
        ("x", 1_800_000_030, 1_800_000_000),
        ("a" * 32, 1_800_000_000, 1_800_000_000),
        ("a" * 32, True, 1_800_000_000),
        ("a" * 32, 1_800_000_030, True),
    ):
        with pytest.raises(VisibilityRuntimeError):
            store.consume(nonce, expires_at=expiry, now=now)


def test_nonce_db_is_not_symlink_and_is_not_group_writable(tmp_path):
    target = tmp_path / "existing.sqlite"
    store = PersistentSnapshotNonces(target)
    store.consume("c" * 32, expires_at=1_900_000_000, now=1_800_000_000)
    linked = tmp_path / "alias.sqlite"
    linked.symlink_to(target)
    with pytest.raises(VisibilityRuntimeError):
        PersistentSnapshotNonces(linked).consume(
            "d" * 32, expires_at=1_900_000_000, now=1_800_000_000
        )
    os.chmod(target, 0o666)
    with pytest.raises(VisibilityRuntimeError):
        PersistentSnapshotNonces(target).consume(
            "e" * 32, expires_at=1_900_000_000, now=1_800_000_000
        )


def test_nonce_store_refuses_db_corruption_without_reset(tmp_path):
    db = tmp_path / "nonces.sqlite"
    db.write_bytes(b"invalid-database")
    os.chmod(db, 0o600)
    with pytest.raises(VisibilityRuntimeError):
        PersistentSnapshotNonces(db).consume("a" * 32, expires_at=1_900_000_000, now=1_800_000_000)


def test_store_never_auto_erases_old_nonce_under_same_identity(tmp_path):
    store = PersistentSnapshotNonces(tmp_path / "nonces.sqlite")
    first = "c" * 32
    assert store.consume(first, expires_at=1_800_000_010, now=1_800_000_000)
    assert not store.consume(first, expires_at=1_800_000_020, now=1_800_000_015)


def test_host_epoch_and_digest_cannot_roll_back_after_restart(tmp_path):
    db = tmp_path / "nonces.sqlite"
    current = PersistentSnapshotNonces(db)
    assert current.consume_bound(
        "1" * 32,
        expires_at=1_900_000_000,
        now=1_800_000_000,
        policy_epoch=11,
        central_policy_sha256="a" * 64,
    )
    assert current.consume_bound(
        "2" * 32,
        expires_at=1_900_000_000,
        now=1_800_000_000,
        policy_epoch=12,
        central_policy_sha256="b" * 64,
    )
    reopened = PersistentSnapshotNonces(db)
    for epoch, digest in ((11, "a" * 64), (12, "a" * 64)):
        with pytest.raises(VisibilityRuntimeError):
            reopened.consume_bound(
                "3" * 32,
                expires_at=1_900_000_000,
                now=1_800_000_000,
                policy_epoch=epoch,
                central_policy_sha256=digest,
            )
    assert reopened.consume_bound(
        "3" * 32,
        expires_at=1_900_000_000,
        now=1_800_000_000,
        policy_epoch=12,
        central_policy_sha256="b" * 64,
    )
    assert not reopened.consume_bound(
        "3" * 32,
        expires_at=1_900_000_000,
        now=1_800_000_000,
        policy_epoch=12,
        central_policy_sha256="b" * 64,
    )


@pytest.mark.parametrize(
    "epoch,digest",
    [(True, "a" * 64), (0, "a" * 64), (-1, "a" * 64), (3, "abc"), (3, "F" * 64)],
)
def test_atomic_epoch_state_rejects_invalid_binding(tmp_path, epoch, digest):
    store = PersistentSnapshotNonces(tmp_path / "nonces.sqlite")
    with pytest.raises(VisibilityRuntimeError):
        store.consume_bound(
            "4" * 32,
            expires_at=1_900_000_000,
            now=1_800_000_000,
            policy_epoch=epoch,
            central_policy_sha256=digest,
        )


def test_unprivileged_agent_owned_key_and_policy_not_trusted(tmp_path):
    """The running Host Agent must not own the authority that grants access."""
    if os.geteuid() == 0:
        pytest.skip("requires non-root test UID")
    from ssh_over_mcp.host_agent.visibility_runtime_v5 import (
        load_host_visibility_runtime,
    )

    key = tmp_path / "key"
    key.write_bytes(bytes(range(32)))
    os.chmod(key, 0o400)
    policy = tmp_path / "policy.json"
    policy.write_text("{}", encoding="utf-8")
    os.chmod(policy, 0o400)
    with pytest.raises(VisibilityRuntimeError):
        load_trusted_visibility_key(key)
    with pytest.raises(VisibilityRuntimeError):
        load_host_visibility_runtime(policy)


def test_v5_trusted_inputs_and_nonce_storage_must_have_separate_parent(tmp_path):
    """Read-only administrator grants must not share a mutable host-user directory."""
    with pytest.raises(ValueError):
        HostVisibilityRuntimeV5.model_validate(
            _config(tmp_path).model_dump(mode="json")
            | {"nonce_db_path": str(tmp_path / "different-nonce.sqlite")}
        )
