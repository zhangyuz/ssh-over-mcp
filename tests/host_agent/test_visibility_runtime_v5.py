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
        "nonce_db_path": str(tmp_path / "nonce.sqlite"),
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


def test_host_signer_key_requires_exact_32_bytes_and_mode(tmp_path):
    path = tmp_path / "signer.key"
    path.write_bytes(bytes(range(32)))
    os.chmod(path, 0o600)
    assert load_trusted_visibility_key(path) == bytes(range(32))
    os.chmod(path, 0o644)
    with pytest.raises(VisibilityRuntimeError):
        load_trusted_visibility_key(path)
    os.chmod(path, 0o600)
    path.write_bytes(b"too-short")
    with pytest.raises(VisibilityRuntimeError):
        load_trusted_visibility_key(path)


def test_signer_key_symlink_is_rejected(tmp_path):
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
