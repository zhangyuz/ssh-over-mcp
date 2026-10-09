"""Canonical, bounded offline drift-report artifact and strict round trip."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_drift"), importlib.import_module(
        "staging_drift_artifact"
    )


@pytest.fixture
def example(modules):
    drift, _codec = modules
    return drift.DetachedDriftReport(
        incident="stale-target",
        before_sha256="a" * 64,
        after_sha256="b" * 64,
        marker_changed=True,
        parent_changed=False,
        selected_metadata_changed=False,
        added_paths=("payload-content/new.bin",),
        removed_paths=(),
        modified_entries=(drift.ChangedEntry("target.bundle", ("size", "ctime_ns")),),
        has_drift=True,
    )


def test_canonical_roundtrip_and_content_checksum(modules, example):
    drift, codec = modules
    artifact = codec.encode_detached_drift(example)
    assert type(artifact) is codec.DriftArtifact
    assert type(artifact.payload) is bytes
    assert artifact.sha256 == hashlib.sha256(artifact.payload).hexdigest()
    assert artifact.payload == json.dumps(
        {
            "schema_version": 1,
            "incident": example.incident,
            "before_sha256": example.before_sha256,
            "after_sha256": example.after_sha256,
            "marker_changed": True,
            "parent_changed": False,
            "selected_metadata_changed": False,
            "added_paths": ["payload-content/new.bin"],
            "removed_paths": [],
            "modified_entries": [{"path": "target.bundle", "changed_fields": ["size", "ctime_ns"]}],
            "has_drift": True,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    result = codec.decode_detached_drift(artifact.payload, expected_sha256=artifact.sha256)
    assert type(result) is drift.DetachedDriftReport
    assert result == example
    assert codec.encode_detached_drift(result) == artifact
    with pytest.raises(FrozenInstanceError):
        artifact.payload = b"mutated"


def test_unchanged_report_roundtrip(modules, example):
    _drift, codec = modules
    same = replace(
        example,
        after_sha256=example.before_sha256,
        marker_changed=False,
        added_paths=(),
        modified_entries=(),
        has_drift=False,
    )
    artifact = codec.encode_detached_drift(same)
    assert codec.decode_detached_drift(artifact.payload, expected_sha256=artifact.sha256) == same


def test_checksums_reject_mutated_bytes_but_not_claim_provenance(modules, example):
    _drift, codec = modules
    artifact = codec.encode_detached_drift(example)
    mutated = artifact.payload.replace(b'"marker_changed":true', b'"marker_changed":false')
    assert mutated != artifact.payload
    with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
        codec.decode_detached_drift(mutated, expected_sha256=artifact.sha256)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"true",
        b"not json",
        b"\xff",
        b'{"schema_version":1,"schema_version":1}',
        b" " * 3,
        b"[" * 6000,
    ],
)
def test_invalid_wire_rejected(modules, example, raw):
    _drift, codec = modules
    with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
        codec.decode_detached_drift(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize(
    "field,bad",
    [
        ("incident", "unknown"),
        ("before_sha256", "not a digest"),
        ("after_sha256", "Z" * 64),
        ("marker_changed", 1),
        ("has_drift", False),
        ("added_paths", ["payload-content/new.bin"]),
        ("removed_paths", ("../escape",)),
        ("modified_entries", ("fake",)),
    ],
)
def test_forged_report_fields_refused(modules, example, field, bad):
    _drift, codec = modules
    with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
        codec.encode_detached_drift(replace(example, **{field: bad}))


@pytest.mark.parametrize(
    "fields",
    [
        ("ctime_ns", "size"),
        ("size", "size"),
        ("unknown",),
        ("size", True),
        (),
    ],
)
def test_changed_fields_must_be_known_unique_and_ordered(modules, example, fields):
    drift, codec = modules
    changed = drift.ChangedEntry("target.bundle", fields)
    report = replace(example, modified_entries=(changed,))
    with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
        codec.encode_detached_drift(report)


def test_modified_entries_must_be_canonical_sorted_nonoverlapping(modules, example):
    drift, codec = modules
    variants = (
        replace(
            example,
            modified_entries=(
                drift.ChangedEntry("z", ("mode",)),
                drift.ChangedEntry("a", ("mode",)),
            ),
        ),
        replace(
            example,
            modified_entries=(
                drift.ChangedEntry("target.bundle", ("size",)),
                drift.ChangedEntry("target.bundle", ("mode",)),
            ),
        ),
        replace(example, removed_paths=("target.bundle",)),
        replace(example, added_paths=("target.bundle",)),
    )
    for report in variants:
        with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
            codec.encode_detached_drift(report)


def test_decoder_requires_canonical_json_and_exact_keys(modules, example):
    _drift, codec = modules
    base = json.loads(codec.encode_detached_drift(example).payload)
    variants = (
        dict(base, unknown=1),
        {key: val for key, val in base.items() if key != "parent_changed"},
        dict(base, schema_version=True),
        dict(base, added_paths=["../escape"]),
    )
    for variant in variants:
        raw = json.dumps(variant, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
            codec.decode_detached_drift(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    reordered = json.dumps(
        dict(reversed(list(base.items()))), sort_keys=False, separators=(",", ":")
    ).encode()
    assert reordered != codec.encode_detached_drift(example).payload
    with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
        codec.decode_detached_drift(
            reordered, expected_sha256=hashlib.sha256(reordered).hexdigest()
        )


def test_large_bytes_and_bad_digest_fail_early(modules, example):
    _drift, codec = modules
    with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
        codec.decode_detached_drift(b"X" * (codec.MAX_BYTES + 1), expected_sha256="0" * 64)
    for bad in (b"0" * 64, None, True, "A" * 64, "0" * 63, "z" * 64):
        with pytest.raises(codec.DriftArtifactError, match="^staging drift artifact rejected$"):
            codec.decode_detached_drift(b"{}", expected_sha256=bad)


def test_codec_calls_no_live_observer_or_host_syscalls(modules, example, monkeypatch):
    _drift, codec = modules

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline artifact codec attempted host or process call")

    artifact = codec.encode_detached_drift(example)
    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "kill", "fork", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        assert (
            codec.decode_detached_drift(artifact.payload, expected_sha256=artifact.sha256)
            == example
        )
        assert codec.encode_detached_drift(example) == artifact
