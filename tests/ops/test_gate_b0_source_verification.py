"""Non-authorizing synthetic B0a sealed-byte unit tests.

These tests do not authenticate a Sigstore signer, trust root, verifier, or source.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops" / "live-e2e" / "gate_b0_immutable_bytes.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gate_b0_immutable_bytes", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_sealed_fixture_measures_exact_all_bytes():
    api = load_module()
    payload = b"B0a synthetic binary fixture\0\xff" * 19
    fixture, witness = api.fixture_from_trusted_bytes(payload, fixture_id="unit-1")
    result = api.ingest_fixed_fixture(fixture, witness)
    try:
        assert result.sha256 == hashlib.sha256(payload).hexdigest()
        assert result.length == len(payload)
        assert result.witness_ref.startswith("synthetic-memfd:")
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        assert fcntl.fcntl(result.fd, fcntl.F_GET_SEALS) & required == required
        os.lseek(result.fd, 0, os.SEEK_SET)
        assert os.read(result.fd, len(payload) + 1) == payload
        with pytest.raises(OSError):
            os.write(result.fd, b"X")
    finally:
        api.close_measurement(result)
    with pytest.raises(OSError):
        os.fstat(result.fd)


def test_untrusted_synthetic_writer_witness_refuses_before_verifier():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"aaa", fixture_id="unit-2")
    forged = api.VerifiedFixtureAuthority(witness._source_identity, witness._proof, False)
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(fixture, forged)
    assert fixture.payload == b"aaa"


def test_synthetic_fixture_identity_mismatch_refuses():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"aaa", fixture_id="unit-3")
    another, _ = api.fixture_from_trusted_bytes(b"aaa", fixture_id="unit-4")
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(another, witness)
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(fixture, object())


def test_length_overflow_or_short_read_refuses():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"x" * 65, fixture_id="unit-5")
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(fixture, witness, max_bytes=64)
    with pytest.raises(api.B0aInputRefused):
        api.fixture_from_trusted_bytes(bytearray(b"x"), fixture_id="bad-type")
    with pytest.raises(api.B0aInputRefused):
        api.fixture_from_trusted_bytes(b"", fixture_id="empty")


def test_fd_closed_after_every_failure(monkeypatch):
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"hello", fixture_id="unit-6")
    opened = []
    real_open = os.memfd_create

    def recorder(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(api.os, "memfd_create", recorder)
    monkeypatch.setattr(api.fcntl, "fcntl", lambda *args: (_ for _ in ()).throw(OSError()))
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(fixture, witness)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_fd_closed_after_late_digest_failure(monkeypatch):
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"abcde", fixture_id="unit-late")
    opened = []
    real_open = os.memfd_create

    def recorder(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(api.os, "memfd_create", recorder)
    monkeypatch.setattr(api.os, "read", lambda *args: b"")
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(fixture, witness)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_cli_unknown_fixture_refuses():
    import json
    import subprocess
    cli = MODULE.with_name("gate_b0_source_verification.py")
    proc = subprocess.run(
        [sys.executable, str(cli), "verify-synthetic", "--fixture", "unknown",
         "--format", "json"],
        text=True, capture_output=True, check=False, timeout=5,
    )
    assert proc.returncode != 0
    result = json.loads(proc.stdout)
    assert result["status"] == "B0A_REFUSED"
    assert result["schema"] == "som.b0a.synthetic.v1"
    assert result["evidence_class"] == "NON_AUTHORIZING_SYNTHETIC"
    assert result["reason_code"] == "FIXTURE_NOT_APPROVED"
    assert not any(x in result for x in ("approved", "source_verified", "measured_sha256"))


def test_cli_known_fixture_never_self_approves_without_t5():
    import json
    import subprocess
    cli = MODULE.with_name("gate_b0_source_verification.py")
    proc = subprocess.run(
        [sys.executable, str(cli), "verify-synthetic", "--fixture", "signed-test-key-1",
         "--format", "json"],
        text=True, capture_output=True, check=False, timeout=5,
    )
    assert proc.returncode != 0
    result = json.loads(proc.stdout)
    assert result["status"] == "B0A_REFUSED"
    assert result["reason_code"] == "T5_POLICY_UNAPPROVED"
    assert len(proc.stdout.encode()) < 16 * 1024
    assert not any(x in result for x in ("approved", "source_verified", "measured_sha256"))


def test_cli_refuses_unsafe_flags_and_unknown_modes():
    import json
    import subprocess
    cli = MODULE.with_name("gate_b0_source_verification.py")
    for extra in [
        ("--root", "/tmp/test-root"), ("--approved", "true"),
        ("--online",), ("verify-approved",),
    ]:
        command = [
            sys.executable, str(cli), "verify-synthetic", "--fixture",
            "signed-test-key-1", "--format", "json", *extra,
        ]
        proc = subprocess.run(command, text=True, capture_output=True, check=False, timeout=5)
        assert proc.returncode != 0
        assert json.loads(proc.stdout)["status"] == "B0A_REFUSED"


def test_cli_help_is_non_authorizing():
    import subprocess
    cli = MODULE.with_name("gate_b0_source_verification.py")
    proc = subprocess.run(
        [sys.executable, str(cli), "--help"], text=True, capture_output=True, check=False, timeout=5,
    )
    assert proc.returncode == 0
    assert "verify-synthetic" in proc.stdout
    assert "verify-approved" not in proc.stdout


def test_forged_measurement_cannot_close_unrelated_fd():
    api = load_module()
    with open(__file__, "rb") as unrelated:
        original_fd = unrelated.fileno()
        fabricated = api.SealedMeasurement(
            fd=original_fd, sha256="0" * 64, length=1, witness_ref="untrusted"
        )
        with pytest.raises(api.B0aInputRefused):
            api.close_measurement(fabricated)
        assert os.fstat(original_fd).st_size > 0


def test_copied_measurement_cannot_close_live_owner():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"live fixture", fixture_id="owned")
    live = api.ingest_fixed_fixture(fixture, witness)
    try:
        clone = api.SealedMeasurement(
            fd=live.fd, sha256=live.sha256, length=live.length, witness_ref=live.witness_ref
        )
        with pytest.raises(api.B0aInputRefused):
            api.close_measurement(clone)
        assert os.fstat(live.fd).st_size == live.length
    finally:
        api.close_measurement(live)


def test_double_close_after_fd_reuse_refuses_and_preserves_replacement():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"closed fixture", fixture_id="reused")
    owned = api.ingest_fixed_fixture(fixture, witness)
    stale_number = owned.fd
    api.close_measurement(owned)
    with open(__file__, "rb") as unrelated:
        os.dup2(unrelated.fileno(), stale_number)
        try:
            with pytest.raises(api.B0aInputRefused):
                api.close_measurement(owned)
            assert os.fstat(stale_number).st_ino == os.fstat(unrelated.fileno()).st_ino
        finally:
            if stale_number != unrelated.fileno():
                os.close(stale_number)


def test_externally_closed_and_reused_owned_fd_refuses_without_closing_replacement():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(
        b"closed fixture", fixture_id="externally-reused"
    )
    owned = api.ingest_fixed_fixture(fixture, witness)
    fd = owned.fd
    os.close(fd)
    with open(__file__, "rb") as unrelated:
        os.dup2(unrelated.fileno(), fd)
        try:
            with pytest.raises(api.B0aInputRefused):
                api.close_measurement(owned)
            assert os.fstat(fd).st_ino == os.fstat(unrelated.fileno()).st_ino
        finally:
            if fd != unrelated.fileno():
                os.close(fd)


def test_mutated_live_measurement_fd_refuses_and_preserves_borrower():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"owned", fixture_id="mutated-fd")
    owned = api.ingest_fixed_fixture(fixture, witness)
    original = owned.fd
    with open(__file__, "rb") as unrelated:
        object.__setattr__(owned, "fd", unrelated.fileno())
        try:
            with pytest.raises(api.B0aInputRefused):
                api.close_measurement(owned)
            assert os.fstat(unrelated.fileno()).st_size > 0
        finally:
            object.__setattr__(owned, "fd", original)
    api.close_measurement(owned)


def test_handoff_rejects_mutated_public_digest_length_or_witness():
    api = load_module()
    payload = b"synthetic signed-boundary bytes"
    fixture, authority = api.fixture_from_trusted_bytes(payload, fixture_id="handoff-fields")
    measured = api.ingest_fixed_fixture(fixture, authority)
    try:
        for field, malicious in (
            ("sha256", "0" * 64),
            ("length", measured.length + 1),
            ("witness_ref", "synthetic-memfd:forged"),
        ):
            original = getattr(measured, field)
            object.__setattr__(measured, field, malicious)
            try:
                with pytest.raises(api.B0aInputRefused):
                    api.authenticated_measurement_for_handoff(measured)
            finally:
                object.__setattr__(measured, field, original)
        fd, digest, size = api.authenticated_measurement_for_handoff(measured)
        assert fd == measured.fd
        assert digest == hashlib.sha256(payload).hexdigest()
        assert size == len(payload)
    finally:
        api.close_measurement(measured)


def test_handoff_rejects_forged_or_closed_issued_descriptor():
    api = load_module()
    fixture, authority = api.fixture_from_trusted_bytes(b"fixture", fixture_id="handoff-stale")
    issued = api.ingest_fixed_fixture(fixture, authority)
    copied = api.SealedMeasurement(
        fd=issued.fd, sha256=issued.sha256,
        length=issued.length, witness_ref=issued.witness_ref,
    )
    try:
        with pytest.raises(api.B0aInputRefused):
            api.authenticated_measurement_for_handoff(copied)
    finally:
        api.close_measurement(issued)
    with pytest.raises(api.B0aInputRefused):
        api.authenticated_measurement_for_handoff(issued)


def _load_unapproved_digest_preflight():
    import importlib.util
    p = MODULE.with_name("gate_b0_sigstore_adapter.py")
    spec = importlib.util.spec_from_file_location("gate_b0_sigstore_adapter", p)
    assert spec is not None and spec.loader is not None
    adapter = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = adapter
    spec.loader.exec_module(adapter)
    return adapter


def _syntactic_message_signature_bundle(digest_hex: str) -> bytes:
    import base64
    import json
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(bytes.fromhex(digest_hex)).decode("ascii"),
                },
            },
        },
        sort_keys=True,
    ).encode("ascii")


def test_bundle_digest_preflight_matches_registered_sealed_bytes_without_certifying_signature():
    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    payload = b"test-only synthetic sealed bytes"
    fixture, witness = api.fixture_from_trusted_bytes(payload, fixture_id="digest-check")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    try:
        bundle = _syntactic_message_signature_bundle(hashlib.sha256(payload).hexdigest())
        # None explicitly denotes a consistency check, NOT a verified signer/root.
        assert adapter.check_bundle_digest_consistency(measurement, bundle) is None
    finally:
        api.close_measurement(measurement)


def test_bundle_declared_digest_differs_from_same_length_payload_refuses_preflight():
    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    payload = b"same length bytes one"
    wrong = b"same length bytes two"
    assert len(payload) == len(wrong)
    fixture, witness = api.fixture_from_trusted_bytes(payload, fixture_id="digest-mismatch")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    try:
        bundle = _syntactic_message_signature_bundle(hashlib.sha256(wrong).hexdigest())
        with pytest.raises(api.B0aInputRefused):
            adapter.check_bundle_digest_consistency(measurement, bundle)
    finally:
        api.close_measurement(measurement)


def test_bundle_duplicate_digest_or_incompatible_shape_refuses_preflight():
    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    fixture, witness = api.fixture_from_trusted_bytes(b"fixed", fixture_id="bundle-shape")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    valid = _syntactic_message_signature_bundle(measurement.sha256)
    try:
        duplicate = valid.replace(b'"digest":', b'"digest":"AAAA","digest":', 1)
        for bad in (duplicate, b"{", b"[]", b"{}", b"null", b"x" * (1024 * 1024 + 1)):
            with pytest.raises(api.B0aInputRefused):
                adapter.check_bundle_digest_consistency(measurement, bad)
    finally:
        api.close_measurement(measurement)


def test_bundle_preflight_rejects_forged_or_closed_measurement():
    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    fixture, witness = api.fixture_from_trusted_bytes(b"sealed", fixture_id="bundle-owner")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    clone = api.SealedMeasurement(
        measurement.fd, measurement.sha256, measurement.length, measurement.witness_ref
    )
    bundle = _syntactic_message_signature_bundle(measurement.sha256)
    try:
        with pytest.raises(api.B0aInputRefused):
            adapter.check_bundle_digest_consistency(clone, bundle)
    finally:
        api.close_measurement(measurement)
    with pytest.raises(api.B0aInputRefused):
        adapter.check_bundle_digest_consistency(measurement, bundle)
