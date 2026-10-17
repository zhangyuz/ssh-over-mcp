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


# Syntactic fake fields are intentionally NOT a signed/verified Sigstore bundle.
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
                "signature": base64.b64encode(b"FAKE_UNVERIFIED_SIGNATURE").decode("ascii"),
            },
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": base64.b64encode(b"FAKE_UNVERIFIED_CERT").decode("ascii")
                },
                "tlogEntries": [{"logId": {"keyId": "UNVERIFIED_TEST_LOG"}}],
                "timestampVerificationData": {
                    "rfc3161Timestamps": [{"signedTimestamp": "RkFLRQ=="}]
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


def test_bundle_unsigned_or_missing_material_refuses():
    import json

    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    fixture, witness = api.fixture_from_trusted_bytes(b"sealed", fixture_id="bundle-unsigned")
    measured = api.ingest_fixed_fixture(fixture, witness)
    try:
        valid = json.loads(_syntactic_message_signature_bundle(measured.sha256))
        variants = []
        unsigned = json.loads(json.dumps(valid))
        del unsigned["messageSignature"]["signature"]
        variants.append(unsigned)
        for missing in ("verificationMaterial",):
            no_material = json.loads(json.dumps(valid))
            del no_material[missing]
            variants.append(no_material)
        for key in ("certificate", "tlogEntries", "timestampVerificationData"):
            absent = json.loads(json.dumps(valid))
            del absent["verificationMaterial"][key]
            variants.append(absent)
        for bad in variants:
            with pytest.raises(api.B0aInputRefused):
                adapter.check_bundle_digest_consistency(
                    measured, json.dumps(bad).encode("utf-8")
                )
    finally:
        api.close_measurement(measured)


def test_bundle_invalid_signature_or_empty_material_refuses():
    import json

    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    fixture, witness = api.fixture_from_trusted_bytes(b"sealed", fixture_id="bundle-incomplete")
    measured = api.ingest_fixed_fixture(fixture, witness)
    try:
        valid = json.loads(_syntactic_message_signature_bundle(measured.sha256))
        variants = []
        for signature in ("", "***", 1):
            bad = json.loads(json.dumps(valid))
            bad["messageSignature"]["signature"] = signature
            variants.append(bad)
        for field, value in (("certificate", {}), ("tlogEntries", []),
                             ("timestampVerificationData", {"rfc3161Timestamps": []})):
            bad = json.loads(json.dumps(valid))
            bad["verificationMaterial"][field] = value
            variants.append(bad)
        for bad in variants:
            with pytest.raises(api.B0aInputRefused):
                adapter.check_bundle_digest_consistency(
                    measured, json.dumps(bad).encode("utf-8")
                )
    finally:
        api.close_measurement(measured)


def test_upstream_real_signed_candidate_fixture_static_digest_matches_without_authority():
    """Archived upstream test signature is data, NOT an approved verifier GREEN."""
    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    bundle = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    assert len(payload) == 109
    assert hashlib.sha256(payload).hexdigest() == (
        "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
    )
    assert len(bundle) == 10123
    assert hashlib.sha256(bundle).hexdigest() == (
        "3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd"
    )
    fixture, witness = api.fixture_from_trusted_bytes(payload, fixture_id="archived-candidate")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    try:
        assert adapter.check_bundle_digest_consistency(measurement, bundle) is None
    finally:
        api.close_measurement(measurement)


def test_upstream_real_signed_candidate_same_length_modified_bytes_refuse():
    """Real archived bundle is unchanged: only sealed artifact differs by one byte."""
    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    bundle = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    modified = bytes([payload[0] ^ 1]) + payload[1:]
    assert len(modified) == len(payload)
    fixture, witness = api.fixture_from_trusted_bytes(modified, fixture_id="modified-candidate")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    try:
        with pytest.raises(api.B0aInputRefused, match="BUNDLE_DIGEST_MISMATCH"):
            adapter.check_bundle_digest_consistency(measurement, bundle)
    finally:
        api.close_measurement(measurement)


def test_upstream_candidate_bundle_digest_field_tamper_refuses_without_rewriting_signature():
    """Change *only* declared digest; original upstream signature/proofs unchanged."""
    import base64
    import json

    api = load_module()
    adapter = _load_unapproved_digest_preflight()
    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    untouched = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    assert hashlib.sha256(untouched).hexdigest() == (
        "3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd"
    )
    bundle = json.loads(untouched)
    original_signature = bundle["messageSignature"]["signature"]
    original_material = bundle["verificationMaterial"]
    bundle["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        b"\x00" * 32
    ).decode("ascii")
    assert bundle["messageSignature"]["signature"] == original_signature
    assert bundle["verificationMaterial"] == original_material
    tampered = json.dumps(bundle).encode("utf-8")
    fixture, witness = api.fixture_from_trusted_bytes(payload, fixture_id="tampered-candidate")
    measurement = api.ingest_fixed_fixture(fixture, witness)
    try:
        with pytest.raises(api.B0aInputRefused, match="BUNDLE_DIGEST_MISMATCH"):
            adapter.check_bundle_digest_consistency(measurement, tampered)
    finally:
        api.close_measurement(measurement)


def _candidate_rekor_merkle_root(
    canonical_body: bytes, *, log_index: int, tree_size: int, hashes: list[str]
) -> bytes:
    """Test-only RFC6962 inclusion math; does NOT authenticate a Rekor key."""
    import base64

    assert 0 <= log_index < tree_size
    node = hashlib.sha256(b"\x00" + canonical_body).digest()
    fn, sn = log_index, tree_size - 1
    for entry in hashes:
        sibling = base64.b64decode(entry, validate=True)
        assert len(sibling) == 32
        if fn & 1 or fn == sn:
            node = hashlib.sha256(b"\x01" + sibling + node).digest()
            while fn % 2 == 0 and fn:
                fn //= 2
                sn //= 2
        else:
            node = hashlib.sha256(b"\x01" + node + sibling).digest()
        fn //= 2
        sn //= 2
    assert fn == sn == 0
    return node


def test_upstream_candidate_rekor_inclusion_consistent_without_trusting_log():
    """Archival data links exact artifact, signature, cert and Merkle root ONLY."""
    import base64
    import json

    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    encoded = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == (
        "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
    )
    assert hashlib.sha256(encoded).hexdigest() == (
        "3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd"
    )
    bundle = json.loads(encoded)
    entries = bundle["verificationMaterial"]["tlogEntries"]
    assert len(entries) == 1
    entry = entries[0]
    canonical_body = base64.b64decode(entry["canonicalizedBody"], validate=True)
    record = json.loads(canonical_body)["spec"]["hashedRekordV002"]
    assert record["data"]["algorithm"] == "SHA2_256"
    assert base64.b64decode(record["data"]["digest"]) == hashlib.sha256(payload).digest()
    assert record["signature"]["content"] == bundle["messageSignature"]["signature"]
    assert (
        record["signature"]["verifier"]["x509Certificate"]["rawBytes"]
        == bundle["verificationMaterial"]["certificate"]["rawBytes"]
    )
    proof = entry["inclusionProof"]
    assert int(proof["logIndex"]) == int(entry["logIndex"]) == 735
    assert int(proof["treeSize"]) == 736
    assert len(proof["hashes"]) == 8
    expected = base64.b64decode(proof["rootHash"], validate=True)
    assert expected.hex() == "aecd583d8d3274057497181faeae69138a11a54270a37b327a9b39f9e1944c32"
    assert _candidate_rekor_merkle_root(
        canonical_body, log_index=735, tree_size=736, hashes=proof["hashes"]
    ) == expected
    note = proof["checkpoint"]["envelope"].split("\n\n— ", 1)[0]
    assert note.splitlines() == [
        "log2025-alpha1.rekor.sigstage.dev", "736", proof["rootHash"]
    ]
    # This verifies neither the signed checkpoint nor its issuer identity.


def test_upstream_candidate_rekor_inclusion_tampering_changes_computed_root():
    """Tampering with archived log bytes/proof must not reproduce the pinned root."""
    import base64
    import json

    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    bundle = json.loads(
        (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    )
    proof = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    body = base64.b64decode(
        bundle["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"],
        validate=True,
    )
    expected = base64.b64decode(proof["rootHash"], validate=True)
    modified_body = bytes([body[0] ^ 1]) + body[1:]
    assert len(modified_body) == len(body)
    assert _candidate_rekor_merkle_root(
        modified_body, log_index=735, tree_size=736, hashes=proof["hashes"]
    ) != expected
    modified_hashes = list(proof["hashes"])
    first_hash = bytearray(base64.b64decode(modified_hashes[0], validate=True))
    first_hash[0] ^= 1
    modified_hashes[0] = base64.b64encode(first_hash).decode("ascii")
    assert _candidate_rekor_merkle_root(
        body, log_index=735, tree_size=736, hashes=modified_hashes
    ) != expected
    # Both are mathematical negatives, not authentication of the log/root.


def _candidate_leaf_ecdsa_verification(
    *, payload: bytes, signature: bytes, certificate_der: bytes
) -> bool:
    """Conditional arithmetic with an UNTRUSTED bundled leaf; never authorizes."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory(prefix="som-b0a-untrusted-ecdsa-") as directory:
        root = Path(directory)
        certificate_path = root / "leaf.der"
        signature_path = root / "signature.der"
        payload_path = root / "payload.bin"
        public_key_path = root / "leaf-public.pem"
        certificate_path.write_bytes(certificate_der)
        signature_path.write_bytes(signature)
        payload_path.write_bytes(payload)
        # Fixed local OS utility: no shell, Sigstore tool, remote roots or network.
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
        key = subprocess.run(
            [
                "/usr/bin/openssl", "x509", "-inform", "DER",
                "-in", str(certificate_path), "-pubkey", "-noout",
            ],
            capture_output=True, check=False, timeout=5, env=env,
        )
        if key.returncode != 0:
            return False
        public_key_path.write_bytes(key.stdout)
        verified = subprocess.run(
            [
                "/usr/bin/openssl", "dgst", "-sha256",
                "-verify", str(public_key_path),
                "-signature", str(signature_path), str(payload_path),
            ],
            capture_output=True, check=False, timeout=5, env=env,
        )
        return verified.returncode == 0 and verified.stdout.strip() == b"Verified OK"


def test_upstream_candidate_ecdsa_leaf_signature_math_only():
    """Genuine archived ECDSA verifies only under self-supplied UNTRUSTED key."""
    import base64
    import json

    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    archive = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    assert len(payload) == 109
    assert hashlib.sha256(payload).hexdigest() == (
        "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
    )
    assert hashlib.sha256(archive).hexdigest() == (
        "3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd"
    )
    bundle = json.loads(archive)
    signature = base64.b64decode(bundle["messageSignature"]["signature"], validate=True)
    certificate = base64.b64decode(
        bundle["verificationMaterial"]["certificate"]["rawBytes"], validate=True
    )
    assert _candidate_leaf_ecdsa_verification(
        payload=payload, signature=signature, certificate_der=certificate
    )
    # This proves signature arithmetic, NOT Fulcio, OIDC, TSA, Rekor or TUF.


def test_upstream_candidate_ecdsa_artifact_and_signature_tamper_fail():
    """Same-length changes must fail under the unchanged untrusted leaf key."""
    import base64
    import json

    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    bundle = json.loads(
        (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    )
    signature = base64.b64decode(bundle["messageSignature"]["signature"], validate=True)
    certificate = base64.b64decode(
        bundle["verificationMaterial"]["certificate"]["rawBytes"], validate=True
    )
    altered_payload = bytes([payload[0] ^ 1]) + payload[1:]
    assert len(altered_payload) == len(payload)
    assert not _candidate_leaf_ecdsa_verification(
        payload=altered_payload, signature=signature, certificate_der=certificate
    )
    altered_signature = bytes([signature[0] ^ 1]) + signature[1:]
    assert len(altered_signature) == len(signature)
    assert not _candidate_leaf_ecdsa_verification(
        payload=payload, signature=altered_signature, certificate_der=certificate
    )
    # These negatives are not T5B or an approved full offline Sigstore verifier.


def test_cli_ambient_sigstore_variables_cannot_grant_t5_authority():
    """Untrusted environment hints must not bypass absent signed T5 policy."""
    import json
    import subprocess

    cli = MODULE.with_name("gate_b0_source_verification.py")
    env = os.environ.copy()
    env.update({
        "SIGSTORE_OFFLINE": "0",
        "SIGSTORE_BUNDLE": "/tmp/attacker-bundle",
        "SIGSTORE_TRUST_CONFIG": "/tmp/attacker-root",
        "SIGSTORE_CERT_IDENTITY": "https://invalid.example/attacker",
        "SIGSTORE_CERT_OIDC_ISSUER": "https://invalid.example",
        "B0A_T5_APPROVED": "true",
    })
    proc = subprocess.run(
        [
            sys.executable, str(cli), "verify-synthetic", "--fixture",
            "signed-test-key-1", "--format", "json",
        ],
        text=True, capture_output=True, check=False, timeout=5, env=env,
    )
    assert proc.returncode == 2
    assert not proc.stderr
    record = json.loads(proc.stdout)
    assert record == {
        "schema": "som.b0a.synthetic.v1",
        "status": "B0A_REFUSED",
        "reason_code": "T5_POLICY_UNAPPROVED",
        "evidence_class": "NON_AUTHORIZING_SYNTHETIC",
    }
    assert len(proc.stdout.encode("ascii")) < 16 * 1024
    # This covers only the current refusal-only CLI, not a future verifier sandbox.


def _archived_candidate_leaf_identity_fields() -> tuple[str, str, str]:
    """Read-only candidate X.509 extension parsing; NOT certificate-chain trust."""
    import base64
    import json
    import re
    import subprocess
    import tempfile

    root = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    bundle = json.loads((root / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes())
    cert_der = base64.b64decode(
        bundle["verificationMaterial"]["certificate"]["rawBytes"], validate=True
    )
    assert hashlib.sha256(cert_der).hexdigest() == (
        "bb2b81c4f07d282f71e99007e78584dbf7b086793fabfdde7c45244a946ac639"
    )
    with tempfile.TemporaryDirectory(prefix="som-b0a-archived-leaf-") as name:
        path = Path(name) / "leaf.der"
        path.write_bytes(cert_der)
        result = subprocess.run(
            ["/usr/bin/openssl", "x509", "-inform", "DER", "-in", str(path),
             "-text", "-noout"],
            capture_output=True, check=False, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
        )
    assert result.returncode == 0 and len(result.stdout) < 16384
    text = result.stdout
    san = re.findall(r"^\s+URI:(\S+)\s*$", text, flags=re.MULTILINE)
    oidc = re.findall(
        r"^\s+1\.3\.6\.1\.4\.1\.57264\.1\.1:\s*\n\s+(\S+)\s*$",
        text, flags=re.MULTILINE,
    )
    assert len(san) == len(oidc) == 1

    # RFC6962 certificate SCT extension: OID -> X.509 extnValue OCTET,
    # inner DER OCTET, TLS list length, one length-prefixed SCT v1 entry.
    # Exact leaf DER digest above is pinned, but its SCT is NOT authenticated.
    def read_der_octet(source: bytes, offset: int) -> tuple[bytes, int]:
        assert source[offset] == 0x04
        head = source[offset + 1]
        if head < 128:
            length, start = head, offset + 2
        else:
            count = head & 0x7F
            assert 1 <= count <= 2
            length = int.from_bytes(source[offset + 2: offset + 2 + count], "big")
            assert length >= 128
            start = offset + 2 + count
        stop = start + length
        assert stop <= len(source)
        return source[start:stop], stop

    oid = bytes.fromhex("060a2b06010401d679020402")
    assert cert_der.count(oid) == 1
    outer, _ = read_der_octet(cert_der, cert_der.index(oid) + len(oid))
    sct_list, inner_end = read_der_octet(outer, 0)
    assert inner_end == len(outer)
    assert len(sct_list) >= 5
    assert int.from_bytes(sct_list[:2], "big") == len(sct_list) - 2
    assert int.from_bytes(sct_list[2:4], "big") == len(sct_list) - 4
    sct_entry = sct_list[4:]
    assert sct_entry[0] == 0 and len(sct_entry) >= 43  # SCT v1
    return san[0], oidc[0], base64.b64encode(sct_entry[1:33]).decode("ascii")


def test_archived_candidate_identity_matches_untrusted_conformance_claims_only():
    """Record real leaf SAN/OIDC/SCT key ID without authenticating their issuer."""
    identity, oidc, sct_log_id = _archived_candidate_leaf_identity_fields()
    assert identity == (
        "https://github.com/sigstore-conformance/"
        "extremely-dangerous-public-oidc-beacon/.github/workflows/"
        "extremely-dangerous-oidc-beacon.yml@refs/heads/main"
    )
    assert oidc == "https://token.actions.githubusercontent.com"
    assert sct_log_id == "KzC83GiIyeLh2CYpXnQfSDkxlgLynDPLXkNA/rKshno="
    # This SCT log key ID is a self-reported value, not an SCT signature proof.


def test_archived_candidate_wrong_signer_identity_not_equal_expected_test_identity():
    """A wrong identity/issuer must never accidentally equal the candidate leaf."""
    identity, oidc, _ = _archived_candidate_leaf_identity_fields()
    assert identity != identity + "/attacker"
    assert identity != identity.replace("@refs/heads/main", "@refs/heads/other")
    assert oidc != "https://attacker.example"
    assert oidc != "https://token.actions.githubusercontent.com.attacker.example"
    # A real pinned Sigstore policy rejection is a DIFFERENT unexecuted T5B test.


def test_inspect_cli_exact_archived_candidate_is_untrusted_only():
    """A successful developer inspection must never certify a signature or source."""
    import json
    import subprocess
    cli = MODULE.with_name("gate_b0_source_verification.py")
    proc = subprocess.run(
        [sys.executable, str(cli), "inspect-synthetic", "--fixture", "signed-test-key-1",
         "--format", "json"],
        text=True, capture_output=True, check=False, timeout=8,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    result = json.loads(proc.stdout)
    assert result == {
        "schema": "som.b0a.inspect.v1",
        "status": "B0A_INSPECTED_UNTRUSTED",
        "evidence_class": "NON_AUTHORIZING_SYNTHETIC",
        "fixture": "signed-test-key-1",
        "measured_sha256": "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf",
        "measured_length": 109,
        "bundle_sha256": "3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd",
        "signature_verified": False,
        "source_approved": False,
    }
    assert len(proc.stdout.encode("ascii")) < 16384


def test_inspect_cli_still_refuses_arbitrary_policy_and_unsafe_flags():
    import json
    import subprocess
    cli = MODULE.with_name("gate_b0_source_verification.py")
    for extra in [("--approved", "true"), ("--root", "/tmp/key"), ("--online",)]:
        proc = subprocess.run(
            [sys.executable, str(cli), "inspect-synthetic", "--fixture", "signed-test-key-1",
             "--format", "json", *extra],
            text=True, capture_output=True, check=False, timeout=8,
        )
        assert proc.returncode == 2
        assert json.loads(proc.stdout)["status"] == "B0A_REFUSED"


def test_inspect_candidate_rejects_changed_bytes_bundle_and_digest_envelope():
    import importlib.util
    cli_path = MODULE.with_name("gate_b0_source_verification.py")
    spec = importlib.util.spec_from_file_location("gate_b0_source_verification", cli_path)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    bundle = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    with pytest.raises(cli.CandidateInspectionRefused):
        cli._inspect_candidate(payload[:-1] + bytes([payload[-1] ^ 1]), bundle)
    with pytest.raises(cli.CandidateInspectionRefused):
        cli._inspect_candidate(payload, bundle[:-1] + bytes([bundle[-1] ^ 1]))
    # Even structurally valid altered-digest bundles cannot be counted as inspected.
    import base64
    import json
    tampered = json.loads(bundle)
    tampered["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        b"\x00" * 32
    ).decode("ascii")
    with pytest.raises(cli.CandidateInspectionRefused):
        cli._inspect_candidate(payload, json.dumps(tampered).encode("ascii"))


@pytest.mark.parametrize("modified", ("artifact-byte", "bundle-byte", "artifact-symlink", "bundle-symlink"))
def test_inspect_cli_rejects_modified_or_symlinked_archived_fixtures(tmp_path, modified):
    """Change only a disposable copied checkout; never mutate the real archive."""
    import json
    import shutil
    import subprocess

    root = tmp_path / "project"
    scripts = root / "ops" / "live-e2e"
    archive = root / "tests" / "ops" / "fixtures" / "b0a_synthetic"
    scripts.mkdir(parents=True)
    archive.mkdir(parents=True)
    for source in MODULE.parent.glob("gate_b0_*.py"):
        shutil.copy2(source, scripts / source.name)
    original_archive = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    for source in original_archive.iterdir():
        if source.is_file():
            shutil.copy2(source, archive / source.name)

    artifact = archive / "sigstore-conformance-a.txt"
    bundle = archive / "sigstore-conformance-rekor2-bundle.sigstore.json"
    target = artifact if modified.startswith("artifact") else bundle
    if modified.endswith("-byte"):
        old = target.read_bytes()
        target.write_bytes(bytes([old[0] ^ 1]) + old[1:])
    else:
        replacement = archive / "not-authorized-copy.bin"
        replacement.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(replacement)

    proc = subprocess.run(
        [sys.executable, str(scripts / "gate_b0_source_verification.py"),
         "inspect-synthetic", "--fixture", "signed-test-key-1", "--format", "json"],
        text=True, capture_output=True, check=False, timeout=8,
    )
    assert proc.returncode == 2
    result = json.loads(proc.stdout)
    assert result["status"] == "B0A_REFUSED"
    assert result["reason_code"] == "CANDIDATE_BYTES_CHANGED"
    assert "measured_sha256" not in result
    assert "signature_verified" not in result


def test_inspect_synthetic_refuses_unsupported_platform_without_traceback(monkeypatch):
    """macOS must receive bounded JSON refusal, not a Linux fcntl import traceback."""
    import importlib.util

    cli_path = MODULE.with_name("gate_b0_source_verification.py")
    spec = importlib.util.spec_from_file_location("gate_b0_source_verification", cli_path)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    base = Path(__file__).resolve().parent / "fixtures" / "b0a_synthetic"
    payload = (base / "sigstore-conformance-a.txt").read_bytes()
    bundle = (base / "sigstore-conformance-rekor2-bundle.sigstore.json").read_bytes()
    with monkeypatch.context() as mp:
        mp.setattr(cli.sys, "platform", "darwin")
        with pytest.raises(cli.CandidateInspectionRefused, match="SEALED_SNAPSHOT_REFUSED"):
            cli._inspect_candidate(payload, bundle)
