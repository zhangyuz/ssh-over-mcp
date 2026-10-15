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


def test_uncontrolled_writer_and_restore_refuses_before_verifier():
    api = load_module()
    fixture, witness = api.fixture_from_trusted_bytes(b"aaa", fixture_id="unit-2")
    forged = api.VerifiedFixtureAuthority(witness._source_identity, witness._proof, False)
    with pytest.raises(api.B0aInputRefused):
        api.ingest_fixed_fixture(fixture, forged)
    assert fixture.payload == b"aaa"


def test_unsealed_or_substituted_fd_refuses():
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
