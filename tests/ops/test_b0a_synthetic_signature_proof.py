"""Synthetic-only OpenSSL Ed25519 proof; no B0a source authority."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'ops/live-e2e/b0a_synthetic_signature_proof.py'
OPENSSL = '/usr/bin/openssl' if sys.platform == 'linux' else '/usr/local/bin/openssl'


def run_cli(payload, signature, key, *, executable=OPENSSL):
    return subprocess.run([sys.executable, str(SCRIPT), '--payload', str(payload), '--signature', str(signature), '--public-key', str(key)], capture_output=True, timeout=5, check=False)


def test_missing_cli_refuses_without_traceback(tmp_path):
    result = run_cli(tmp_path/'missing', tmp_path/'missing.sig', tmp_path/'missing.pub')
    assert result.returncode == 2
    assert b'B0A_SYNTHETIC_REFUSED' in result.stdout
    assert b'Traceback' not in result.stderr


def test_real_ed25519_green_and_hostile_red(tmp_path):
    if sys.platform != 'linux' or not Path(OPENSSL).is_file():
        pytest.skip('fixed OpenSSL executable unavailable')
    private = tmp_path / 'ephemeral.key'
    public = tmp_path / 'ephemeral.pub'
    payload = tmp_path / 'payload.bin'
    signature = tmp_path / 'payload.sig'
    payload.write_bytes(b'SOM-B0A-SYNTHETIC-V1\x00' + b'test-only-artifact')
    subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'Ed25519', '-out', str(private)], check=True, capture_output=True, timeout=5)
    subprocess.run([OPENSSL, 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True, timeout=5)
    subprocess.run([OPENSSL, 'pkeyutl', '-sign', '-rawin', '-inkey', str(private), '-in', str(payload), '-out', str(signature)], check=True, capture_output=True, timeout=5)
    good = run_cli(payload, signature, public)
    assert good.returncode == 0, good.stderr
    assert json.loads(good.stdout)['status'] == 'SYNTHETIC_ONLY'
    assert json.loads(good.stdout)['source_approved'] is False
    payload.write_bytes(b'SOM-B0A-SYNTHETIC-V1\x00' + b'test-only-artifacT')
    bad = run_cli(payload, signature, public)
    assert bad.returncode == 2
    assert b'B0A_SYNTHETIC_REFUSED' in bad.stdout
    payload.write_bytes(b'SOM-B0A-SYNTHETIC-V1\x00' + b'test-only-artifact')
    original_signature = signature.read_bytes()
    signature.write_bytes(bytes([original_signature[0] ^ 1]) + original_signature[1:])
    assert run_cli(payload, signature, public).returncode == 2
    signature.write_bytes(original_signature)
    other_private = tmp_path / 'other.key'
    subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'Ed25519', '-out', str(other_private)], check=True, capture_output=True, timeout=5)
    subprocess.run([OPENSSL, 'pkey', '-in', str(other_private), '-pubout', '-out', str(public)], check=True, capture_output=True, timeout=5)
    assert run_cli(payload, signature, public).returncode == 2


def test_fifo_refused_without_waiting(tmp_path):
    if not hasattr(os, 'mkfifo'):
        pytest.skip('FIFO unavailable')
    fifo = tmp_path / 'input.fifo'
    os.mkfifo(fifo)
    result = run_cli(fifo, tmp_path/'missing.sig', tmp_path/'missing.pub')
    assert result.returncode == 2
    assert b'Traceback' not in result.stderr


def test_oversized_payload_refused(tmp_path):
    payload = tmp_path / 'large.bin'
    payload.write_bytes(b'X' * 4097)
    result = run_cli(payload, tmp_path/'missing.sig', tmp_path/'missing.pub')
    assert result.returncode == 2
