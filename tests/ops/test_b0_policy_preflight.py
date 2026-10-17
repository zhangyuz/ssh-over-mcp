import importlib.util
from pathlib import Path

P = Path(__file__).resolve().parents[2] / 'ops/live-e2e/b0_policy_preflight.py'
spec = importlib.util.spec_from_file_location('b0_policy_preflight', P)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def test_missing_fields_refuse():
    status, missing = mod.preflight({'artifact_name': 'candidate'})
    assert status == 'B0_POLICY_INCOMPLETE'
    assert 'verifier_sha256' in missing

def test_full_fields_never_authorize():
    status, missing = mod.preflight({key: 'UNVERIFIED' for key in mod.FIELDS})
    assert status == 'B0_POLICY_INCOMPLETE'
    assert missing

def test_non_object_refuses():
    assert mod.preflight([])[0] == 'B0_POLICY_INCOMPLETE'

def test_placeholder_value_cannot_pass_candidate_preflight():
    candidate = {key: 'UNVERIFIED' for key in mod.FIELDS}
    status, invalid = mod.preflight(candidate)
    assert status == 'B0_POLICY_INCOMPLETE'
    assert 'artifact_sha256' in invalid

def test_malformed_digests_and_boolean_size_refuse():
    candidate = {key: 'valid-looking' for key in mod.FIELDS}
    candidate['artifact_sha256'] = 'not-a-digest'
    candidate['artifact_size'] = True
    status, invalid = mod.preflight(candidate)
    assert status == 'B0_POLICY_INCOMPLETE'
    assert 'artifact_sha256' in invalid
    assert 'artifact_size' in invalid

def test_valid_shaped_candidate_remains_non_authorizing():
    candidate = {key: 'example-value' for key in mod.FIELDS}
    for key in ('artifact_sha256', 'trust_config_sha256', 'verifier_sha256'):
        candidate[key] = 'a' * 64
    candidate['fulcio_roots_sha256'] = ['b' * 64]
    candidate['rekor_log_ids'] = ['test-log']
    candidate['artifact_size'] = 123
    candidate['max_root_age_seconds'] = 86400
    candidate['max_clock_skew_seconds'] = 60
    candidate['handoff_mode'] = 'digest-from-sealed-bytes'
    assert mod.preflight(candidate) == ('B0_POLICY_CANDIDATE_ONLY', [])

def test_fifo_refused_without_blocking(tmp_path):
    import os
    import subprocess
    import sys
    fifo = tmp_path / 'policy.fifo'
    os.mkfifo(fifo)
    result = subprocess.run([sys.executable, str(P), str(fifo)], capture_output=True, timeout=3, check=False)
    assert result.returncode == 2
    assert b'B0_POLICY_REFUSED' in result.stdout

def test_oversize_refused(tmp_path):
    import subprocess
    import sys
    path = tmp_path / 'huge.json'
    path.write_bytes(b' ' * (65537))
    result = subprocess.run([sys.executable, str(P), str(path)], capture_output=True, timeout=3, check=False)
    assert result.returncode == 2

def test_deep_json_refused(tmp_path):
    import subprocess
    import sys
    path = tmp_path / 'deep.json'
    path.write_text('[' * 1000 + '0' + ']' * 1000)
    result = subprocess.run([sys.executable, str(P), str(path)], capture_output=True, timeout=3, check=False)
    assert result.returncode == 2

def test_ultra_deep_json_refuses_without_traceback(tmp_path):
    import subprocess
    import sys
    path = tmp_path / 'ultradeep.json'
    path.write_text('[' * 10000 + '0' + ']' * 10000)
    result = subprocess.run([sys.executable, str(P), str(path)], capture_output=True, timeout=3, check=False)
    assert result.returncode == 2
    assert b'B0_POLICY_REFUSED' in result.stdout
    assert b'Traceback' not in result.stderr
