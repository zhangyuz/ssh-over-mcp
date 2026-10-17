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
    assert status == 'B0_POLICY_CANDIDATE_ONLY'
    assert not missing

def test_non_object_refuses():
    assert mod.preflight([])[0] == 'B0_POLICY_INCOMPLETE'
