from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
FROZEN = {
    'scripts/run-live-local-e2e-orchestrator.py': '38cb1d7638bb69aa4000300a75aa3a95cd9cc34f327ebe425e96b4364e2ddfd5',
    'ops/live-e2e/recover_provider.py': '312e8d11295bc1cdac6b116d9fbbb9302f596dde4a379bbf6c8b03cd6bca4068',
    'ops/live-e2e/staging_preflight.py': 'ad48c5483f42cfcc09d49f4f48f79315a298e1df735649ba4b172369fc8ae342',
    'ops/live-e2e/staging_diagnostics.py': '79d1c8bbc54503d3a3ae6d6b14e821d18fc2a498534cb9ae5e5ce83431116a6a',
    'ops/live-e2e/dispose_historical_residuals.py': 'b95f9eb41803c8b0c7c8c14d64ac421285dcd3829b6be5630886e455c6088365',
    '.github/workflows/ci.yml': '6404f2669e8cc7aa7d590aef800f9326e5c59d30e51162d90eb7f5d92ab3353b',
    '.github/workflows/live-local-e2e.yml': 'ce35810c277f83272b230ae3c54b84dbe9edd2f3da8931e70e1be8a7eb57f643',
    '.github/workflows/live-local-e2e-recovery.yml': 'be9bd60aa89a3f02072fc9ed67626bdb7bc08249496de1d00873aae940cd78a3',
}


def load_module(file='protected_staging.py'):
    name = '_som_dormant_test'
    spec = importlib.util.spec_from_file_location(name, ROOT / 'ops/live-e2e' / file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.mark.parametrize('file', ['protected_staging.py', 'staging_namespace_native.py', 'staging_namespace_types.py'])
def test_module_is_dormant(monkeypatch, file):
    calls = []

    def forbidden(*a, **k):
        calls.append(True)
        pytest.fail('host operation during import')
    for name in ('open', 'stat', 'access', 'scandir', 'mkdir', 'unlink', 'rmdir', 'kill'):
        monkeypatch.setattr(os, name, forbidden)
    load_module(file)
    assert calls == []


@pytest.mark.parametrize('path,expected', FROZEN.items())
def test_existing_authority_and_callers_remain_byte_identical(path, expected):
    assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected


@pytest.fixture
def context(monkeypatch):
    p = load_module()
    env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'zhangyuz/ssh-over-mcp',
           'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_SHA': 'a' * 40}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    account = SimpleNamespace(pw_uid=502, pw_name='gha-e2e-orchestrator',
                              pw_dir='/Users/gha-e2e-orchestrator', pw_gid=20)
    monkeypatch.setattr(p, 'platform', SimpleNamespace(system=lambda: 'Darwin', machine=lambda: 'x86_64'), raising=False)
    monkeypatch.setattr(p, 'pwd', SimpleNamespace(getpwuid=lambda _: account), raising=False)
    monkeypatch.setattr(p, 'grp', SimpleNamespace(getgrnam=lambda _: SimpleNamespace(gr_gid=80)), raising=False)
    for name, value in [('getuid', 502), ('geteuid', 502), ('getgid', 20), ('getegid', 20)]:
        monkeypatch.setattr(os, name, lambda _value=value: _value)
    monkeypatch.setattr(os, 'getgroups', lambda: [21, 20])
    return p, account


@pytest.mark.parametrize('event', ['push', 'workflow_dispatch'])
def test_only_fixed_non_admin_provider_context_is_admitted(context, monkeypatch, event):
    p, _ = context
    monkeypatch.setenv('GITHUB_EVENT_NAME', event)
    value = p._validate_context()
    assert (value.uid, value.euid, value.gid, value.egid, value.groups) == (502, 502, 20, 20, (20, 21))


@pytest.mark.parametrize('key,value', [('GITHUB_ACTIONS', 'false'), ('GITHUB_REPOSITORY', 'fork/ssh-over-mcp'), ('GITHUB_REF', 'refs/pull/1/head'), ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_SHA', 'A' * 40), ('GITHUB_SHA', 'a' * 39)])
def test_context_refuses_unsupported_workflow_before_discovery(context, monkeypatch, key, value):
    p, _ = context
    monkeypatch.setenv(key, value)
    calls = []
    monkeypatch.setattr(p, '_native_module', lambda: calls.append(True))
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'context' and calls == []


@pytest.mark.parametrize('fault', ['real-uid', 'effective-uid', 'real-admin-gid', 'effective-admin-gid', 'admin-group', 'account-uid', 'account-name', 'account-home', 'account-admin-gid', 'architecture', 'platform'])
def test_context_identity_confusion_or_admin_membership_refuses(context, monkeypatch, fault):
    p, account = context
    if fault in ('real-uid', 'effective-uid'):
        monkeypatch.setattr(os, 'getuid' if fault == 'real-uid' else 'geteuid', lambda: 503)
    elif fault in ('real-admin-gid', 'effective-admin-gid'):
        monkeypatch.setattr(os, 'getgid' if fault == 'real-admin-gid' else 'getegid', lambda: 80)
    elif fault == 'admin-group':
        monkeypatch.setattr(os, 'getgroups', lambda: [20, 80])
    elif fault.startswith('account-'):
        field, value = {'account-uid': ('pw_uid', 503), 'account-name': ('pw_name', 'yuz'),
                        'account-home': ('pw_dir', '/other'), 'account-admin-gid': ('pw_gid', 80)}[fault]
        setattr(account, field, value)
    elif fault == 'architecture':
        p.platform.machine = lambda: 'arm64'
    else:
        p.platform.system = lambda: 'Linux'
    with pytest.raises(p.NamespaceError) as error:
        p._validate_context()
    assert error.value.reason == 'context'


def test_dormant_documentation_matches_delivered_scope():
    evidence = ROOT / 'docs/evidence/2026-10-13-protected-staging-health-inspection.md'
    assert evidence.is_file()
    text = evidence.read_text()
    assert 'implemented dormant' in text and 'not protected-placement acceptance' in text
    for path in ('docs/decisions/0019-protected-native-e2e-staging.md',
                 'docs/superpowers/specs/2026-10-13-protected-native-e2e-staging-design.md',
                 'docs/development-plan.md'):
        assert '2026-10-13-protected-staging-health-inspection.md' in (ROOT / path).read_text()
