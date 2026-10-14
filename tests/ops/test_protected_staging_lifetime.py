"""ADR 0019 Slice 2A: dormant, non-authorizing workspace primitives."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_owned_lifetime.py"


def load_module():
    name = "_som_staging_owned_lifetime_test"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    sys.path.insert(0, str(MODULE.parent))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_unbound_entrypoint_and_helper_never_mkdir(monkeypatch):
    module = load_module()
    calls = []
    monkeypatch.setattr(os, "mkdir", lambda *a, **kw: calls.append((a, kw)))
    with pytest.raises(module.NamespaceError) as exc:
        module.create_owned_workspace()
    assert exc.value.reason == "unbound"
    assert calls == []
    assert not hasattr(module, "claim_live_marker")


def test_preexisting_marker_same_pid_never_grants_permit(tmp_path, monkeypatch):
    module = load_module()
    marker = tmp_path / "active-run.json"
    marker.write_text('{"target":"' + "a" * 40 + '","owner_pid":' + str(os.getpid()) + "}")
    calls = []
    monkeypatch.setattr(os, "mkdir", lambda *a, **kw: calls.append((a, kw)))
    with pytest.raises(module.NamespaceError) as exc:
        module.create_owned_workspace()
    assert exc.value.reason == "unbound"
    assert calls == []


@pytest.mark.parametrize("claimed", [True, False, None, object()])
def test_no_claimed_bool_or_path_override(claimed, tmp_path):
    module = load_module()
    with pytest.raises(TypeError):
        module.create_owned_workspace(claimed=claimed)
    with pytest.raises(TypeError):
        module.create_owned_workspace(root=tmp_path)


def test_all_startup_blockers_precede_mkdir(monkeypatch):
    module = load_module()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "zhangyuz/ssh-over-mcp")
    for event in ("push", "workflow_dispatch", "workflow_run"):
        monkeypatch.setenv("GITHUB_EVENT_NAME", event)
        calls = []
        monkeypatch.setattr(os, "mkdir", lambda *a, _calls=calls, **kw: _calls.append(1))
        with pytest.raises(module.NamespaceError) as exc:
            module.create_owned_workspace()
        assert exc.value.reason == "unbound"
        assert not calls
