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


def _fixture_library(tmp_path):
    lib = tmp_path / "Library"
    lib.mkdir(mode=0o700)
    fd = os.open(lib, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    return lib, fd


def test_fixture_exclusive_claim_required_before_first_descendant_mkdir(tmp_path):
    module = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        preexisting = library / ".adr19-disposable-claim"
        preexisting.write_text("pretend claim owned by current PID")
        with pytest.raises(module.NamespaceError):
            module._claim_disposable_fixture(fd)
        assert not (library / "Application Support").exists()
    finally:
        os.close(fd)


def test_fixture_fixed_descendants_mode_acl_and_unique_run_child(tmp_path):
    module = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        permit = module._claim_disposable_fixture(fd)
        workspace = module._create_for_fixture(permit)
        assert workspace.name.startswith("ssh-over-mcp-e2e-")
        assert len(workspace.name) == len("ssh-over-mcp-e2e-") + 32
        assert all(c in "0123456789abcdef" for c in workspace.name[len("ssh-over-mcp-e2e-"):])
        path = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
        assert path.is_dir()
        assert path.stat().st_ino == workspace.root_identity[1]
        assert path.stat().st_dev == workspace.root_identity[0]
        for ancestor in (path.parent, path.parent.parent, path.parent.parent.parent, path):
            assert (ancestor.stat().st_mode & 0o777) == 0o700
        with pytest.raises(module.NamespaceError):
            module._create_for_fixture(permit)
        workspace.close()
    finally:
        os.close(fd)


def test_postcreate_exact_original_child_only(tmp_path):
    module = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = module._create_for_fixture(module._claim_disposable_fixture(fd))
        workspace.verify_single_owned_child()
        staging = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1"
        (staging / "foreign-entry").write_text("foreign")
        with pytest.raises(module.NamespaceError):
            workspace.verify_single_owned_child()
        workspace.close()
    finally:
        os.close(fd)


def test_interleaved_foreign_mkdir_refuses(tmp_path, monkeypatch):
    module = load_module()
    library, fd = _fixture_library(tmp_path)
    original_mkdir = os.mkdir
    try:
        permit = module._claim_disposable_fixture(fd)
        triggered = False

        def interleave(name, *args, **kwargs):
            nonlocal triggered
            if name == "Application Support" and not triggered:
                triggered = True
                original_mkdir("foreign-entry", mode=0o700, dir_fd=kwargs["dir_fd"])
            return original_mkdir(name, *args, **kwargs)

        monkeypatch.setattr(os, "mkdir", interleave)
        with pytest.raises(module.NamespaceError):
            module._create_for_fixture(permit)
        assert triggered
        assert (library / "foreign-entry").exists()
    finally:
        os.close(fd)
