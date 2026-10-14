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


def test_fixture_original_root_only_cleanup(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        staging = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1"
        target = staging / workspace.name
        (target / "nested").mkdir(mode=0o700)
        (target / "nested" / "test.txt").write_text("fixture-only")
        receipt = m._fixture_never_started_receipt(workspace)
        m._dispose_never_started_fixture(workspace, receipt)
        assert not target.exists()
        assert list(staging.iterdir()) == []
        assert (library / ".adr19-disposable-claim").exists()
    finally:
        os.close(fd)


def test_bool_and_foreign_receipt_never_delete(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        staging = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1"
        for invalid in (True, None, object(), {"reaped": True}):
            with pytest.raises(m.NamespaceError):
                m._dispose_never_started_fixture(workspace, invalid)
        with pytest.raises(m.NamespaceError):
            m.OwnedWorkspace.__new__(m.OwnedWorkspace).dispose(True)
        assert (staging / workspace.name).is_dir()
        workspace.close()
    finally:
        os.close(fd)


def test_original_run_root_swap_refuses(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        staging = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1"
        (staging / workspace.name).rename(staging / (workspace.name + "-moved"))
        (staging / workspace.name).symlink_to(outside, target_is_directory=True)
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, m._fixture_never_started_receipt(workspace))
        assert (outside / "keep.txt").read_text() == "keep"
        assert (staging / (workspace.name + "-moved")).is_dir()
        workspace.close()
    finally:
        os.close(fd)


def test_nested_symlink_target_preserved(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    outside = tmp_path / "untouched"
    outside.mkdir()
    (outside / "keep").write_text("safe")
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        root = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
        (root / "link").symlink_to(outside, target_is_directory=True)
        m._dispose_never_started_fixture(workspace, m._fixture_never_started_receipt(workspace))
        assert (outside / "keep").read_text() == "safe"
        assert not root.exists()
    finally:
        os.close(fd)


def test_uncertain_unlink_never_clears_marker(tmp_path, monkeypatch):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        root = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
        (root / "fixture-file").write_text("present")
        receipt = m._fixture_never_started_receipt(workspace)
        calls = []
        original_unlink = os.unlink

        def fail_once(*args, **kwargs):
            calls.append(args)
            raise OSError("refuse only this unlink")

        monkeypatch.setattr(os, "unlink", fail_once)
        with pytest.raises(m.NamespaceError) as exc:
            m._dispose_never_started_fixture(workspace, receipt)
        assert exc.value.cleanup_uncertain is True
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, receipt)
        assert len(calls) == 1
        monkeypatch.setattr(os, "unlink", original_unlink)
        assert (library / ".adr19-disposable-claim").exists()
        assert (root / "fixture-file").exists()
        workspace.close()
    finally:
        os.close(fd)


def test_lost_root_fd_refuses(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        root_fd = workspace._root_fd
        os.close(root_fd)
        workspace._root_fd = -1
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, m._fixture_never_started_receipt(workspace))
        assert (library / ".adr19-disposable-claim").exists()
        workspace.close()
    finally:
        os.close(fd)


def test_finalizer_closes_only_no_unlink(tmp_path, monkeypatch):
    import gc

    m = load_module()
    library, fd = _fixture_library(tmp_path)
    workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
    root = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
    calls = []
    monkeypatch.setattr(os, "unlink", lambda *a, **kw: calls.append(("unlink", a)))
    monkeypatch.setattr(os, "rmdir", lambda *a, **kw: calls.append(("rmdir", a)))
    del workspace
    gc.collect()
    assert calls == []
    assert root.is_dir()
    assert (library / ".adr19-disposable-claim").is_file()
    os.close(fd)


def test_fixture_cross_workspace_receipt_is_not_transferable(tmp_path):
    m = load_module()
    (tmp_path / "a").mkdir(mode=0o700)
    (tmp_path / "b").mkdir(mode=0o700)
    _la, fd_a = _fixture_library(tmp_path / "a")
    lb, fd_b = _fixture_library(tmp_path / "b")
    try:
        a = m._create_for_fixture(m._claim_disposable_fixture(fd_a))
        b = m._create_for_fixture(m._claim_disposable_fixture(fd_b))
        receipt_a = m._fixture_never_started_receipt(a)
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(b, receipt_a)
        assert (lb / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / b.name).is_dir()
        m._dispose_never_started_fixture(a, receipt_a)
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(a, receipt_a)
        b.close()
    finally:
        os.close(fd_a)
        os.close(fd_b)


def test_close_error_fails_uncertain_without_any_delete(tmp_path, monkeypatch):
    m = load_module()
    lib, fd = _fixture_library(tmp_path)
    workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
    target_fd = workspace._root_fd
    original_close = os.close
    calls = []
    one = [True]

    def fail_on_root(child_fd):
        if child_fd == target_fd and one[0]:
            one[0] = False
            calls.append("close_failed")
            raise OSError("could have closed")
        return original_close(child_fd)

    monkeypatch.setattr(os, "close", fail_on_root)
    try:
        with pytest.raises(m.NamespaceError) as exc:
            workspace.close()
        assert exc.value.cleanup_uncertain is True
        assert workspace._cleanup_state == "uncertain"
        assert calls == ["close_failed"]
        root = lib / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
        assert root.exists()
    finally:
        monkeypatch.setattr(os, "close", original_close)
        original_close(fd)


def test_missing_original_root_refuses_without_retry(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        root = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
        root.rmdir()  # disposable fixture only; simulates foreign disappearance
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, m._fixture_never_started_receipt(workspace))
        assert (library / ".adr19-disposable-claim").exists()
        workspace.close()
    finally:
        os.close(fd)


def test_failed_fixture_claim_closes_descriptors_and_preserves_evidence(tmp_path, monkeypatch):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    original_open = os.open
    observed = []

    def track_open(name, *args, **kwargs):
        result = original_open(name, *args, **kwargs)
        if name == ".adr19-disposable-claim":
            observed.append(result)
        return result

    def fail_fsync(_fd):
        raise OSError("simulated fsync failure after exclusive claim")

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "fsync", fail_fsync)
    try:
        with pytest.raises(m.NamespaceError):
            m._claim_disposable_fixture(fd)
        assert len(observed) == 1
        with pytest.raises(OSError):
            os.fstat(observed[0])  # failed claim must NOT leak a raw FD
        assert (library / ".adr19-disposable-claim").is_file()
        assert not (library / "Application Support").exists()
    finally:
        os.close(fd)


def test_owned_scan_rechecks_staging_acl_before_deletion(tmp_path, monkeypatch):
    m = load_module()
    _library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        original = m._validate_private_dir
        checked = []

        def check_acl(fd_value):
            checked.append(fd_value)
            return original(fd_value)

        monkeypatch.setattr(m, "_validate_private_dir", check_acl)
        workspace.verify_single_owned_child()
        assert workspace._staging_fd in checked
        workspace.close()
    finally:
        os.close(fd)


def test_postcreate_claim_marker_swap_refuses_owned_cleanup(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        original = library / ".adr19-disposable-claim"
        original.rename(library / ".adr19-disposable-claim-moved")
        original.write_text("forged same-looking claim")
        staging = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1"
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, m._fixture_never_started_receipt(workspace))
        assert (staging / workspace.name).is_dir()
        workspace.close()
    finally:
        os.close(fd)


def test_postcreate_original_ancestor_substitution_refuses(tmp_path):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        app = library / "Application Support"
        app.rename(library / "Application Support-moved")
        app.mkdir(mode=0o700)
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, m._fixture_never_started_receipt(workspace))
        old = library / "Application Support-moved" / "ssh-over-mcp-e2e" / "staging-v1"
        assert (old / workspace.name).is_dir()
        workspace.close()
    finally:
        os.close(fd)


def test_validation_failure_after_child_open_closes_all_owned_fds(tmp_path, monkeypatch):
    m = load_module()
    _library, fd = _fixture_library(tmp_path)
    permit = m._claim_disposable_fixture(fd)
    original_open, original_validate = os.open, m._validate_private_dir
    child_fds = []
    count = [0]

    def track_open(name, *args, **kwargs):
        result = original_open(name, *args, **kwargs)
        if name == "Application Support":
            child_fds.append(result)
        return result

    def fail_after_open(child_fd):
        count[0] += 1
        if count[0] == 2:
            raise m.NamespaceError("namespace")
        return original_validate(child_fd)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(m, "_validate_private_dir", fail_after_open)
    try:
        with pytest.raises(m.NamespaceError):
            m._create_for_fixture(permit)
        assert len(child_fds) == 1
        for owned_fd in (*child_fds, permit.library_fd, permit.claim_fd):
            with pytest.raises(OSError):
                os.fstat(owned_fd)
    finally:
        os.close(fd)


def test_verification_failure_after_handle_created_closes_all_fds(tmp_path, monkeypatch):
    m = load_module()
    _library, fd = _fixture_library(tmp_path)
    permit = m._claim_disposable_fixture(fd)
    raw_fds = []
    original_init = m._FixtureOwnedWorkspace.__init__

    def remember_handle(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        raw_fds.extend([self._root_fd, self._staging_fd, self._permit.claim_fd,
                        self._permit.library_fd])

    def refuse(_self):
        raise m.NamespaceError("drift")

    monkeypatch.setattr(m._FixtureOwnedWorkspace, "__init__", remember_handle)
    monkeypatch.setattr(m._FixtureOwnedWorkspace, "verify_single_owned_child", refuse)
    try:
        with pytest.raises(m.NamespaceError):
            m._create_for_fixture(permit)
        assert len(raw_fds) == 4
        for owned_fd in raw_fds:
            with pytest.raises(OSError):
                os.fstat(owned_fd)
    finally:
        os.close(fd)


def test_large_fixture_tree_refuses_with_early_bounded_scan(tmp_path, monkeypatch):
    m = load_module()
    library, fd = _fixture_library(tmp_path)
    original_scandir = os.scandir
    try:
        workspace = m._create_for_fixture(m._claim_disposable_fixture(fd))
        root = library / "Application Support" / "ssh-over-mcp-e2e" / "staging-v1" / workspace.name
        for index in range(140):
            (root / f"fixture-{index:03}").write_text("keep")
        receipt = m._fixture_never_started_receipt(workspace)
        consumed = [0]
        class CountedScan:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                self.stream.__enter__()
                return self
            def __exit__(self, *a):
                return self.stream.__exit__(*a)
            def __iter__(self):
                return self
            def __next__(self):
                record = next(self.stream)
                consumed[0] += 1
                assert consumed[0] <= 129, "unbounded directory consumption"
                return record
        def count_scan(target):
            stream = original_scandir(target)
            try:
                match = os.fstat(target).st_ino == workspace.root_identity[1]
            except (OSError, TypeError):
                match = False
            return CountedScan(stream) if match else stream
        monkeypatch.setattr(os, "scandir", count_scan)
        with pytest.raises(m.NamespaceError):
            m._dispose_never_started_fixture(workspace, receipt)
        assert consumed[0] == 129
        assert len(list(root.iterdir())) == 140
        workspace.close()
    finally:
        os.close(fd)


def test_claim_close_error_closes_other_owned_fd_without_retry(tmp_path, monkeypatch):
    m = load_module()
    _library, fd = _fixture_library(tmp_path)
    permit = m._claim_disposable_fixture(fd)
    original_close = os.close
    captured_library, captured_claim = permit.library_fd, permit.claim_fd
    calls = []

    def fail_claim_once(raw_fd):
        calls.append(raw_fd)
        if raw_fd == captured_claim:
            raise OSError("unknown close outcome")
        return original_close(raw_fd)

    monkeypatch.setattr(os, "close", fail_claim_once)
    try:
        with pytest.raises(m.NamespaceError) as exc:
            permit.close()
        assert exc.value.cleanup_uncertain is True
        assert calls.count(captured_claim) == 1
        assert calls.count(captured_library) == 1
        with pytest.raises(OSError):
            os.fstat(captured_library)
        assert permit.claim_fd == -1
        assert permit.library_fd == -1
    finally:
        monkeypatch.setattr(os, "close", original_close)
        # A fixture injected a failure *before* closing this FD; the test
        # harness, not production, owns its teardown.
        original_close(captured_claim)
        original_close(fd)
