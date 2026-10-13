from __future__ import annotations

import importlib.util
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from time import monotonic

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load():
    path = ROOT / "ops/live-e2e/dispose_historical_residuals.py"
    assert path.exists(), "approved guarded disposition implementation is missing"
    spec = importlib.util.spec_from_file_location("incident_disposal", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def incident(tmp_path):
    module = load()
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    (root / "a").mkdir(mode=0o700)
    (root / "a/deep").mkdir(mode=0o700)
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    with ExitStack() as stack:
        fds = []
        for p in (tmp_path, root, cache):
            fd = os.open(p, module.DIR_FLAGS)
            stack.callback(os.close, fd)
            fds.append(fd)
        parent_fd, root_fd, cache_fd = fds
        entries = module.observer._collect_special_metadata(root_fd, uid=os.geteuid())
        yield module, root, parent_fd, root_fd, cache_fd, entries


def journal(module, cache_fd):
    return module.Journal(cache_fd, {"fixture": True})


def remove(data, sink, check=lambda: None):
    module, _, parent_fd, root_fd, _, entries = data
    module._remove_root(parent_fd, "root", root_fd, entries, sink,
                        check=check, deadline=monotonic() + 30)


def test_bottom_up_disposal_preserves_symlink_destination(incident, tmp_path):
    module, root, _, root_fd, cache_fd, _ = incident
    target = tmp_path / "outside"
    target.write_bytes(b"keep this payload")
    (root / "a/link").symlink_to(target)
    entries = module.observer._collect_special_metadata(root_fd, uid=os.geteuid())
    data = (*incident[:-1], entries)
    with journal(module, cache_fd) as sink:
        remove(data, sink)
    assert not root.exists()
    assert target.read_bytes() == b"keep this payload"
    records = [json.loads(l) for l in (tmp_path / "cache" / module.JOURNAL_NAME).read_text().splitlines()]
    assert [r["event"] for r in records].count("intent") == 4
    assert [r["event"] for r in records].count("confirmed") == 4
    assert records[0]["event"] == "begin"


@pytest.mark.parametrize("kind", ["extra-directory", "regular", "fifo", "replaced-directory"])
def test_changed_inventory_refuses_before_any_removal(incident, kind, tmp_path):
    module, root, _, _, cache_fd, _ = incident
    if kind == "extra-directory":
        (root / "new").mkdir(mode=0o700)
    elif kind == "regular":
        (root / "payload").write_bytes(b"never delete")
    elif kind == "fifo":
        os.mkfifo(root / "fifo", 0o600)
    else:
        (root / "a/deep").rmdir()
        (root / "a/deep").symlink_to(tmp_path)
    with journal(module, cache_fd) as sink, pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
        remove(incident, sink)
    assert root.exists()
    assert (root / "a").exists()


def test_no_follow_directory_to_link_swap_is_refused(incident, tmp_path):
    module, root, _, _, cache_fd, _ = incident
    called = False

    def swap():
        nonlocal called
        if not called:
            called = True
            (root / "a/deep").rmdir()
            (root / "a").rmdir()
            (root / "a").symlink_to(tmp_path)

    with journal(module, cache_fd) as sink, pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
        remove(incident, sink, check=swap)
    assert (root / "a").is_symlink()
    assert (tmp_path / "cache").is_dir()


@pytest.mark.parametrize("failure", ["intent-sync", "parent-sync", "confirmation-sync"])
def test_sync_failure_preserves_explicit_unknown_result(incident, monkeypatch, tmp_path, failure):
    module, root, _, _, cache_fd, _ = incident
    with journal(module, cache_fd) as sink:
        original_append = sink.append
        original_sync = module._sync_directory

        def append(event):
            if failure == "intent-sync" and event["event"] == "intent":
                raise OSError("test intended intent failure")
            if failure == "confirmation-sync" and event["event"] == "confirmed":
                raise OSError("test intended confirmation failure")
            original_append(event)

        def sync(fd):
            if failure == "parent-sync":
                raise OSError("test intended directory failure")
            original_sync(fd)

        monkeypatch.setattr(sink, "append", append)
        monkeypatch.setattr(module, "_sync_directory", sync)
        with pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
            remove(incident, sink)
    assert root.exists()
    assert (root / "a").exists()
    events = [json.loads(l)["event"] for l in (tmp_path / "cache" / module.JOURNAL_NAME).read_text().splitlines()]
    assert "confirmed" not in events
    assert (root / "a/deep").exists() == (failure == "intent-sync")


def test_journal_initial_sync_failure_cannot_remove_anything(incident, monkeypatch):
    module, root, _, _, cache_fd, _ = incident

    def fail(fd):
        raise OSError("fixture fsync failure")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
        journal(module, cache_fd)
    assert (root / "a/deep").is_dir()


def test_existing_journal_blocks_replay(incident):
    module, root, _, _, cache_fd, _ = incident
    with journal(module, cache_fd):
        pass
    with pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
        journal(module, cache_fd)
    assert (root / "a/deep").is_dir()


def test_deadline_and_journal_budget_are_fail_closed(incident, monkeypatch):
    module, root, parent_fd, root_fd, cache_fd, entries = incident
    with journal(module, cache_fd) as sink:
        with pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
            module._remove_root(parent_fd, "root", root_fd, entries, sink,
                                check=lambda: None, deadline=monotonic() - 1)
        monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 1)
        with pytest.raises((module.DispositionError, module.preflight.PreflightError, OSError)):
            remove(incident, sink)
    assert (root / "a/deep").is_dir()


def test_entry_digest_pins_full_metadata(incident):
    module, _, _, _, _, entries = incident
    changed = [dict(e) for e in entries]
    changed[0]["ctime_ns"] += 1
    assert module._digest(entries) != module._digest(changed)


def test_arbitrary_cli_path_is_refused(monkeypatch):
    module = load()
    monkeypatch.setattr(module, "_validate_context", lambda: pytest.fail("must reject args first"))
    with pytest.raises(module.DispositionError):
        module.main(["/private/tmp/arbitrary"])


def test_wrong_workflow_context_is_refused(monkeypatch):
    module = load()
    monkeypatch.setattr(module.recovery, "_validate_context", lambda env: None)
    monkeypatch.setattr(module.os, "geteuid", lambda: 502)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_WORKFLOW_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "zhangyuz/ssh-over-mcp/.github/workflows/other.yml@refs/heads/main")
    with pytest.raises(module.DispositionError):
        module._validate_context()


def test_workflow_only_manual_trusted_main_fixed_apply():
    p = ROOT / ".github/workflows/live-local-e2e-dispose-historical.yml"
    assert p.exists(), "separate incident workflow missing"
    text = p.read_text()
    assert "workflow_dispatch:" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "group: live-local-e2e" in text and "cancel-in-progress: false" in text
    assert "--apply" in text and "boolean" in text and "default: false" in text
    assert "sudo" not in text and "pull_request:" not in text
    assert "persist-credentials: false" in text
    assert "contents: read" in text


@pytest.fixture
def composition(incident, monkeypatch, tmp_path):
    from contextlib import contextmanager
    from dataclasses import asdict
    from types import SimpleNamespace

    module, root, parent_fd, _, cache_fd, entries = incident
    marker_path = tmp_path / "cache/active-run.json"
    marker_path.write_text('{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}\n')
    marker_path.chmod(0o600)
    uid = os.geteuid()
    marker = module.preflight._read_marker(cache_fd, uid=uid)

    @contextmanager
    def chain(fd):
        yield SimpleNamespace(_fds=(fd,), revalidate=lambda: None)

    monkeypatch.setattr(module, "UID", uid)
    monkeypatch.setattr(module, "DEVICE", os.fstat(parent_fd).st_dev)
    monkeypatch.setattr(module, "MARKER_META", asdict(marker.metadata))
    monkeypatch.setattr(module, "CATALOG", (("root", root.stat().st_ino, len(entries), module._digest(entries)),))
    monkeypatch.setattr(module, "_validate_context", lambda: {"fixture": True})
    monkeypatch.setattr(module, "_maintenance_window", lambda: None)
    monkeypatch.setattr(module.observer.private_tmp, "_pin_private_tmp", lambda: chain(parent_fd))
    monkeypatch.setattr(module.preflight, "_pin_observed_fixed_cache_chain", lambda: chain(cache_fd))
    monkeypatch.setattr(module.preflight, "_observe_fixed_process_snapshot_checked", lambda: None)
    monkeypatch.setattr(module.preflight, "_require_fixed_marker_owner_absent", lambda: None)
    return module, root, marker_path


def test_inspect_only_creates_no_journal_or_removes_nodes(composition, tmp_path):
    module, root, marker = composition
    original_marker = marker.read_bytes()
    module.dispose(apply=False)
    assert (root / "a/deep").exists()
    assert marker.read_bytes() == original_marker
    assert not (tmp_path / "cache" / module.JOURNAL_NAME).exists()


def test_full_apply_keeps_marker_and_writes_complete_journal(composition, tmp_path):
    module, root, marker = composition
    original_marker = marker.read_bytes()
    module.dispose(apply=True)
    assert not root.exists()
    assert marker.read_bytes() == original_marker
    records = [json.loads(l) for l in (tmp_path / "cache" / module.JOURNAL_NAME).read_text().splitlines()]
    assert records[-1]["event"] == "complete"
    assert records[-1]["marker_preserved"] is True


@pytest.mark.parametrize("failure", ["owner", "qemu", "marker", "second-root"])
def test_composition_gates_fail_before_journal_and_mutation(composition, tmp_path, monkeypatch, failure):
    module, root, marker = composition

    def refuse():
        raise module.preflight.PreflightError()

    if failure == "owner":
        monkeypatch.setattr(module.preflight, "_require_fixed_marker_owner_absent", refuse)
    elif failure == "qemu":
        monkeypatch.setattr(module.preflight, "_observe_fixed_process_snapshot_checked", refuse)
    elif failure == "marker":
        marker.write_text('{"target":"0000000000000000000000000000000000000000","owner_pid":38013}\n')
    else:
        second = tmp_path / "other"
        second.mkdir(mode=0o700)
        monkeypatch.setattr(module, "CATALOG", module.CATALOG + (
            ("other", second.stat().st_ino, 1, "0" * 64),))
    with pytest.raises((module.DispositionError, module.preflight.PreflightError)):
        module.dispose(apply=True)
    assert (root / "a/deep").exists()
    assert not (tmp_path / "cache" / module.JOURNAL_NAME).exists()


@pytest.mark.parametrize("swap", ["root", "ancestor"])
def test_intent_time_namespace_swap_refuses_before_leaf_removal(incident, tmp_path, monkeypatch, swap):
    module, root, _, _, cache_fd, _ = incident
    with journal(module, cache_fd) as sink:
        original = sink.append
        detached = tmp_path / "detached"

        def append(event):
            original(event)
            if event["event"] == "intent":
                if swap == "root":
                    root.rename(detached)
                    root.mkdir(mode=0o700)
                else:
                    (root / "a").rename(detached)
                    (root / "a").mkdir(mode=0o700)

        monkeypatch.setattr(sink, "append", append)
        with pytest.raises(module.DispositionError):
            remove(incident, sink)
    preserved = detached / ("a/deep" if swap == "root" else "deep")
    assert preserved.exists(), "a detached namespace must never be mutated"


def test_inspection_rechecks_catalog_edges_after_process_snapshot(composition, tmp_path, monkeypatch):
    module, root, _ = composition
    calls = 0

    def snapshot():
        nonlocal calls
        calls += 1
        if calls == 2:
            root.rename(tmp_path / "detached")
            root.mkdir(mode=0o700)

    monkeypatch.setattr(module.preflight, "_observe_fixed_process_snapshot_checked", snapshot)
    with pytest.raises(module.DispositionError):
        module.dispose(apply=False)
    assert (tmp_path / "detached/a/deep").is_dir()


@pytest.mark.parametrize("phase", ["intent", "parent", "confirmation"])
def test_real_fsync_boundary_failure_stops_without_complete(incident, monkeypatch, tmp_path, phase):
    module, root, _, _, cache_fd, _ = incident
    with journal(module, cache_fd) as sink:
        original = os.fsync
        journal_calls = 0

        def fsync(fd):
            nonlocal journal_calls
            if fd == sink.fd:
                journal_calls += 1
                if (phase == "intent" and journal_calls == 1) or (phase == "confirmation" and journal_calls == 2):
                    raise OSError("injected journal fsync failure")
            elif phase == "parent":
                raise OSError("injected parent fsync failure")
            original(fd)

        monkeypatch.setattr(os, "fsync", fsync)
        with pytest.raises(OSError):
            remove(incident, sink)
    assert root.is_dir()
    assert (root / "a").is_dir()
    assert (root / "a/deep").exists() == (phase == "intent")
    events = [json.loads(l)["event"] for l in (tmp_path / "cache" / module.JOURNAL_NAME).read_text().splitlines()]
    assert "complete" not in events


def test_real_write_failure_and_journal_close_uncertainty(incident, monkeypatch):
    module, root, _, _, cache_fd, _ = incident
    with journal(module, cache_fd) as sink:
        original_write = os.write

        def write(fd, data):
            if fd == sink.fd:
                raise OSError("injected write failure")
            return original_write(fd, data)

        monkeypatch.setattr(os, "write", write)
        with pytest.raises(OSError):
            remove(incident, sink)
    assert (root / "a/deep").is_dir()

    # Close is attempted exactly once, and its uncertainty is propagated.
    fd = os.open(root, module.DIR_FLAGS)
    sink = object.__new__(module.Journal)
    sink.fd = fd
    real_close = os.close
    calls = []

    def close(target):
        calls.append(target)
        real_close(target)
        raise OSError("injected close uncertainty")

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "close", close)
        with pytest.raises(OSError):
            sink.close()
        sink.close()
    assert calls == [fd]


@pytest.mark.parametrize("after_removal", [False, True])
def test_process_crash_journal_prevents_automatic_resume(incident, tmp_path, after_removal):
    module, root, _, _, cache_fd, _ = incident
    pid = os.fork()
    if pid == 0:
        try:
            with journal(module, cache_fd) as sink:
                count = 0

                def check():
                    nonlocal count
                    count += 1
                    if not after_removal and count == 2:
                        os._exit(77)

                if after_removal:
                    original = module._sync_directory

                    def stop(fd):
                        original(fd)
                        os._exit(77)

                    module._sync_directory = stop
                remove(incident, sink, check=check)
        finally:
            os._exit(99)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    assert root.is_dir()
    assert (root / "a/deep").exists() == (not after_removal)
    events = [json.loads(l)["event"] for l in (tmp_path / "cache" / module.JOURNAL_NAME).read_text().splitlines()]
    assert events == ["begin", "intent"]
    with pytest.raises(FileExistsError):
        journal(module, cache_fd)


def test_real_incident_size_and_depth_dispose_with_bounded_journal(incident, tmp_path, monkeypatch):
    module, root, parent_fd, root_fd, cache_fd, _ = incident
    # Native authority runs on macOS. Model stable metadata on Linux strictatime:
    # owner-permitted O_NOATIME prevents our own directory reads changing atime.
    # No identity/mtime/ctime/mode observation or refusal is mocked or relaxed.
    if sys.platform == "linux":
        import fcntl

        flags = fcntl.fcntl(root_fd, fcntl.F_GETFL)
        fcntl.fcntl(root_fd, fcntl.F_SETFL, flags | os.O_NOATIME)
        monkeypatch.setattr(module.observer, "_DIR_FLAGS", module.DIR_FLAGS | os.O_NOATIME)
    deep = root / "a/deep"
    chain = deep
    for index in range(11):
        chain = chain / f"chain{index}"
        chain.mkdir(mode=0o700)
    for index in range(1312):
        (deep / f"leaf{index:04d}").mkdir(mode=0o700)
    outside = tmp_path / "canary"
    outside.write_bytes(b"destination remains")
    for index in range(6):
        (deep / f"link{index}").symlink_to(outside)
    entries = module.observer._collect_special_metadata(root_fd, uid=os.geteuid())
    assert len(entries) == 1332
    assert max(len(e["path"].split("/")) for e in entries) == 13
    with journal(module, cache_fd) as sink:
        module._remove_root(parent_fd, "root", root_fd, entries, sink,
                            check=lambda: None, deadline=monotonic() + module.MAX_SECONDS)
    assert not root.exists()
    assert outside.read_bytes() == b"destination remains"
    path = tmp_path / "cache" / module.JOURNAL_NAME
    assert path.stat().st_size < module.MAX_JOURNAL_BYTES
    events = [json.loads(l)["event"] for l in path.read_text().splitlines()]
    assert events.count("confirmed") == 1332


def test_journal_name_replacement_refuses_before_intention_and_mutation(incident, tmp_path):
    module, root, _, _, cache_fd, _ = incident
    with journal(module, cache_fd) as sink:
        path = tmp_path / "cache" / module.JOURNAL_NAME
        path.rename(tmp_path / "detached-journal")
        path.write_text("replacement must not receive journal writes")
        path.chmod(0o600)
        with pytest.raises(module.DispositionError):
            remove(incident, sink)
    assert (root / "a/deep").is_dir()
    assert path.read_text() == "replacement must not receive journal writes"
