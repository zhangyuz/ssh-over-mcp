"""RED/GREEN: fixed getconf-derived temp ancestry, private and not activated."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_preflight.py"
PROCESS_MODULE = ROOT / "ops/live-e2e/staging_process_metadata.py"
PARTS = ("private", "var", "folders", "ab", "runner_123", "T")


def _load(file: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def env(tmp_path, monkeypatch):
    preflight = _load(MODULE, "_som_native_temp_binding")
    process = _load(PROCESS_MODULE, "_som_native_temp_process")
    root = tmp_path / "fixture_root"
    root.mkdir(mode=0o700)
    cursor = root
    for part in PARTS:
        cursor /= part
        cursor.mkdir(mode=0o700)
    events = []
    monkeypatch.setattr(preflight, "_TEMP_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_TEMP_ACCOUNT_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_fixed_process_metadata_module", lambda: process)
    parent = process.TempParent(
        "/var/folders/ab/runner_123/T/",
        "/private/var/folders/ab/runner_123/T/",
    )

    def getconf():
        events.append("getconf")
        return parent

    def native_root():
        events.append("root")
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    monkeypatch.setattr(preflight, "_observe_fixed_temp_parent", getconf)
    monkeypatch.setattr(preflight, "_open_fixed_native_root", native_root)
    monkeypatch.setattr(
        preflight, "_stat_fixed_native_root", lambda: preflight._metadata(os.stat(root))
    )
    return preflight, process, root, cursor, events


def test_fixed_getconf_precedes_open_and_pins_chain(env):
    p, _, root, leaf, events = env
    with p._pin_observed_native_temp_chain() as chain:
        assert events == ["getconf", "root"]
        assert chain._parts == PARTS
        assert len(chain.metadata) == 6
        assert chain.metadata[-1].inode == leaf.stat().st_ino
        assert chain.metadata[-1].uid == os.geteuid()
        chain.revalidate()
    assert (root / "private").is_dir()


def test_cannot_supply_root_fd_parent_or_path(env):
    import inspect

    p, *_ = env
    assert len(inspect.signature(p._pin_observed_native_temp_chain).parameters) == 0
    assert len(inspect.signature(p._open_fixed_native_root).parameters) == 0
    with pytest.raises(TypeError):
        p._pin_observed_native_temp_chain("/untrusted")


@pytest.mark.parametrize(
    "native,canonical",
    [
        ("/var/folders/ab/runner_123/T/", "/var/folders/ab/runner_123/T/"),
        ("/var/folders/ab/runner_123/T/", "/private/var/folders/zz/wrong/T/"),
        ("/var/folders/ab/runner_123/T/", "/private/var/folders/ab/../T/"),
        ("/tmp/ab/runner_123/T/", "/private/tmp/ab/runner_123/T/"),
        ("/var/folders/a/runner_123/T/", "/private/var/folders/a/runner_123/T/"),
        ("/var/folders/ab/UPPER/T/", "/private/var/folders/ab/UPPER/T/"),
        ("/var/folders/ab/runner_123/T/", "/private/var/folders/ab/runner_123/T/extra/"),
    ],
)
def test_untrusted_temp_parent_refuses_before_root_open(env, monkeypatch, native, canonical):
    p, process, _, _, events = env
    monkeypatch.setattr(
        p, "_observe_fixed_temp_parent", lambda: process.TempParent(native, canonical)
    )
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$"),
        p._pin_observed_native_temp_chain(),
    ):
        pytest.fail("accepted malformed temp parent")
    assert events == []


def test_fixed_temp_parent_failure_refuses_before_root_open(env, monkeypatch):
    p, _, _, _, events = env

    def fail():
        raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_observe_fixed_temp_parent", fail)
    with pytest.raises(p.PreflightError) as err, p._pin_observed_native_temp_chain():
        pytest.fail("must not yield")
    assert err.value.cleanup_uncertain is True
    assert events == []


@pytest.mark.parametrize("index", range(6))
def test_late_edge_swap_refuses_with_held_fds(env, index):
    p, _, root, _, events = env
    with pytest.raises(p.PreflightError), p._pin_observed_native_temp_chain() as chain:
        edge = root.joinpath(*PARTS[: index + 1])
        edge.rename(edge.with_name(edge.name + "-former"))
        edge.mkdir(mode=0o700)
        assert stat.S_ISDIR(os.fstat(chain._fds[-1]).st_mode)
    assert events == ["getconf", "root"]


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4, 5])
def test_unsafe_temp_modes_refuse(env, index):
    p, _, root, _, _ = env
    root.joinpath(*PARTS[: index + 1]).chmod(0o777)
    with pytest.raises(p.PreflightError), p._pin_observed_native_temp_chain():
        pytest.fail("accepted unsafe edge")


def test_borrowed_fixture_context_owns_and_closes_its_root(env, monkeypatch):
    p, _, _, _, events = env
    original = p._open_fixed_native_root
    held = []

    def record():
        fd = original()
        held.append(fd)
        return fd

    monkeypatch.setattr(p, "_open_fixed_native_root", record)
    with p._pin_observed_native_temp_chain():
        assert held and os.fstat(held[0])
    with pytest.raises(OSError):
        os.fstat(held[0])
    assert events == ["getconf", "root"]


def test_ambiguous_owned_root_fd_close_is_uncertain(env, monkeypatch):
    p, _, _, _, _ = env
    root = p._open_fixed_native_root
    held = []
    original_close = os.close

    def record():
        fd = root()
        held.append(fd)
        return fd

    def ambiguous_close(fd):
        if held and fd == held[0]:
            original_close(fd)
            raise OSError("ambiguous root close")
        return original_close(fd)

    monkeypatch.setattr(p, "_open_fixed_native_root", record)
    with monkeypatch.context() as patch:
        patch.setattr(p.os, "close", ambiguous_close)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err,
            p._pin_observed_native_temp_chain(),
        ):
            pass
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None


def test_no_real_guest_or_host_mutation(env, monkeypatch):
    p, _, _, _, _ = env

    def forbidden(*_args, **_kwargs):
        pytest.fail("host mutation/signal is forbidden")

    for name in ("kill", "unlink", "rename", "rmdir", "chmod", "chown"):
        monkeypatch.setattr(p.os, name, forbidden)
    with p._pin_observed_native_temp_chain() as chain:
        chain.revalidate()


def test_literal_root_identity_mismatch_refuses_and_closes_owned_fd(env, monkeypatch):
    from dataclasses import replace

    p, _, _, _, events = env
    actual = p._stat_fixed_native_root
    created = []
    original = p._open_fixed_native_root

    def record_root():
        fd = original()
        created.append(fd)
        return fd

    monkeypatch.setattr(p, "_open_fixed_native_root", record_root)
    monkeypatch.setattr(
        p,
        "_stat_fixed_native_root",
        lambda: replace(actual(), inode=actual().inode + 1),
    )
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$"),
        p._pin_observed_native_temp_chain(),
    ):
        pytest.fail("must not yield unverified root")
    assert events == ["getconf", "root"]
    with pytest.raises(OSError):
        os.fstat(created[0])


def test_late_literal_root_identity_swap_refuses(env, monkeypatch):
    from dataclasses import replace

    p, _, _, _, events = env
    native_stat = p._stat_fixed_native_root
    calls = 0

    def drift():
        nonlocal calls
        calls += 1
        baseline = native_stat()
        return baseline if calls == 1 else replace(baseline, inode=baseline.inode + 1)

    monkeypatch.setattr(p, "_stat_fixed_native_root", drift)
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$"),
        p._pin_observed_native_temp_chain() as chain,
    ):
        chain.revalidate()
    assert calls == 2
    assert events == ["getconf", "root"]


def test_already_uncertain_getconf_error_is_not_downgraded(env, monkeypatch):
    p, _, _, _, events = env

    def uncertain_getconf():
        raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_observe_fixed_temp_parent", uncertain_getconf)
    with pytest.raises(p.PreflightError) as err, p._pin_observed_native_temp_chain():
        pytest.fail("must not yield")
    assert err.value.cleanup_uncertain is True
    assert not events


def test_original_body_error_stays_uncertain_when_root_close_succeeds(env):
    p, _, _, _, _ = env
    with pytest.raises(p.PreflightError) as err, p._pin_observed_native_temp_chain():
        raise p.PreflightError(cleanup_uncertain=True)
    assert err.value.cleanup_uncertain is True


@pytest.mark.parametrize(
    "index,ambiguous_close",
    [
        (5, False),  # T is replaced immediately after its held FD closes
        (2, False),  # folders ancestor is replaced on its held FD close
        (5, True),  # successful close plus raising must retain uncertainty
        (2, True),  # ancestor ambiguity must likewise retain uncertainty
    ],
)
def test_post_descendant_close_namespace_swap_refuses(env, monkeypatch, index, ambiguous_close):
    p, _, root, _, events = env
    close_native = os.close
    swapped = []
    chosen_fd = [None]

    def closing(fd):
        if fd == chosen_fd[0] and not swapped:
            close_native(fd)
            edge = root.joinpath(*PARTS[: index + 1])
            former = edge.with_name("former-" + edge.name)
            edge.rename(former)
            edge.mkdir(mode=0o700)
            swapped.append((edge, former))
            if ambiguous_close:
                raise OSError("sensitive ambiguous descendant close")
            return
        close_native(fd)

    with monkeypatch.context() as injected:
        injected.setattr(p.os, "close", closing)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure,
            p._pin_observed_native_temp_chain() as chain,
        ):
            chosen_fd[0] = chain._fds[index + 1]
            chain.revalidate()
    assert swapped, "fault injection must occur after the originally checked edge"
    assert failure.value.cleanup_uncertain is ambiguous_close
    assert failure.value.__cause__ is None
    assert "sensitive" not in str(failure.value)
    assert events == ["getconf", "root"]


@pytest.mark.parametrize("ambiguous_close", [False, True])
def test_second_pass_close_swap_refuses_after_all_descendants_closed(
    env, monkeypatch, ambiguous_close
):
    p, _, root, _, events = env
    native_open, native_close = os.open, os.close
    observed_t = []
    swapped = []

    def capture_t_open(name, flags, *args, **kwargs):
        fd = native_open(name, flags, *args, **kwargs)
        if name == "T":
            observed_t.append(fd)
        return fd

    def close_second_t(fd):
        if len(observed_t) == 2 and fd == observed_t[-1] and not swapped:
            native_close(fd)
            leaf = root.joinpath(*PARTS)
            former = leaf.with_name("former-T")
            leaf.rename(former)
            leaf.mkdir(mode=0o700)
            swapped.append(True)
            if ambiguous_close:
                raise OSError("sensitive second-close uncertainty")
            return
        native_close(fd)

    with monkeypatch.context() as injected:
        injected.setattr(p.os, "open", capture_t_open)
        injected.setattr(p.os, "close", close_second_t)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure,
            p._pin_observed_native_temp_chain() as chain,
        ):
            chain.revalidate()
    assert len(observed_t) == 2
    assert swapped
    assert failure.value.cleanup_uncertain is ambiguous_close
    assert failure.value.__cause__ is None
    assert events == ["getconf", "root"]


def test_final_temp_observation_never_uses_joined_path_stat(env, monkeypatch):
    """Joined stat follows intermediate symlinks even if final edge is NOFOLLOW."""
    p, _, _, _, events = env
    original_stat = os.stat
    observed = []

    def require_single_edge(path, *args, **kwargs):
        if kwargs.get("dir_fd") is not None:
            assert "/" not in str(path), "joined path is not component-wise NOFOLLOW"
            observed.append(path)
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "stat", require_single_edge)
        with p._pin_observed_native_temp_chain() as chain:
            chain.revalidate()
    assert "folders" in observed
    assert events == ["getconf", "root"]


def test_second_pass_temp_symlink_replace_after_stat_refuses(env, monkeypatch):
    """Replace folders with a symlink to the moved original before nofollow open."""
    p, _, root, _, events = env
    original_stat, original_open = os.stat, os.open
    leaf_opens = []
    swaps = []

    def trace_open(name, flags, *args, **kwargs):
        fd = original_open(name, flags, *args, **kwargs)
        if name == "T":
            leaf_opens.append(fd)
        return fd

    def interleave(path, *args, **kwargs):
        value = original_stat(path, *args, **kwargs)
        if (
            path == "folders"
            and kwargs.get("dir_fd") is not None
            and len(leaf_opens) == 1
            and not swaps
        ):
            original = root.joinpath(*PARTS[:3])
            original.rename(original.with_name("folders-former"))
            original.symlink_to("folders-former", target_is_directory=True)
            swaps.append(True)
        return value

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "open", trace_open)
        patch.setattr(p.os, "stat", interleave)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as error,
            p._pin_observed_native_temp_chain(),
        ):
            pass
    assert swaps == [True]
    assert error.value.cleanup_uncertain is False
    assert root.joinpath(*PARTS[:3]).is_symlink()
    assert events == ["getconf", "root"]


@pytest.mark.parametrize("ambiguous", [False, True])
def test_final_native_temp_edge_drift_after_second_leaf_close_refuses(env, monkeypatch, ambiguous):
    p, _, root, _, events = env
    original_close, original_open = os.close, os.open
    leaves = []
    swaps = []

    def trace_open(name, flags, *args, **kwargs):
        fd = original_open(name, flags, *args, **kwargs)
        if name == "T":
            leaves.append(fd)
        return fd

    def close_then_replace(fd):
        original_close(fd)
        if len(leaves) == 2 and fd == leaves[-1] and not swaps:
            edge = root.joinpath(*PARTS)
            edge.rename(edge.with_name("T-former"))
            edge.symlink_to("T-former", target_is_directory=True)
            swaps.append(True)
            if ambiguous:
                raise OSError("private ambiguous temp close")

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "open", trace_open)
        patch.setattr(p.os, "close", close_then_replace)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as error,
            p._pin_observed_native_temp_chain(),
        ):
            pass
    assert swaps == [True]
    assert error.value.cleanup_uncertain is ambiguous
    assert error.value.__cause__ is None
    assert events == ["getconf", "root"]
