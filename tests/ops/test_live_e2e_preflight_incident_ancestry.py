"""RED/GREEN: only fixed read-only cache, temp, selected descriptor ancestry."""

from __future__ import annotations

import importlib.util
import inspect
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "ops/live-e2e/staging_preflight.py"
PROCESS = ROOT / "ops/live-e2e/staging_process_metadata.py"
TEMP_PARTS = ("private", "var", "folders", "ab", "runner_123", "T")


def _load(source, name):
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(name, None)
    return mod


@pytest.fixture
def env(tmp_path, monkeypatch):
    p = _load(PREFLIGHT, "_som_incident_pinned_ancestry")
    process = _load(PROCESS, "_som_incident_pinned_process")
    root = tmp_path / "disposable"
    root.mkdir(mode=0o700)
    cache = root.joinpath(*p._CACHE_PARTS)
    cache.mkdir(parents=True, mode=0o700)
    temp = root.joinpath(*TEMP_PARTS)
    temp.mkdir(parents=True, mode=0o700)
    incident = p._select_incident("stale-target")
    selected = temp / incident.basename
    selected.mkdir(mode=0o700)
    info = selected.stat()
    allowed = replace(
        incident,
        uid=os.geteuid(),
        device=info.st_dev,
        inode=info.st_ino,
        mode=0o700,
    )
    selector = p._select_incident

    def selected_catalog(name):
        original = selector(name)
        return allowed if name == "stale-target" else original

    monkeypatch.setattr(p, "_select_incident", selected_catalog)
    monkeypatch.setattr(p, "_TEMP_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(p, "_TEMP_ACCOUNT_UID", os.geteuid())
    monkeypatch.setattr(p, "_CACHE_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(p, "_CACHE_ACCOUNT_UID", os.geteuid())
    monkeypatch.setattr(p, "_fixed_process_metadata_module", lambda: process)
    trace = []

    def getconf():
        trace.append("getconf")
        return process.TempParent(
            "/var/folders/ab/runner_123/T/",
            "/private/var/folders/ab/runner_123/T/",
        )

    def literal_root():
        trace.append("root")
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    monkeypatch.setattr(p, "_observe_fixed_temp_parent", getconf)
    monkeypatch.setattr(p, "_open_fixed_native_root", literal_root)
    monkeypatch.setattr(p, "_stat_fixed_native_root", lambda: p._metadata(os.stat(root)))
    return p, root, temp, cache, selected, trace


def test_pinned_three_chains_have_strict_sequence_and_no_detached_evidence(env):
    p, _root, temp, cache, selected, trace = env
    with p._pin_observed_incident_ancestry("stale-target") as chains:
        assert type(chains) is tuple and len(chains) == 3
        cache_pin, temp_pin, selected_pin = chains
        assert cache_pin._parts == p._CACHE_PARTS
        assert temp_pin._parts == TEMP_PARTS
        assert selected_pin._parts == (selected.name,)
        assert cache_pin.metadata[-1].inode == cache.stat().st_ino
        assert temp_pin.metadata[-1].inode == temp.stat().st_ino
        assert selected_pin.metadata[0].inode == selected.stat().st_ino
        for pinned in chains:
            pinned.revalidate()
        assert trace == ["getconf", "root", "root"]
        borrowed = [fd for pinned in chains for fd in pinned._fds]
        for fd in borrowed:
            os.fstat(fd)
    for fd in borrowed:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert trace == ["getconf", "root", "root"]


def test_no_arbitrary_paths_uid_pids_or_generic_selectors(env):
    p, *_unused, trace = env
    assert tuple(inspect.signature(p._pin_observed_incident_ancestry).parameters) == ("selector",)
    with pytest.raises(TypeError):
        p._pin_observed_incident_ancestry("stale-target", "/untrusted")
    with pytest.raises(p.PreflightError), p._pin_observed_incident_ancestry("not-catalogued"):
        pytest.fail("invalid selector reached host")
    assert trace == []


@pytest.mark.parametrize(
    "surface,index",
    [
        ("temp", 0),
        ("temp", 3),
        ("temp", 5),
        ("cache", 0),
        ("cache", 2),
        ("cache", 4),
        ("selected", 0),
    ],
)
def test_late_parent_edge_replacement_refuses(env, surface, index):
    p, root, _temp, _cache, selected, _trace = env
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$"),
        p._pin_observed_incident_ancestry("stale-target") as chains,
    ):
        chain = {"cache": chains[0], "temp": chains[1], "selected": chains[2]}[surface]
        if surface == "cache":
            edge = root.joinpath(*p._CACHE_PARTS[: index + 1])
        elif surface == "temp":
            edge = root.joinpath(*TEMP_PARTS[: index + 1])
        else:
            edge = selected
        edge.rename(edge.with_name("former-" + edge.name))
        edge.mkdir(mode=0o700)
        assert len(chain._fds) > 1


def test_invalid_selected_catalog_refuses_after_only_getconf_and_roots(env, monkeypatch):
    p, *_unused, trace = env
    selector = p._select_incident

    def drift(name):
        value = selector(name)
        return replace(value, inode=value.inode + 1)

    monkeypatch.setattr(p, "_select_incident", drift)
    with pytest.raises(p.PreflightError), p._pin_observed_incident_ancestry("stale-target"):
        pytest.fail("unsafe selected namespace accepted")
    assert trace[:1] == ["getconf"]


def test_does_not_read_marker_or_spawn_ps_or_inventory(env, monkeypatch):
    p, *_ = env

    def deny(*args, **kwargs):
        raise AssertionError("forbidden stage or child access")

    monkeypatch.setattr(p, "_read_marker", deny)
    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", deny)
    monkeypatch.setattr(p, "_observe_selected_inventory", deny)
    monkeypatch.setattr(p, "_observe_paired_process_inventory", deny)
    with p._pin_observed_incident_ancestry("stale-target") as chains:
        for chain in chains:
            chain.revalidate()


def test_nested_cleanup_preserves_original_uncertainty(env, monkeypatch):
    p, *_ = env
    original = p._pin_fixed_incident_root

    from contextlib import contextmanager

    @contextmanager
    def fails_on_exit(*args):
        with original(*args) as selected:
            yield selected
            raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_pin_fixed_incident_root", fails_on_exit)
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err,
        p._pin_observed_incident_ancestry("stale-target"),
    ):
        pass
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None


def test_failed_getconf_does_not_open_cache_or_selected(env, monkeypatch):
    p, _root, _temp, _cache, _selected, trace = env

    def reject_getconf():
        trace.append("getconf")
        raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_observe_fixed_temp_parent", reject_getconf)
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure,
        p._pin_observed_incident_ancestry("stale-target"),
    ):
        pytest.fail("child failure yielded pinned ancestry")
    assert failure.value.cleanup_uncertain is True
    assert trace == ["getconf"]


def test_cache_unsafe_mode_refuses_before_selected_pin(env, monkeypatch):
    p, _root, _temp, cache, _selected, trace = env
    cache.chmod(0o777)
    calls = []
    original = p._pin_fixed_incident_root

    def count_selected(*args):
        calls.append(True)
        return original(*args)

    monkeypatch.setattr(p, "_pin_fixed_incident_root", count_selected)
    with pytest.raises(p.PreflightError), p._pin_observed_incident_ancestry("stale-target"):
        pytest.fail("unsafe cache accepted")
    assert calls == []
    assert trace[0] == "getconf"


def test_selected_symlink_denied_before_context_yield(env):
    p, _root, _temp, _cache, selected, _trace = env
    renamed = selected.with_name("selected-former")
    selected.rename(renamed)
    selected.symlink_to(renamed.name, target_is_directory=True)
    with pytest.raises(p.PreflightError), p._pin_observed_incident_ancestry("stale-target"):
        pytest.fail("selected symlink accepted")


def _install_two_root_transition(env, monkeypatch):
    """Exercise actual fixed nofollow opens under different disposable roots.

    Temp sees A, cache sees B. Each wrapper's literal-root stat is
    individually consistent with a simulated A->B->A root view.
    """
    p, root_a, _temp, _cache, _selected, events = env
    root_b = root_a.parent / "different-root"
    root_b.mkdir(mode=0o700)
    root_b.joinpath(*p._CACHE_PARTS).mkdir(parents=True, mode=0o700)
    old_open = os.open
    opens = []
    stats = []

    def two_roots():
        root = (root_a, root_b)[len(opens)]
        fd = old_open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        opens.append((root, fd))
        events.append("root")
        return fd

    def root_view():
        # Entry(temp=A, cache=B), exit(cache=B twice, temp=A twice)
        sequence = (root_a, root_b, root_b, root_b, root_a, root_a)
        choice = sequence[min(len(stats), len(sequence) - 1)]
        stats.append(choice)
        return p._metadata(os.stat(choice))

    monkeypatch.setattr(p, "_open_fixed_native_root", two_roots)
    monkeypatch.setattr(p, "_stat_fixed_native_root", root_view)
    return root_a, root_b, opens, stats


def test_two_distinct_root_fds_must_not_be_jointly_accepted(env, monkeypatch):
    p, *_ = env
    root_a, root_b, opens, stats = _install_two_root_transition(env, monkeypatch)
    accepted = []
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure,
        p._pin_observed_incident_ancestry("stale-target") as chains,
    ):
        accepted.append(True)
        assert chains[1]._initial[0] != chains[0]._initial[0]
    assert accepted == []
    assert failure.value.cleanup_uncertain is False
    assert len(opens) == 2
    assert root_a.stat().st_ino != root_b.stat().st_ino
    assert stats[:2] == [root_a, root_b]
    for _, fd in opens:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_root_view_transition_with_locally_consistent_checks_refuses(env, monkeypatch):
    p, *_ = env
    root_a, root_b, opens, stats = _install_two_root_transition(env, monkeypatch)
    accepted = []
    with pytest.raises(p.PreflightError), p._pin_observed_incident_ancestry("stale-target"):
        accepted.append(True)
    assert accepted == []
    assert [path for path, _ in opens] == [root_a, root_b]
    assert stats[:2] == [root_a, root_b]


def test_common_root_and_shared_t_are_explicitly_bound(env):
    p, *_ = env
    with p._pin_observed_incident_ancestry("stale-target") as chains:
        cache, temp, selected = chains
        assert cache._initial[0] == temp._initial[0]
        assert selected._initial[0] == temp._initial[-1]
        assert p._metadata(os.fstat(cache._fds[0])) == temp._initial[0]
        assert p._metadata(os.fstat(selected._fds[0])) == temp._initial[-1]


def test_forged_selected_t_baseline_rejected_before_yield(env, monkeypatch):
    from contextlib import contextmanager

    p, *_ = env
    original = p._pin_fixed_incident_root

    @contextmanager
    def forged_parent(*args):
        with original(*args) as selected:
            forged = replace(
                selected,
                _initial=(
                    replace(selected._initial[0], inode=selected._initial[0].inode + 1),
                    selected._initial[1],
                ),
            )
            yield forged

    monkeypatch.setattr(p, "_pin_fixed_incident_root", forged_parent)
    accepted = []
    with (
        pytest.raises(p.PreflightError, match="^staging preflight rejected$"),
        p._pin_observed_incident_ancestry("stale-target"),
    ):
        accepted.append(True)
    assert accepted == []
