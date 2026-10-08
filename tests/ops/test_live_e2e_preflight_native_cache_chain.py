"""Fixture-only RED/GREEN for fixed cache ancestry from literal-root authority."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "ops/live-e2e/staging_preflight.py"


def _load():
    name = "_som_cache_root_binding_fixture"
    spec = importlib.util.spec_from_file_location(name, PREFLIGHT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    p = _load()
    root = tmp_path / "private-root"
    root.mkdir(mode=0o700)
    cursor = root
    for name in p._CACHE_PARTS:
        cursor /= name
        cursor.mkdir(mode=0o700)
    monkeypatch.setattr(p, "_CACHE_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(p, "_CACHE_ACCOUNT_UID", os.geteuid())
    events = []

    def literal_root():
        events.append("open-root")
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def stat_root():
        events.append("stat-root")
        return p._metadata(os.stat(root))

    monkeypatch.setattr(p, "_open_fixed_native_root", literal_root)
    monkeypatch.setattr(p, "_stat_fixed_native_root", stat_root)
    return p, root, cursor, events


def test_fixed_cache_chain_remains_pinned_through_context(fixture):
    p, root, leaf, events = fixture
    with p._pin_observed_fixed_cache_chain() as chain:
        assert chain._parts == p._CACHE_PARTS
        assert len(chain.metadata) == len(p._CACHE_PARTS)
        assert chain.metadata[-1].inode == leaf.stat().st_ino
        assert chain.metadata[-1].uid == os.geteuid()
        chain.revalidate()
        with pytest.raises(FrozenInstanceError):
            chain._parts = ()
    assert events.count("open-root") == 1
    assert events.count("stat-root") >= 2
    assert (root / p._CACHE_PARTS[0]).is_dir()


def test_no_root_or_path_selector_arguments(fixture):
    import inspect

    p, *_ = fixture
    assert tuple(inspect.signature(p._pin_observed_fixed_cache_chain).parameters) == ()
    with pytest.raises(TypeError):
        p._pin_observed_fixed_cache_chain("/tmp")
    assert "active-run.json" not in inspect.getsource(p._pin_observed_fixed_cache_chain)


@pytest.mark.parametrize("index", range(5))
def test_post_yield_original_namespace_swap_refuses(fixture, index):
    p, root, _, _ = fixture
    with pytest.raises(p.PreflightError), p._pin_observed_fixed_cache_chain() as chain:
        edge = root.joinpath(*p._CACHE_PARTS[: index + 1])
        edge.rename(edge.with_name("former-" + edge.name))
        edge.mkdir(mode=0o700)
        assert stat.S_ISDIR(os.fstat(chain._fds[-1]).st_mode)


@pytest.mark.parametrize("index", range(5))
def test_unsafe_cache_edge_refused(fixture, index):
    p, root, _, _ = fixture
    root.joinpath(*p._CACHE_PARTS[: index + 1]).chmod(0o777)
    with pytest.raises(p.PreflightError), p._pin_observed_fixed_cache_chain():
        pytest.fail("unsafe cache edge accepted")


def test_root_identity_drift_refuses_before_yield(fixture, monkeypatch):
    p, _, _, events = fixture
    old = p._stat_fixed_native_root
    monkeypatch.setattr(p, "_stat_fixed_native_root", lambda: replace(old(), inode=old().inode + 1))
    with pytest.raises(p.PreflightError), p._pin_observed_fixed_cache_chain():
        pytest.fail("drifted root accepted")
    assert events.count("open-root") == 1


def test_root_identity_drift_after_yield_refuses(fixture, monkeypatch):
    p, _, _, _ = fixture
    old = p._stat_fixed_native_root
    calls = []

    def drift():
        value = old()
        calls.append(1)
        return value if len(calls) == 1 else replace(value, inode=value.inode + 1)

    monkeypatch.setattr(p, "_stat_fixed_native_root", drift)
    with pytest.raises(p.PreflightError), p._pin_observed_fixed_cache_chain() as chain:
        chain.revalidate()
    assert len(calls) >= 2


@pytest.mark.parametrize("index", [0, 2, 4])
@pytest.mark.parametrize("ambiguous", [False, True])
def test_original_descendant_close_swap_refuses(fixture, monkeypatch, index, ambiguous):
    p, root, _, _ = fixture
    native_close = os.close
    selected = [None]
    swaps = []

    def close_swap(fd):
        if fd == selected[0] and not swaps:
            native_close(fd)
            edge = root.joinpath(*p._CACHE_PARTS[: index + 1])
            edge.rename(edge.with_name("former-" + edge.name))
            edge.mkdir(mode=0o700)
            swaps.append(True)
            if ambiguous:
                raise OSError("sensitive ambiguous owned close")
            return
        return native_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "close", close_swap)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err,
            p._pin_observed_fixed_cache_chain() as chain,
        ):
            selected[0] = chain._fds[index + 1]
    assert swaps == [True]
    assert err.value.cleanup_uncertain is ambiguous
    assert err.value.__cause__ is None
    assert "sensitive" not in str(err.value)


@pytest.mark.parametrize("ambiguous", [False, True])
def test_second_pass_descendant_close_swap_refuses(fixture, monkeypatch, ambiguous):
    p, root, _, _ = fixture
    native_open, native_close = os.open, os.close
    seen = []
    swaps = []

    def open_trace(name, flags, *args, **kwargs):
        fd = native_open(name, flags, *args, **kwargs)
        if name == p._CACHE_PARTS[-1]:
            seen.append(fd)
        return fd

    def close_swap(fd):
        if len(seen) == 2 and fd == seen[-1] and not swaps:
            native_close(fd)
            leaf = root.joinpath(*p._CACHE_PARTS)
            leaf.rename(root.joinpath(*p._CACHE_PARTS[:-1], "former-cache"))
            leaf.mkdir(mode=0o700)
            swaps.append(True)
            if ambiguous:
                raise OSError("ambiguous second close")
            return
        return native_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "open", open_trace)
        patch.setattr(p.os, "close", close_swap)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err,
            p._pin_observed_fixed_cache_chain(),
        ):
            pass
    assert len(seen) == 2
    assert swaps == [True]
    assert err.value.cleanup_uncertain is ambiguous


def test_owned_literal_root_closes_on_success_and_preserves_uncertain(fixture, monkeypatch):
    p, _, _, _ = fixture
    actual = p._open_fixed_native_root
    native_close = os.close
    roots = []

    def root_open():
        fd = actual()
        roots.append(fd)
        return fd

    monkeypatch.setattr(p, "_open_fixed_native_root", root_open)
    with p._pin_observed_fixed_cache_chain():
        os.fstat(roots[0])
    with pytest.raises(OSError):
        os.fstat(roots[0])

    def close_ambiguous(fd):
        if fd == roots[-1]:
            native_close(fd)
            raise OSError("private root close")
        return native_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "close", close_ambiguous)
        with (
            pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err,
            p._pin_observed_fixed_cache_chain(),
        ):
            pass
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None
