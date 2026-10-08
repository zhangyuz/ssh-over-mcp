"""Disposable RED/GREEN fixtures for selected incident catalog root binding."""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"
CATALOG = {
    "stale-target": (
        "ssh-over-mcp-e2e-i8ow1ni6",
        16777220,
        187176421,
        "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
    ),
    "older-target": (
        "ssh-over-mcp-e2e-w_kn4rus",
        16777220,
        186877220,
        "bf84c7aafa5c79d629fc04488b5e0bda1cd98cef",
    ),
}


@pytest.fixture
def preflight():
    name = "ssh_over_mcp_catalog_root_fixture"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def catalog_fixture(tmp_path, preflight, monkeypatch):
    # Assert the production catalog before replacing only private filesystem
    # identities. No incident path or inode is opened by this fixture.
    assert set(preflight._INCIDENTS) == set(CATALOG)
    for selector, expected in CATALOG.items():
        item = preflight._select_incident(selector)
        assert (item.basename, item.device, item.inode, item.expected_commit) == expected
        assert (item.selector, item.uid, item.mode) == (selector, 502, 0o700)
    parent = tmp_path / "T"
    parent.mkdir(mode=0o700)
    roots = {}
    for selector, (basename, *_) in CATALOG.items():
        root = parent / basename
        root.mkdir(mode=0o700)
        roots[selector] = root
    original_select = preflight._select_incident

    def disposable_select(selector):
        item = original_select(selector)
        info = roots[selector].stat()
        return replace(item, device=info.st_dev, inode=info.st_ino, uid=os.geteuid())

    # Snapshot fixture identities, never adopt replacements as a new catalog.
    selected = {selector: disposable_select(selector) for selector in CATALOG}

    def fixed_fixture_select(selector):
        original_select(selector)
        return selected[selector]

    monkeypatch.setattr(preflight, "_select_incident", fixed_fixture_select)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield parent, roots, fd
    finally:
        # Fault cases change this disposable fixture's mode; return it to an
        # accessible state for pytest's own cleanup, never touch host state.
        parent.chmod(0o700)
        os.close(fd)


def _pin(preflight, fd, selector="stale-target"):
    operation = getattr(preflight, "_pin_fixed_incident_root", None)
    assert operation is not None, "fixed incident-root binding is missing"
    return operation(fd, selector)


@pytest.mark.parametrize("selector", CATALOG)
def test_selector_subclass_has_no_authority(preflight, monkeypatch, selector):
    class Selector(str):
        pass

    def forbidden(*args, **kwargs):
        pytest.fail("subclass selector reached filesystem")

    monkeypatch.setattr(preflight.os, "fstat", forbidden)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, 99, Selector(selector)),
    ):
        pytest.fail("accepted selector subclass")


@pytest.mark.parametrize("fd", [True, None, -1, "99", [], ()])
def test_invalid_borrowed_fd_refuses(preflight, catalog_fixture, fd):
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, fd),
    ):
        pytest.fail("accepted invalid borrowed FD")


def test_wrong_temp_parent_uid_refuses_before_dup(preflight, catalog_fixture, monkeypatch):
    parent, _, borrowed = catalog_fixture
    inode = parent.stat().st_ino
    real_metadata = preflight._metadata

    def wrong_uid(info):
        result = real_metadata(info)
        return replace(result, uid=result.uid + 1) if result.inode == inode else result

    monkeypatch.setattr(preflight, "_metadata", wrong_uid)
    monkeypatch.setattr(preflight.os, "dup", lambda fd: pytest.fail("wrong-owner T duplicated"))
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted wrong-owner T")


@pytest.mark.parametrize("selector", CATALOG)
def test_selected_catalog_root_pins_only_literal_edge(preflight, catalog_fixture, selector):
    _, roots, borrowed = catalog_fixture
    with _pin(preflight, borrowed, selector) as chain:
        assert chain._parts == (CATALOG[selector][0],)
        assert len(chain.metadata) == 1
        info = roots[selector].stat()
        meta = chain.metadata[0]
        assert (meta.device, meta.inode, meta.uid, meta.mode) == (
            info.st_dev,
            info.st_ino,
            os.geteuid(),
            0o700,
        )
        chain.revalidate()


@pytest.mark.parametrize(
    "selector",
    [
        None,
        True,
        1,
        b"stale-target",
        [],
        {},
        "",
        "stale-target/..",
        "other-target",
        "recover.cc8Del",
    ],
)
def test_unknown_selector_refuses_before_filesystem(preflight, monkeypatch, selector):
    def forbidden(*args, **kwargs):
        pytest.fail("unknown selector reached filesystem")

    monkeypatch.setattr(preflight.os, "fstat", forbidden)
    monkeypatch.setattr(preflight.os, "dup", forbidden)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, 99, selector),
    ):
        pytest.fail("accepted unknown selector")


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o777, 0o600, 0o1700])
def test_temp_parent_requires_exact_0700(preflight, catalog_fixture, monkeypatch, mode):
    parent, _, borrowed = catalog_fixture
    parent.chmod(mode)
    monkeypatch.setattr(preflight.os, "dup", lambda fd: pytest.fail("unsafe T duplicated"))
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted unsafe T")


@pytest.mark.parametrize("object_name", ["parent", "selected"])
@pytest.mark.parametrize("field", ["device", "inode", "uid", "gid", "mode"])
def test_late_held_metadata_drift_refuses(
    preflight, catalog_fixture, monkeypatch, object_name, field
):
    parent, roots, borrowed = catalog_fixture
    target = parent if object_name == "parent" else roots["stale-target"]
    inode = target.stat().st_ino
    real_metadata = preflight._metadata
    with _pin(preflight, borrowed) as chain:

        def drift(info):
            result = real_metadata(info)
            if result.inode == inode:
                return replace(result, **{field: getattr(result, field) + 1})
            return result

        monkeypatch.setattr(preflight, "_metadata", drift)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


@pytest.mark.parametrize("field", ["device", "inode", "uid", "mode"])
def test_selected_root_must_match_catalog(preflight, catalog_fixture, monkeypatch, field):
    _, roots, borrowed = catalog_fixture
    inode = roots["stale-target"].stat().st_ino
    real_metadata = preflight._metadata

    def changed(info):
        result = real_metadata(info)
        if result.inode == inode:
            return replace(result, **{field: getattr(result, field) + 1})
        return result

    monkeypatch.setattr(preflight, "_metadata", changed)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted root differing from catalog")


@pytest.mark.parametrize("replacement", ["missing", "file", "symlink"])
def test_selected_root_refuses_missing_or_wrong_type(preflight, catalog_fixture, replacement):
    _, roots, borrowed = catalog_fixture
    root = roots["stale-target"]
    old = root.with_name("old")
    root.rename(old)
    if replacement == "file":
        root.write_bytes(b"fixture")
    elif replacement == "symlink":
        root.symlink_to(old.name, target_is_directory=True)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted missing or special root")


def test_selected_root_replacement_between_stat_open(preflight, catalog_fixture, monkeypatch):
    _, roots, borrowed = catalog_fixture
    root = roots["stale-target"]
    real_open = os.open

    def replaced_open(name, flags, **kwargs):
        if name == root.name:
            root.rename(root.with_name("old"))
            root.mkdir(mode=0o700)
        return real_open(name, flags, **kwargs)

    monkeypatch.setattr(preflight.os, "open", replaced_open)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted replaced catalog root")


def test_late_root_edge_replacement_refuses_while_old_fd_valid(preflight, catalog_fixture):
    _, roots, borrowed = catalog_fixture
    root = roots["stale-target"]
    with _pin(preflight, borrowed) as chain:
        before = os.fstat(chain._fds[-1])
        root.rename(root.with_name("old"))
        root.mkdir(mode=0o700)
        assert os.fstat(chain._fds[-1]).st_ino == before.st_ino
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


@pytest.mark.parametrize("restore", [False, True])
def test_parent_safe_mode_drift_during_dup_never_becomes_baseline(
    preflight, catalog_fixture, monkeypatch, restore
):
    parent, roots, borrowed = catalog_fixture
    real_dup, real_open = os.dup, os.open

    def changed_dup(fd):
        result = real_dup(fd)
        parent.chmod(0o755)
        return result

    def maybe_restored_open(name, flags, **kwargs):
        result = real_open(name, flags, **kwargs)
        if restore and name == roots["stale-target"].name:
            parent.chmod(0o700)
        return result

    monkeypatch.setattr(preflight.os, "dup", changed_dup)
    monkeypatch.setattr(preflight.os, "open", maybe_restored_open)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("adopted changed T baseline")


def test_pin_preserves_borrowed_fd_and_closes_owned(preflight, catalog_fixture):
    import fcntl

    _, _, borrowed = catalog_fixture
    info = os.fstat(borrowed)
    before = (
        fcntl.fcntl(borrowed, fcntl.F_GETFD),
        fcntl.fcntl(borrowed, fcntl.F_GETFL),
        os.lseek(borrowed, 0, os.SEEK_CUR),
    )
    with _pin(preflight, borrowed) as chain:
        owned = chain._fds
        assert all(not os.get_inheritable(fd) for fd in owned)
    assert os.fstat(borrowed) == info
    assert before == (
        fcntl.fcntl(borrowed, fcntl.F_GETFD),
        fcntl.fcntl(borrowed, fcntl.F_GETFL),
        os.lseek(borrowed, 0, os.SEEK_CUR),
    )
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("failed_index", [0, 1])
@pytest.mark.parametrize("body_uncertain", [False, True])
def test_close_ambiguity_preserves_true_and_attempts_every_owned_fd(
    preflight, catalog_fixture, monkeypatch, failed_index, body_uncertain
):
    _, _, borrowed = catalog_fixture
    real_close = os.close
    calls = []
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as failure,
        _pin(preflight, borrowed) as chain,
    ):
        owned = chain._fds

        def uncertain_close(fd):
            calls.append(fd)
            real_close(fd)
            if fd == owned[failed_index]:
                raise OSError("fixture close ambiguity")

        monkeypatch.setattr(preflight.os, "close", uncertain_close)
        if body_uncertain:
            raise preflight.PreflightError(cleanup_uncertain=True)
    monkeypatch.setattr(preflight.os, "close", real_close)
    assert calls == list(reversed(owned))
    assert failure.value.cleanup_uncertain is True
    assert os.fstat(borrowed)


def test_no_content_inventory_signal_or_environment_action(preflight, catalog_fixture, monkeypatch):
    _, _, borrowed = catalog_fixture

    def forbidden(*args, **kwargs):
        pytest.fail("namespace pin gained extra authority")

    for name in ("read", "write", "scandir", "kill", "getenv"):
        monkeypatch.setattr(preflight.os, name, forbidden)
    assert not hasattr(preflight, "preflight_incident")
    assert not hasattr(preflight, "main")
    with _pin(preflight, borrowed) as chain:
        chain.revalidate()
