"""Disposable namespace fixtures; no real temp derivation or incident access."""

from __future__ import annotations

import fcntl
import importlib.util
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"
PARTS = ("private", "var", "folders", "ab", "token_123", "T")


@pytest.fixture
def preflight():
    name = "ssh_over_mcp_temp_chain_fixture"
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
def temp_tree(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    cursor = root
    for part in PARTS:
        cursor /= part
        cursor.mkdir(mode=0o700)
    borrowed = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, cursor, borrowed
    finally:
        os.close(borrowed)


def _pin(preflight, borrowed, monkeypatch, components=("ab", "token_123")):
    operation = getattr(preflight, "_pin_fixed_temp_chain", None)
    assert callable(operation), "fixed temp-chain policy is not implemented"
    assert preflight._TEMP_SYSTEM_UID == 0
    assert preflight._TEMP_ACCOUNT_UID == 502
    monkeypatch.setattr(preflight, "_TEMP_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_TEMP_ACCOUNT_UID", os.geteuid())
    return operation(borrowed, components)


@pytest.mark.parametrize("token_mode", [0o700, 0o755])
def test_temp_chain_pins_exact_native_components(preflight, temp_tree, monkeypatch, token_mode):
    root, leaf, borrowed = temp_tree
    leaf.parent.chmod(token_mode)
    with _pin(preflight, borrowed, monkeypatch) as chain:
        assert chain._parts == PARTS
        assert len(chain.metadata) == 6
        assert chain.metadata[-2].mode == token_mode
        assert chain.metadata[-1].inode == leaf.stat().st_ino
        assert chain.metadata[-1].mode == 0o700
        chain.revalidate()
    assert os.fstat(borrowed).st_ino == root.stat().st_ino


@pytest.mark.parametrize(
    "components",
    [
        None,
        True,
        "ab/token_123",
        ["ab", "token_123"],
        (),
        ("ab",),
        ("ab", "t", "extra"),
        (True, "t"),
        (b"ab", "t"),
        ("a", "t"),
        ("abc", "t"),
        ("a_", "t"),
        ("AB", "t"),
        ("a/", "t"),
        ("éa", "t"),
        ("ab", None),
        ("ab", b"t"),
        ("ab", ""),
        ("ab", "../other"),
        ("ab", "path/name"),
        ("ab", "UPPER"),
        ("ab", "space token"),
        ("ab", "tab\ttoken"),
        ("ab", "line\ntoken"),
        ("ab", "null\x00token"),
        ("ab", "é"),
        ("ab", "t" * 256),
    ],
)
def test_temp_components_refuse_before_any_fd_action(preflight, temp_tree, monkeypatch, components):
    _, _, borrowed = temp_tree
    context = _pin(preflight, borrowed, monkeypatch, components)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        pytest.fail("malformed components reached filesystem operations")

    with monkeypatch.context() as guard:
        guard.setattr(preflight.os, "dup", forbidden)
        guard.setattr(preflight.os, "fstat", forbidden)
        with (
            pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
            context,
        ):
            pytest.fail("accepted malformed native components")
    assert not calls


def test_temp_token_component_limit_equality(preflight, temp_tree, monkeypatch):
    _, leaf, borrowed = temp_tree
    token = "t" * 255
    leaf.parent.rename(leaf.parent.with_name(token))
    with _pin(preflight, borrowed, monkeypatch, ("ab", token)) as chain:
        assert chain._parts[-2] == token
        chain.revalidate()


@pytest.mark.parametrize("index", range(6))
def test_temp_chain_rejects_unsafe_component_modes(preflight, temp_tree, monkeypatch, index):
    root, _, borrowed = temp_tree
    root.joinpath(*PARTS[: index + 1]).chmod(0o777)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed, monkeypatch),
    ):
        pytest.fail("accepted unsafe ancestor")


@pytest.mark.parametrize("index,mode", [(4, 0o750), (4, 0o770), (5, 0o755)])
def test_temp_chain_requires_exact_account_modes(preflight, temp_tree, monkeypatch, index, mode):
    root, _, borrowed = temp_tree
    root.joinpath(*PARTS[: index + 1]).chmod(mode)
    with pytest.raises(preflight.PreflightError), _pin(preflight, borrowed, monkeypatch):
        pytest.fail("accepted unsupported account mode")


@pytest.mark.parametrize("index", range(6))
def test_temp_chain_rejects_wrong_component_owner(preflight, temp_tree, monkeypatch, index):
    root, _, borrowed = temp_tree
    context = _pin(preflight, borrowed, monkeypatch)
    target_inode = root.joinpath(*PARTS[: index + 1]).stat().st_ino
    original = preflight._metadata

    def wrong_uid(info):
        value = original(info)
        return replace(value, uid=value.uid + 1) if value.inode == target_inode else value

    monkeypatch.setattr(preflight, "_metadata", wrong_uid)
    with pytest.raises(preflight.PreflightError), context:
        pytest.fail("accepted wrong ancestor owner")


@pytest.mark.parametrize("index", range(6))
def test_temp_chain_refuses_symlink_at_every_edge(preflight, temp_tree, monkeypatch, index):
    root, _, borrowed = temp_tree
    path = root.joinpath(*PARTS[: index + 1])
    former = path.with_name(path.name + "-former")
    path.rename(former)
    path.symlink_to(former.name, target_is_directory=True)
    with pytest.raises(preflight.PreflightError), _pin(preflight, borrowed, monkeypatch):
        pytest.fail("followed ancestor symlink")


@pytest.mark.parametrize("index", range(6))
def test_temp_chain_late_namespace_replacement_refuses(preflight, temp_tree, monkeypatch, index):
    root, _, borrowed = temp_tree
    with _pin(preflight, borrowed, monkeypatch) as chain:
        path = root.joinpath(*PARTS[: index + 1])
        path.rename(path.with_name(path.name + "-former"))
        path.mkdir(mode=0o700)
        # Held objects remain valid; only their current namespace edge changed.
        assert all(
            os.fstat(fd).st_ino == original.inode
            for fd, original in zip(chain._fds, chain._initial, strict=True)
        )
        with pytest.raises(preflight.PreflightError):
            chain.revalidate()


def test_temp_chain_rejects_stat_open_replacement(preflight, temp_tree, monkeypatch):
    root, _, borrowed = temp_tree
    context = _pin(preflight, borrowed, monkeypatch)
    original_open = os.open
    changed = False

    def replace_before_open(name, flags, *args, **kwargs):
        nonlocal changed
        if name == "folders" and not changed:
            changed = True
            path = root / "private" / "var" / "folders"
            path.rename(path.with_name("former"))
            path.mkdir(mode=0o700)
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(preflight.os, "open", replace_before_open)
    with pytest.raises(preflight.PreflightError), context:
        pytest.fail("accepted replacement at open")
    assert changed


@pytest.mark.parametrize("change", ["mode", "uid", "restore-mode"])
def test_temp_chain_root_dup_races_refuse(preflight, temp_tree, monkeypatch, change):
    root, _, borrowed = temp_tree
    context = _pin(preflight, borrowed, monkeypatch)
    original_dup, original_open, original_meta = os.dup, os.open, preflight._metadata
    changed = False

    def mutate_after_dup(fd):
        nonlocal changed
        result = original_dup(fd)
        if fd == borrowed:
            changed = True
            if change != "uid":
                root.chmod(0o777)
        return result

    def metadata(info):
        result = original_meta(info)
        if changed and change == "uid" and result.inode == root.stat().st_ino:
            return replace(result, uid=result.uid + 1)
        return result

    def restore_after_pin(name, flags, *args, **kwargs):
        result = original_open(name, flags, *args, **kwargs)
        if name == "T" and change == "restore-mode":
            root.chmod(0o700)
        return result

    monkeypatch.setattr(preflight.os, "dup", mutate_after_dup)
    monkeypatch.setattr(preflight.os, "open", restore_after_pin)
    monkeypatch.setattr(preflight, "_metadata", metadata)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"), context:
        pytest.fail("adopted unsafe root baseline")
    assert changed


def test_temp_chain_preserves_borrowed_fd_and_closes_owned(
    preflight, temp_tree, monkeypatch, capsys
):
    root, _, borrowed = temp_tree
    os.set_inheritable(borrowed, True)
    original = os.fstat(borrowed)
    offset = os.lseek(borrowed, 0, os.SEEK_CUR)
    flags = (fcntl.fcntl(borrowed, fcntl.F_GETFD), fcntl.fcntl(borrowed, fcntl.F_GETFL))
    with _pin(preflight, borrowed, monkeypatch) as chain:
        owned = chain._fds
        assert borrowed not in owned
        assert all(not os.get_inheritable(fd) for fd in owned)
        chain.revalidate()
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert os.get_inheritable(borrowed)
    assert os.lseek(borrowed, 0, os.SEEK_CUR) == offset
    assert (fcntl.fcntl(borrowed, fcntl.F_GETFD), fcntl.fcntl(borrowed, fcntl.F_GETFL)) == flags
    assert os.fstat(borrowed).st_ino == original.st_ino == root.stat().st_ino
    assert capsys.readouterr() == ("", "")


def test_temp_chain_close_uncertainty_stays_true(preflight, temp_tree, monkeypatch):
    _, _, borrowed = temp_tree
    context = _pin(preflight, borrowed, monkeypatch)
    original_close = os.close
    closed = []
    owned = ()

    def ambiguous_close(fd):
        original_close(fd)
        closed.append(fd)
        if len(closed) == 1:
            raise OSError("fixture close ambiguity")

    with monkeypatch.context() as guard:
        guard.setattr(preflight.os, "close", ambiguous_close)
        with (
            pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as error,
            context as chain,
        ):
            owned = chain._fds
        assert error.value.cleanup_uncertain is True
    assert closed == list(reversed(owned))
    assert os.fstat(borrowed)


def test_temp_chain_has_no_capture_or_state_access(preflight, temp_tree, monkeypatch):
    _, _, borrowed = temp_tree
    context = _pin(preflight, borrowed, monkeypatch)
    assert not hasattr(preflight, "main")
    assert not hasattr(preflight, "preflight_incident")

    def forbidden(*args, **kwargs):
        pytest.fail("temp ancestry acquired non-directory authority")

    for name in ("read", "write", "kill", "scandir", "getenv"):
        monkeypatch.setattr(preflight.os, name, forbidden)
    with context as chain:
        chain.revalidate()
