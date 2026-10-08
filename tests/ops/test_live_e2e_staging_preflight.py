"""RED: dormant, descriptor-pinned namespace primitives; disposable fixtures only."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"


@pytest.fixture
def preflight():
    assert MODULE.is_file(), "Slice A preflight module is not implemented"
    name = "ssh_over_mcp_dormant_staging_preflight"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "borrowed"
    root.mkdir(mode=0o700)
    (root / "alpha").mkdir(mode=0o700)
    (root / "alpha" / "beta").mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, fd
    finally:
        os.close(fd)


def _pin(p, fd, count=2):
    names = ("alpha", "beta")[:count]
    rules = ((os.geteuid(), (0o700,)),) * count
    return p._pin_directory_chain(fd, names, rules)


def test_pins_child_descriptors_with_no_follow_and_revalidates(preflight, tree):
    root, fd = tree
    borrowed_before = os.fstat(fd)
    with _pin(preflight, fd) as chain:
        assert len(chain.metadata) == 2
        assert chain.metadata[0].inode == (root / "alpha").stat().st_ino
        assert chain.metadata[1].inode == (root / "alpha" / "beta").stat().st_ino
        chain.revalidate()
    assert os.fstat(fd).st_ino == borrowed_before.st_ino
    assert (root / "alpha").is_dir()


@pytest.mark.parametrize("name", ("..", ".", "", "a/b", "a\\b", "\x00x"))
def test_rejects_non_component_input(preflight, tree, name):
    _, fd = tree
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_directory_chain(fd, (name,), ((os.geteuid(), (0o700,)),)),
    ):
        pytest.fail("accepted invalid component")


def test_rejects_symlink_in_child_chain(preflight, tree):
    root, fd = tree
    (root / "alpha" / "beta").rename(root / "alpha" / "old")
    (root / "alpha" / "beta").symlink_to("old", target_is_directory=True)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, fd),
    ):
        pytest.fail("accepted symlink")


def test_rejects_wrong_permissions(preflight, tree):
    root, fd = tree
    (root / "alpha").chmod(0o777)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, fd),
    ):
        pytest.fail("accepted unsafe directory")


def test_rejects_wrong_owner_without_touching_tree(preflight, tree):
    _, fd = tree
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_directory_chain(fd, ("alpha",), ((os.geteuid() + 999, (0o700,)),)),
    ):
        pytest.fail("accepted wrong UID")


def test_detects_replaced_parent_edge_even_with_held_descriptor(preflight, tree):
    root, fd = tree
    with _pin(preflight, fd) as chain:
        (root / "alpha").rename(root / "departed")
        (root / "alpha").mkdir(mode=0o700)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


def test_detects_replaced_leaf_edge(preflight, tree):
    root, fd = tree
    with _pin(preflight, fd) as chain:
        (root / "alpha" / "beta").rename(root / "alpha" / "former")
        (root / "alpha" / "beta").mkdir(mode=0o700)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


def test_detects_permission_drift_on_open_directory(preflight, tree):
    root, fd = tree
    with _pin(preflight, fd) as chain:
        (root / "alpha" / "beta").chmod(0o750)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


def test_rejects_policy_shape_and_bool_fd(preflight, tree):
    _, fd = tree
    for args in [
        (True, ("alpha",), ((os.geteuid(), (0o700,)),)),
        (fd, ("alpha",), ()),
        (fd, ("alpha",), ((True, (0o700,)),)),
        (fd, ("alpha",), ((os.geteuid(), (True,)),)),
        (fd, ["alpha"], ((os.geteuid(), (0o700,)),)),
    ]:
        with (
            pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
            preflight._pin_directory_chain(*args),
        ):
            pytest.fail("accepted malformed policy")


def test_no_host_action_or_public_entrypoint(preflight):

    assert not hasattr(preflight, "main")
    assert not hasattr(preflight, "preflight_incident")
    assert not hasattr(preflight, "capture_getconf")
    assert not hasattr(preflight, "capture_ps")
    source = MODULE.read_text()
    for token in ("subprocess", "os.kill", "os.unlink", "os.rmdir", "os.rename", "shutil"):
        assert token not in source
    assert "staging preflight rejected" in source


def test_literal_incident_catalog(preflight):
    cases = (
        (
            "stale-target",
            "ssh-over-mcp-e2e-i8ow1ni6",
            187176421,
            "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
        ),
        (
            "older-target",
            "ssh-over-mcp-e2e-w_kn4rus",
            186877220,
            "bf84c7aafa5c79d629fc04488b5e0bda1cd98cef",
        ),
    )
    for selector, name, inode, expected in cases:
        record = preflight._select_incident(selector)
        assert record.selector == selector
        assert record.basename == name
        assert record.device == 16777220
        assert record.inode == inode
        assert record.expected_commit == expected
        assert record.uid == 502
        assert record.mode == 0o700


@pytest.mark.parametrize(
    "selector",
    (
        "recover",
        "ssh-over-mcp-e2e-recover.cc8Del",
        "STALE-TARGET",
        "../stale-target",
        "",
        None,
        0,
        True,
    ),
)
def test_unknown_incident_selector_has_no_authority(preflight, selector):
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        preflight._select_incident(selector)


def test_owned_descriptors_closed_after_normal_context(preflight, tree):
    _, borrowed = tree
    with _pin(preflight, borrowed) as chain:
        owned = chain._fds
        assert owned and all(os.fstat(fd).st_ino > 0 for fd in owned)
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert os.fstat(borrowed).st_ino > 0


def test_stat_open_replacement_race_refuses(preflight, tree, monkeypatch):
    root, borrowed = tree
    real_open = os.open
    created = False

    def raced_open(name, flags, *, dir_fd=None):
        nonlocal created
        if name == "beta" and not created:
            created = True
            (root / "alpha" / "beta").rename(root / "alpha" / "gone")
            (root / "alpha" / "beta").mkdir(mode=0o700)
        return real_open(name, flags, dir_fd=dir_fd)

    monkeypatch.setattr(preflight.os, "open", raced_open)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted replaced child")
    assert created
    assert os.fstat(borrowed).st_ino > 0


def test_failed_child_open_closes_helper_fds(preflight, tree, monkeypatch):
    root, borrowed = tree
    (root / "alpha" / "beta").rename(root / "alpha" / "old")
    (root / "alpha" / "beta").symlink_to("old", target_is_directory=True)
    real_dup, real_open = os.dup, os.open
    created_fds = []

    def observed_dup(fd):
        result = real_dup(fd)
        created_fds.append(result)
        return result

    def observed_open(name, flags, *, dir_fd=None):
        result = real_open(name, flags, dir_fd=dir_fd)
        created_fds.append(result)
        return result

    monkeypatch.setattr(preflight.os, "dup", observed_dup)
    monkeypatch.setattr(preflight.os, "open", observed_open)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted symlink")
    assert len(created_fds) == 2
    for fd in created_fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert os.fstat(borrowed).st_ino > 0


@pytest.mark.parametrize("name", ("é", "bad\x01name", "x" * 256))
def test_refuses_non_ascii_control_and_oversized_name(preflight, tree, name):
    _, borrowed = tree
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_directory_chain(borrowed, (name,), ((os.geteuid(), (0o700,)),)),
    ):
        pytest.fail("accepted invalid child")


def test_pinned_record_is_frozen_and_detached(preflight, tree):
    from dataclasses import FrozenInstanceError

    _, borrowed = tree
    with _pin(preflight, borrowed) as chain:
        with pytest.raises(FrozenInstanceError):
            chain.metadata[0].inode = 999
        with pytest.raises(FrozenInstanceError):
            chain._initial = ()
        chain.revalidate()


def test_close_error_reports_sanitized_uncertainty_and_closes_remaining(
    preflight,
    tree,
    monkeypatch,
):
    _, borrowed = tree
    close_original = os.close
    once = False

    def close_with_ambiguous_result(fd):
        nonlocal once
        close_original(fd)
        if not once:
            once = True
            raise OSError("untrusted file descriptor details")

    monkeypatch.setattr(preflight.os, "close", close_with_ambiguous_result)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as failure,
        _pin(preflight, borrowed) as chain,
    ):
        owned = chain._fds
    assert type(failure.value.cleanup_uncertain) is bool
    assert failure.value.cleanup_uncertain is True
    assert "untrusted" not in str(failure.value)
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert os.fstat(borrowed).st_ino > 0
