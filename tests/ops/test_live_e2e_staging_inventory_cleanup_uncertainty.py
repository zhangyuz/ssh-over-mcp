"""Disposable regression: an inventory-owned FD close must not become settled."""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"
SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"


@pytest.fixture
def case(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("_inventory_cleanup_preflight_test", MODULE)
    assert spec and spec.loader
    preflight = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = preflight
    try:
        spec.loader.exec_module(preflight)
    finally:
        sys.modules.pop(spec.name, None)

    original = preflight._select_incident("stale-target")
    parent = tmp_path / "T"
    parent.mkdir(mode=0o700)
    root = parent / original.basename
    root.mkdir(mode=0o700)
    payload = root / "payload-content"
    payload.mkdir(mode=0o700)
    expected = payload / "expected_commit"
    expected.write_bytes((SHA + "\n").encode("ascii"))
    expected.chmod(0o600)
    for name in ("bootstrap-wheels", "payload-iso", "seed", "target.git", "wheels"):
        (root / name).mkdir(mode=0o700)
    for name in ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle"):
        entry = root / name
        entry.write_bytes(b"metadata only")
        entry.chmod(0o600)

    info = root.stat()
    fixture_incident = replace(original, device=info.st_dev, inode=info.st_ino, uid=os.geteuid())
    genuine = preflight._select_incident

    def fixture_select(selector):
        genuine(selector)
        return fixture_incident

    monkeypatch.setattr(preflight, "_select_incident", fixture_select)
    borrowed = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield preflight, root, borrowed
    finally:
        os.close(borrowed)


def _observe(preflight, borrowed):
    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        return preflight._observe_selected_inventory(chain, "stale-target")


@pytest.mark.parametrize("failing_close", ("duplicated-root", "nested-directory"))
def test_inventory_owned_close_ambiguity_propagates(case, monkeypatch, failing_close):
    preflight, root, borrowed = case
    real_dup, real_open, real_close = os.dup, os.open, os.close
    inventory_fd = None
    nested_fd = None
    injected = False

    def tracked_dup(fd):
        nonlocal inventory_fd
        result = real_dup(fd)
        if fd == selected_root_fd:
            inventory_fd = result
        return result

    def tracked_open(name, flags, *args, **kwargs):
        nonlocal nested_fd
        result = real_open(name, flags, *args, **kwargs)
        if name == "payload-content" and kwargs.get("dir_fd") == inventory_fd:
            nested_fd = result
        return result

    def ambiguous_close(fd):
        nonlocal injected
        real_close(fd)
        expected_fd = inventory_fd if failing_close == "duplicated-root" else nested_fd
        if fd == expected_fd and not injected:
            injected = True
            raise OSError("private close ambiguity")

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        selected_root_fd = chain._fds[-1]
        with monkeypatch.context() as patch:
            patch.setattr(os, "dup", tracked_dup)
            patch.setattr(os, "open", tracked_open)
            patch.setattr(os, "close", ambiguous_close)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as error:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert injected
        assert error.value.cleanup_uncertain is True
        assert "private" not in str(error.value)
        chain.revalidate()
    assert os.fstat(borrowed).st_ino == (root.parent).stat().st_ino


def test_failed_traversal_then_root_close_ambiguity_is_preserved(case, monkeypatch):
    preflight, _, borrowed = case
    real_dup, real_close, real_stat = os.dup, os.close, os.stat
    inventory_fd = None
    injected = False

    def tracked_dup(fd):
        nonlocal inventory_fd
        result = real_dup(fd)
        if fd == selected_root_fd:
            inventory_fd = result
        return result

    def ambiguous_close(fd):
        nonlocal injected
        real_close(fd)
        if fd == inventory_fd and not injected:
            injected = True
            raise OSError("secondary close unknown")

    def fail_stat(name, *args, **kwargs):
        if name == "target.bundle" and kwargs.get("dir_fd") is not None:
            raise OSError("injected traversal rejection")
        return real_stat(name, *args, **kwargs)

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        selected_root_fd = chain._fds[-1]
        with monkeypatch.context() as patch:
            patch.setattr(os, "dup", tracked_dup)
            patch.setattr(os, "close", ambiguous_close)
            patch.setattr(os, "stat", fail_stat)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as error:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert injected
        assert error.value.cleanup_uncertain is True
    assert os.fstat(borrowed).st_ino > 0


def test_normal_inventory_rejection_has_settled_cleanup(case):
    preflight, root, borrowed = case
    (root / "seed" / "unsafe-symlink").symlink_to(root / "wheels")
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as error:
        _observe(preflight, borrowed)
    assert error.value.cleanup_uncertain is False
    assert os.fstat(borrowed).st_ino > 0


def test_inventory_error_cleanup_contract_is_strict(case):
    preflight, _, _ = case
    inventory = preflight._fixed_inventory_module()
    assert inventory.InventoryError().cleanup_uncertain is False
    assert inventory.InventoryError(cleanup_uncertain=True).cleanup_uncertain is True
    for malformed in (1, None, "true", []):
        with pytest.raises(TypeError):
            inventory.InventoryError(cleanup_uncertain=malformed)


def test_two_ambiguous_inventory_closes_keep_uncertainty(case, monkeypatch):
    preflight, _, borrowed = case
    real_dup, real_open, real_close = os.dup, os.open, os.close
    collector_root = None
    collector_child = None
    ambiguous = set()

    def track_dup(fd):
        nonlocal collector_root
        result = real_dup(fd)
        if fd == selected_root_fd:
            collector_root = result
        return result

    def track_open(name, flags, *args, **kwargs):
        nonlocal collector_child
        result = real_open(name, flags, *args, **kwargs)
        if name == "payload-content" and kwargs.get("dir_fd") == collector_root:
            collector_child = result
        return result

    def two_failed_closes(fd):
        real_close(fd)
        if fd in (collector_root, collector_child):
            ambiguous.add(fd)
            raise OSError("ambiguous close after successful syscall")

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        selected_root_fd = chain._fds[-1]
        with monkeypatch.context() as patch:
            patch.setattr(os, "dup", track_dup)
            patch.setattr(os, "open", track_open)
            patch.setattr(os, "close", two_failed_closes)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as error:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert collector_root in ambiguous and collector_child in ambiguous
        assert type(error.value.cleanup_uncertain) is bool
        assert error.value.cleanup_uncertain is True
        chain.revalidate()
    assert os.fstat(borrowed).st_ino > 0


def test_scandir_owned_iterator_close_ambiguity_is_not_settled(case, monkeypatch):
    preflight, _, borrowed = case
    actual_scandir = os.scandir
    injected = False

    class UncertainIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __iter__(self):
            return iter(self.wrapped)

        def close(self):
            nonlocal injected
            self.wrapped.close()
            injected = True
            raise OSError("scandir-owned duplicate close ambiguous")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def uncertain_scandir(fd):
        return UncertainIterator(actual_scandir(fd))

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        with monkeypatch.context() as patch:
            patch.setattr(os, "scandir", uncertain_scandir)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as error:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert injected
        assert error.value.cleanup_uncertain is True
    assert os.fstat(borrowed).st_ino > 0


@pytest.mark.parametrize("fault", ("missing-status", "throwing-getter", "nonbool-status"))
def test_unreadable_inventory_cleanup_status_fails_uncertain(case, monkeypatch, fault):
    """Unknown collector cleanup must never be reported as settled."""
    preflight, root, borrowed = case
    inventory = preflight._fixed_inventory_module()
    failure = inventory.InventoryError(cleanup_uncertain=True)

    with monkeypatch.context() as patch:
        if fault == "missing-status":
            del failure._cleanup_uncertain
        elif fault == "throwing-getter":

            def broken_status(_self):
                raise RuntimeError("private getter failure details")

            patch.setattr(inventory.InventoryError, "cleanup_uncertain", property(broken_status))
        else:
            failure._cleanup_uncertain = "unknown"

        def refuse(_root_fd, *, uid):
            raise failure

        patch.setattr(inventory, "collect_staging_inventory", refuse)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as error:
            _observe(preflight, borrowed)

    assert type(error.value.cleanup_uncertain) is bool
    assert error.value.cleanup_uncertain is True
    assert "private" not in str(error.value)
    assert os.fstat(borrowed).st_ino == root.parent.stat().st_ino


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit, GeneratorExit, RuntimeError])
@pytest.mark.parametrize("secondary", [False, True])
def test_collector_owned_root_close_cancellation_remains_uncertain(
    case, monkeypatch, error_type, secondary
):
    preflight, _root, borrowed = case
    real_dup, real_close, real_stat = os.dup, os.close, os.stat
    duplicated_root = None
    triggered = False

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        selected_root = chain._fds[-1]

        def track_dup(fd):
            nonlocal duplicated_root
            result = real_dup(fd)
            if fd == selected_root:
                duplicated_root = result
            return result

        def close_once(fd):
            nonlocal triggered
            real_close(fd)
            if fd == duplicated_root and not triggered:
                triggered = True
                raise error_type("ambiguous owned FD close")

        def fail_traversal(path, *args, **kwargs):
            if secondary and path == "target.bundle" and kwargs.get("dir_fd") is not None:
                raise OSError("original traversal failure")
            return real_stat(path, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(os, "dup", track_dup)
            patch.setattr(os, "close", close_once)
            patch.setattr(os, "stat", fail_traversal)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as failure:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert triggered
        assert failure.value.cleanup_uncertain is True
        assert failure.value.__cause__ is None
        chain.revalidate()


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit, GeneratorExit, RuntimeError])
def test_scandir_iterator_close_cancellation_remains_uncertain(case, monkeypatch, error_type):
    preflight, _root, borrowed = case
    original_scandir = os.scandir
    triggered = False

    class OwnedIterator:
        def __init__(self, real):
            self.real = real

        def __iter__(self):
            return iter(self.real)

        def close(self):
            nonlocal triggered
            self.real.close()
            if not triggered:
                triggered = True
                raise error_type("iterator close interrupted")

    def replacement(fd):
        return OwnedIterator(original_scandir(fd))

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        with monkeypatch.context() as patch:
            patch.setattr(os, "scandir", replacement)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as failure:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert triggered
        assert failure.value.cleanup_uncertain is True
        assert failure.value.__cause__ is None
        chain.revalidate()


@pytest.mark.parametrize("boundary", ["dup", "scandir"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, RuntimeError])
def test_ambiguous_owned_resource_acquisition_is_not_reported_settled(
    case, monkeypatch, boundary, error_type
):
    preflight, root, borrowed = case
    original_dup, original_scandir, original_close = os.dup, os.scandir, os.close
    attempted = []

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        selected_root = chain._fds[-1]

        def uncertain_dup(fd):
            if (
                boundary == "dup"
                and fd == selected_root
                and sys._getframe(1).f_code.co_name == "collect_staging_inventory"
            ):
                # The test fixture disposes its own post-syscall clone; the
                # caller receives no FD, so it cannot prove a settled close.
                allocated = original_dup(fd)
                original_close(allocated)
                attempted.append("dup")
                raise error_type("private ambiguous dup")
            return original_dup(fd)

        def uncertain_scandir(fd):
            if boundary == "scandir":
                acquired = original_scandir(fd)
                acquired.close()
                attempted.append("scandir")
                raise error_type("private ambiguous iterator allocation")
            return original_scandir(fd)

        with monkeypatch.context() as patch:
            patch.setattr(os, "dup", uncertain_dup)
            patch.setattr(os, "scandir", uncertain_scandir)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as failure:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert attempted == [boundary]
        assert failure.value.cleanup_uncertain is True
        assert failure.value.__cause__ is None
        chain.revalidate()
    assert root.is_dir()


def test_failed_borrowed_root_fstat_before_acquisition_remains_settled(case, monkeypatch):
    preflight, _root, borrowed = case
    actual_fstat = os.fstat
    attempted = []

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        original_collect = preflight._fixed_inventory_module().collect_staging_inventory
        module = preflight._fixed_inventory_module()

        def reject_before_dup(fd):
            original = os.dup

            def forbidden_dup(*args):
                attempted.append("dup")
                return original(*args)

            with monkeypatch.context() as patch:
                patch.setattr(os, "dup", forbidden_dup)

                def fail_fstat(candidate):
                    if candidate == fd:
                        raise OSError("before collector acquisition")
                    return actual_fstat(candidate)

                patch.setattr(os, "fstat", fail_fstat)
                return original_collect(fd, uid=os.geteuid())

        with pytest.raises(module.InventoryError, match="^staging inventory rejected$") as failure:
            reject_before_dup(chain._fds[-1])
        assert failure.value.cleanup_uncertain is False
        assert attempted == []
        chain.revalidate()


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt])
def test_child_directory_open_acquisition_unknown_cleanup_is_true(case, monkeypatch, error_type):
    preflight, root, borrowed = case
    original_open, original_close = os.open, os.close
    injected = []

    def ambiguous_open(name, flags, *args, **kwargs):
        if (
            name == "payload-content"
            and kwargs.get("dir_fd") is not None
            and sys._getframe(1).f_code.co_name == "walk"
            and not injected
        ):
            owned = original_open(name, flags, *args, **kwargs)
            original_close(owned)  # Fixture disposes its own post-syscall FD.
            injected.append("child")
            raise error_type("ambiguous child acquisition")
        return original_open(name, flags, *args, **kwargs)

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", ambiguous_open)
            with pytest.raises(
                preflight.PreflightError, match="^staging preflight rejected$"
            ) as failure:
                preflight._observe_selected_inventory(chain, "stale-target")
        assert injected == ["child"]
        assert failure.value.cleanup_uncertain is True
        assert failure.value.__cause__ is None
        chain.revalidate()
    assert root.is_dir()
    assert os.fstat(borrowed).st_ino == root.parent.stat().st_ino
