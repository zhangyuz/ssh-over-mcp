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


def test_fixed_catalog_lookup_is_immutable(preflight):
    original = preflight._select_incident("stale-target")
    with pytest.raises(TypeError):
        preflight._INCIDENTS["stale-target"] = preflight._select_incident("older-target")
    assert preflight._select_incident("stale-target") is original


# A4/A5: all files/directories below are disposable test-owned fixtures.
FIXED_SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"
MARKER = b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}'


@pytest.fixture
def payload_tree(tmp_path):
    root = tmp_path / "stage"
    root.mkdir(mode=0o700)
    payload = root / "payload-content"
    payload.mkdir(mode=0o700)
    leaf = payload / "expected_commit"
    leaf.write_bytes((FIXED_SHA + "\n").encode("ascii"))
    leaf.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root, fd
    finally:
        os.close(fd)


@pytest.fixture
def marker_tree(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    leaf = cache / "active-run.json"
    leaf.write_bytes(MARKER)
    leaf.chmod(0o600)
    fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield cache, fd
    finally:
        os.close(fd)


def test_expected_commit_initial_inventory_and_final_binding(preflight, payload_tree):
    from types import SimpleNamespace

    root, fd = payload_tree
    with preflight._pin_expected_commit(
        fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as p:
        assert p.first.content == (FIXED_SHA + "\n").encode()
        m = p.first.metadata
        entry = SimpleNamespace(
            path="payload-content/expected_commit",
            kind="regular",
            **{key: getattr(m, key) for key in m.__dataclass_fields__},
        )
        preflight._require_expected_inventory_entry(entry, p.first)
        p.revalidate(FIXED_SHA, uid=os.geteuid())
    assert os.fstat(fd).st_ino == root.stat().st_ino


@pytest.mark.parametrize(
    "replacement",
    (
        b"X" * 40 + b"\n",
        b"0" * 40 + b"\n",
        b"0" * 40,
        b"\n",
        b"0" * 41 + b"\n",
        b"0" * 42,
        b"0" * 40 + b"\r",
    ),
)
def test_expected_commit_rejects_wrong_content(preflight, payload_tree, replacement):
    root, fd = payload_tree
    leaf = root / "payload-content" / "expected_commit"
    leaf.write_bytes(replacement)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_expected_commit(fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev),
    ):
        pytest.fail("accepted wrong content")


def test_expected_commit_refuses_symlink_and_hardlink(preflight, payload_tree):
    root, fd = payload_tree
    leaf = root / "payload-content" / "expected_commit"
    linked = root / "payload-content" / "other"
    os.link(leaf, linked)
    with (
        pytest.raises(preflight.PreflightError),
        preflight._pin_expected_commit(fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev),
    ):
        pytest.fail("accepted hardlink")
    linked.unlink()
    leaf.rename(linked)
    leaf.symlink_to("other")
    with (
        pytest.raises(preflight.PreflightError),
        preflight._pin_expected_commit(fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev),
    ):
        pytest.fail("accepted symlink")


def test_expected_commit_refuses_post_observation_replacement(preflight, payload_tree):
    root, fd = payload_tree
    leaf = root / "payload-content" / "expected_commit"
    with preflight._pin_expected_commit(
        fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as p:
        leaf.rename(leaf.with_name("old"))
        leaf.write_bytes((FIXED_SHA + "\n").encode())
        leaf.chmod(0o600)
        with pytest.raises(preflight.PreflightError):
            p.revalidate(FIXED_SHA, uid=os.geteuid())


def test_expected_commit_refuses_same_inode_rewrite(preflight, payload_tree):
    root, fd = payload_tree
    leaf = root / "payload-content" / "expected_commit"
    with preflight._pin_expected_commit(
        fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as p:
        leaf.write_bytes(b"0" * 40 + b"\n")
        leaf.write_bytes((FIXED_SHA + "\n").encode())
        with pytest.raises(preflight.PreflightError):
            p.revalidate(FIXED_SHA, uid=os.geteuid())


def test_expected_commit_detects_payload_edge_replacement(preflight, payload_tree):
    root, fd = payload_tree
    with preflight._pin_expected_commit(
        fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as p:
        (root / "payload-content").rename(root / "old-payload")
        (root / "payload-content").mkdir(mode=0o700)
        with pytest.raises(preflight.PreflightError):
            p.revalidate(FIXED_SHA, uid=os.geteuid())


def test_expected_commit_inventory_disagreement(preflight, payload_tree):
    from types import SimpleNamespace

    root, fd = payload_tree
    with preflight._pin_expected_commit(
        fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as p:
        m = p.first.metadata
        fields = m.__dataclass_fields__
        good = SimpleNamespace(
            path="payload-content/expected_commit",
            kind="regular",
            **{key: getattr(m, key) for key in fields},
        )
        bad = SimpleNamespace(**vars(good))
        bad.inode += 1
        with pytest.raises(preflight.PreflightError):
            preflight._require_expected_inventory_entry(bad, p.first)
        with pytest.raises(preflight.PreflightError):
            preflight._require_expected_inventory_entry(
                SimpleNamespace(**{**vars(good), "path": "fake"}), p.first
            )


def test_marker_initial_and_final_binding(preflight, marker_tree):
    cache, fd = marker_tree
    first = preflight._read_marker(fd, uid=os.geteuid())
    assert first.content == MARKER
    preflight._revalidate_marker(fd, first, uid=os.geteuid())
    assert os.fstat(fd).st_ino == cache.stat().st_ino


@pytest.mark.parametrize(
    "raw",
    (
        b"",
        b"[]",
        b"{}",
        b"true",
        b"1",
        b" ",
        b"garbage",
        b'{"target":"wrong","target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013,"owner_pid":38013}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":true}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013.0}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":NaN}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":999999999999999999999999}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":{"nested":[]}}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":"38013"}',
        b"[" * 2000 + b"]" * 2000,
        b'{"target":"\xff","owner_pid":38013}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}\x00',
    ),
)
def test_strict_marker_parser_rejects_invalid_json(preflight, raw):
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        preflight._parse_marker(raw)


def test_marker_refuses_raw_drift_even_equal_state(preflight, marker_tree):
    cache, fd = marker_tree
    first = preflight._read_marker(fd, uid=os.geteuid())
    leaf = cache / "active-run.json"
    leaf.write_bytes(b'{ "target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}')
    with pytest.raises(preflight.PreflightError):
        preflight._revalidate_marker(fd, first, uid=os.geteuid())


def test_marker_refuses_fifo(preflight, marker_tree):
    cache, fd = marker_tree
    leaf = cache / "active-run.json"
    leaf.unlink()
    os.mkfifo(leaf, 0o600)
    with pytest.raises(preflight.PreflightError):
        preflight._read_marker(fd, uid=os.geteuid())


def test_no_arbitrary_regular_file_content_read(preflight, payload_tree, monkeypatch):
    root, fd = payload_tree
    opened = []
    real_open = os.open

    def audited(name, flags, *args, **kwargs):
        opened.append(name)
        assert name in ("payload-content", "expected_commit")
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(preflight.os, "open", audited)
    with preflight._pin_expected_commit(
        fd, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as p:
        p.revalidate(FIXED_SHA, uid=os.geteuid())
    assert opened == ["payload-content", "expected_commit", "expected_commit"]


def _populate_collector_layout(root):
    directories = (
        "bootstrap-wheels",
        "payload-iso",
        "seed",
        "target.git",
        "wheels",
    )
    regulars = (
        "git-askpass",
        "overlay.qcow2",
        "payload.iso",
        "seed.iso",
        "target.bundle",
    )
    for name in directories:
        (root / name).mkdir(mode=0o700)
    for name in regulars:
        path = root / name
        path.write_bytes(b"content is never read during inventory")
        path.chmod(0o600)


def test_actual_inventory_collector_bound_to_pinned_commit(
    preflight,
    payload_tree,
    monkeypatch,
):
    root, borrowed = payload_tree
    _populate_collector_layout(root)
    monkeypatch.syspath_prepend(str(MODULE.parent))
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:
        entries = preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())
        assert type(entries) is tuple
        paths = {record.path for record in entries}
        assert "." in paths
        assert "payload-content/expected_commit" in paths
        assert len(paths) >= 13
        observation.revalidate(FIXED_SHA, uid=os.geteuid())
        with pytest.raises((AttributeError, TypeError)):
            entries[0].path = "forged"
    assert os.fstat(borrowed).st_ino == root.stat().st_ino


def test_inventory_refuses_expected_commit_drift(
    preflight,
    payload_tree,
    monkeypatch,
):
    root, borrowed = payload_tree
    _populate_collector_layout(root)
    monkeypatch.syspath_prepend(str(MODULE.parent))
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:
        leaf = root / "payload-content" / "expected_commit"
        leaf.write_bytes(b"0" * 40 + b"\n")
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())


@pytest.mark.parametrize("mode", (0o400, 0o444, 0o600, 0o644))
def test_expected_commit_safe_read_only_permissions(preflight, payload_tree, mode):
    root, borrowed = payload_tree
    (root / "payload-content" / "expected_commit").chmod(mode)
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:
        assert observation.first.metadata.mode == mode
        observation.revalidate(FIXED_SHA, uid=os.geteuid())


@pytest.mark.parametrize("mode", (0o620, 0o602, 0o777))
def test_expected_commit_rejects_group_or_world_writable(preflight, payload_tree, mode):
    root, borrowed = payload_tree
    (root / "payload-content" / "expected_commit").chmod(mode)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_expected_commit(
            borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
        ),
    ):
        pytest.fail("accepted unsafe commit")


def test_marker_accepts_exact_maximum_payload(preflight, marker_tree):
    cache, fd = marker_tree
    extra = b" " * (4096 - len(MARKER))
    leaf = cache / "active-run.json"
    leaf.write_bytes(MARKER + extra)
    observation = preflight._read_marker(fd, uid=os.geteuid())
    assert len(observation.content) == 4096
    preflight._revalidate_marker(fd, observation, uid=os.geteuid())


def test_marker_over_maximum_refuses(preflight, marker_tree):
    cache, fd = marker_tree
    (cache / "active-run.json").write_bytes(MARKER + b" " * 4096)
    with pytest.raises(preflight.PreflightError):
        preflight._read_marker(fd, uid=os.geteuid())


def test_inventory_import_shadowing_does_not_execute_foreign_code(
    preflight, payload_tree, monkeypatch
):
    from types import ModuleType

    root, borrowed = payload_tree
    _populate_collector_layout(root)
    forged = ModuleType("staging_inventory")
    forged.__file__ = "/tmp/foreign/staging_inventory.py"

    def forbidden(*_args, **_kwargs):
        pytest.fail("foreign collector must not execute")

    forged.collect_staging_inventory = forbidden
    monkeypatch.setitem(sys.modules, "staging_inventory", forged)
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:
        entries = preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())
        assert any(entry.path == "payload-content/expected_commit" for entry in entries)


def test_expected_commit_revalidation_bad_sha_fails_closed(preflight, payload_tree):
    root, borrowed = payload_tree
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:
        for bad in (None, True, "x", "0" * 40 + "x"):
            with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
                observation.revalidate(bad, uid=os.geteuid())


def test_marker_stat_open_same_bytes_replacement_refuses(preflight, marker_tree, monkeypatch):
    cache, borrowed = marker_tree
    original_open = os.open
    swapped = False

    def swapping_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if name == "active-run.json" and not swapped:
            swapped = True
            leaf = cache / name
            leaf.rename(cache / "old-marker")
            leaf.write_bytes(MARKER)
            leaf.chmod(0o600)
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(preflight.os, "open", swapping_open)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        preflight._read_marker(borrowed, uid=os.geteuid())
    assert swapped
    assert os.fstat(borrowed).st_ino > 0


def test_expected_commit_stat_open_same_bytes_replacement_refuses(
    preflight, payload_tree, monkeypatch
):
    root, borrowed = payload_tree
    original_open = os.open
    swapped = False

    def swapping_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if name == "expected_commit" and not swapped:
            swapped = True
            leaf = root / "payload-content" / name
            leaf.rename(leaf.with_name("former"))
            leaf.write_bytes((FIXED_SHA + "\n").encode())
            leaf.chmod(0o600)
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(preflight.os, "open", swapping_open)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_expected_commit(
            borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
        ),
    ):
        pytest.fail("accepted replaced inode")
    assert swapped
    assert os.fstat(borrowed).st_ino > 0


def test_fixed_leaf_reader_refuses_custom_budget_or_flags(preflight, marker_tree):
    _, borrowed = marker_tree
    for name, mode, limit, device in (
        ("active-run.json", 0o600, 8192, None),
        ("active-run.json", None, 4096, None),
        ("expected_commit", 0o600, 41, 1),
        ("expected_commit", None, 4096, 1),
        ("../../some-other-file", None, 41, 1),
    ):
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            preflight._read_named_regular(
                borrowed, name, uid=os.geteuid(), mode=mode, limit=limit, device=device
            )


def test_fixed_collector_returns_stable_record_class(preflight, payload_tree):
    root, borrowed = payload_tree
    _populate_collector_layout(root)
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:
        first = preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())
        second = preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())
        assert first == second
        assert all(type(left) is type(right) for left, right in zip(first, second))


def test_final_expected_commit_refuses_payload_swap_during_reread(
    preflight, payload_tree, monkeypatch
):
    """Pinned old payload descriptor cannot authorize the new live path."""
    root, borrowed = payload_tree
    real_read = preflight._read_named_regular
    altered = False
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:

        def swapped_read(*args, **kwargs):
            nonlocal altered
            if not altered:
                altered = True
                (root / "payload-content").rename(root / "moved-away")
                new_payload = root / "payload-content"
                new_payload.mkdir(mode=0o700)
                leaf = new_payload / "expected_commit"
                leaf.write_bytes((FIXED_SHA + "\n").encode("ascii"))
                leaf.chmod(0o600)
            return real_read(*args, **kwargs)

        monkeypatch.setattr(preflight, "_read_named_regular", swapped_read)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            observation.revalidate(FIXED_SHA, uid=os.geteuid())
        assert altered
        assert os.fstat(borrowed).st_ino == root.stat().st_ino


def test_final_expected_commit_refuses_leaf_swap_after_reread(preflight, payload_tree, monkeypatch):
    """A replaced directory entry is rejected even when the read was valid."""
    root, borrowed = payload_tree
    real_read = preflight._read_named_regular
    altered = False
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:

        def swapped_read(*args, **kwargs):
            nonlocal altered
            result = real_read(*args, **kwargs)
            if not altered:
                altered = True
                leaf = root / "payload-content" / "expected_commit"
                leaf.rename(leaf.with_name("moved-expected-commit"))
                leaf.write_bytes((FIXED_SHA + "\n").encode("ascii"))
                leaf.chmod(0o600)
            return result

        monkeypatch.setattr(preflight, "_read_named_regular", swapped_read)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            observation.revalidate(FIXED_SHA, uid=os.geteuid())
        assert altered


def test_collector_propagates_known_cleanup_uncertainty(preflight, payload_tree, monkeypatch):
    root, borrowed = payload_tree
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:

        def uncertain():
            raise preflight.PreflightError(cleanup_uncertain=True)

        monkeypatch.setattr(preflight, "_fixed_inventory_module", uncertain)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
            preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())
        assert err.value.cleanup_uncertain is True


def test_directory_metadata_memory_error_is_sanitized(preflight, tree, monkeypatch):
    _, borrowed = tree

    def exhausted(_stat):
        raise MemoryError("sensitive allocation internals")

    monkeypatch.setattr(preflight, "_metadata", exhausted)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err,
        _pin(preflight, borrowed),
    ):
        pytest.fail("unexpected pin success")
    assert type(err.value.cleanup_uncertain) is bool
    assert "sensitive" not in str(err.value)
    assert os.fstat(borrowed).st_ino > 0


def test_final_directory_revalidation_memory_error_is_sanitized(preflight, tree, monkeypatch):
    _, borrowed = tree
    with _pin(preflight, borrowed) as chain:

        def exhausted(_stat):
            raise MemoryError("sensitive allocation internals")

        monkeypatch.setattr(preflight, "_metadata", exhausted)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


def test_sibling_loader_syntax_error_is_sanitized(preflight, payload_tree, monkeypatch):
    root, borrowed = payload_tree
    with preflight._pin_expected_commit(
        borrowed, FIXED_SHA, uid=os.geteuid(), device=root.stat().st_dev
    ) as observation:

        def invalid_loader():
            raise SyntaxError("sensitive import internals")

        monkeypatch.setattr(preflight, "_fixed_inventory_module", invalid_loader)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
            preflight._collect_and_bind(borrowed, observation, uid=os.geteuid())
        assert err.value.cleanup_uncertain is False
        assert "sensitive" not in str(err.value)


def test_directory_policy_allocation_failure_is_sanitized(preflight, tree, monkeypatch):
    _, borrowed = tree

    def exhausted(*_args, **_kwargs):
        raise MemoryError("private policy allocation details")

    monkeypatch.setattr(preflight, "_verify_parts_and_policies", exhausted)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as error,
        _pin(preflight, borrowed),
    ):
        pytest.fail("accepted policy allocation failure")
    assert error.value.cleanup_uncertain is False
    assert "private" not in str(error.value)
    assert os.fstat(borrowed).st_ino > 0
