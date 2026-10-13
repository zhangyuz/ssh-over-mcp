from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ops/live-e2e" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def collect(module, root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return module.collect_residual_inventory(fd, uid=os.geteuid())
    finally:
        os.close(fd)


def test_partial_inventory_is_metadata_only_and_does_not_weaken_staging(tmp_path, monkeypatch):
    module = load("staging_inventory")
    root = tmp_path / "partial"
    root.mkdir(mode=0o700)
    (root / "clean").mkdir(mode=0o700)
    leaf = root / "clean/fixture"
    leaf.write_bytes(b"secret content must not be read")
    leaf.chmod(0o600)
    real_open = os.open

    def directory_only(path, flags, *args, **kwargs):
        assert flags & os.O_DIRECTORY and flags & os.O_NOFOLLOW
        return real_open(path, flags, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("inventory accessed file content or mutated state")

    with monkeypatch.context() as guard:
        guard.setattr(os, "open", directory_only)
        for name in ("read", "write", "unlink", "rmdir", "rename", "chmod"):
            guard.setattr(os, name, forbidden)
        entries = collect(module, root)
    assert [entry.path for entry in entries] == [".", "clean", "clean/fixture"]
    assert leaf.read_bytes() == b"secret content must not be read"
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(module.InventoryError):
            module.collect_staging_inventory(fd, uid=os.geteuid())
    finally:
        os.close(fd)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "writable"])
def test_partial_inventory_refuses_unsafe_entries(tmp_path, kind):
    module = load("staging_inventory")
    root = tmp_path / "partial"
    root.mkdir(mode=0o700)
    leaf = root / "leaf"
    if kind == "symlink":
        leaf.symlink_to(tmp_path)
    elif kind == "fifo":
        os.mkfifo(leaf, 0o600)
    else:
        leaf.write_bytes(b"fixture")
        leaf.chmod(0o600 if kind == "hardlink" else 0o666)
        if kind == "hardlink":
            os.link(leaf, root / "alias")
    with pytest.raises(module.InventoryError):
        collect(module, root)


def test_partial_inventory_refuses_count_and_deadline(tmp_path, monkeypatch):
    module = load("staging_inventory")
    root = tmp_path / "partial"
    root.mkdir(mode=0o700)
    (root / "child").mkdir(mode=0o700)
    monkeypatch.setattr(module, "MAX_ENTRIES", 1)
    with pytest.raises(module.InventoryError):
        collect(module, root)
    monkeypatch.setattr(module, "MAX_ENTRIES", 4096)
    ticks = iter([0, 61])
    monkeypatch.setattr(module, "monotonic", lambda: next(ticks))
    with pytest.raises(module.InventoryError):
        collect(module, root)
