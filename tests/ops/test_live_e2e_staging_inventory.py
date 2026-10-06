from __future__ import annotations

import builtins
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_inventory.py"
DIRECTORIES = ("bootstrap-wheels", "payload-content", "payload-iso", "seed", "target.git", "wheels")
FILES = ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle")


def _load_module() -> ModuleType:
    assert MODULE.is_file(), "dormant staging inventory collector is not implemented"
    name = "ssh_over_mcp_staging_inventory"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _staging(tmp_path: Path) -> Path:
    root = tmp_path / "staging"
    root.mkdir(mode=0o700)
    for name in DIRECTORIES:
        (root / name).mkdir(mode=0o700)
    for name in FILES:
        (root / name).write_bytes(b"do not read this fixture content")
        (root / name).chmod(0o600)
    return root


def _collect(module: ModuleType, root: Path):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        result = module.collect_staging_inventory(fd, uid=os.geteuid())
        assert stat.S_ISDIR(os.fstat(fd).st_mode), "collector closed borrowed root descriptor"
        return result
    finally:
        os.close(fd)


def test_inventory_records_exact_layout_without_reading_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    (root / "wheels/sub").mkdir(mode=0o700)
    leaf = root / "wheels/sub/secret-canary"
    leaf.write_bytes(b"fixture-secret-never-in-inventory")
    leaf.chmod(0o600)
    before = leaf.stat()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    real_open = os.open

    def forbidden(*args, **kwargs):
        pytest.fail("metadata collector attempted data access, mutation or execution")

    def directory_open(path, flags, *args, **kwargs):
        assert flags & os.O_DIRECTORY
        assert flags & os.O_NOFOLLOW
        return real_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as guard:
            guard.setattr(os, "open", directory_open)
            guard.setattr(os, "read", forbidden)
            guard.setattr(builtins, "open", forbidden)
            for name in ("write", "unlink", "rmdir", "mkdir", "rename", "chmod", "link"):
                guard.setattr(os, name, forbidden)
            guard.setattr(subprocess, "run", forbidden)
            guard.setattr(subprocess, "Popen", forbidden)
            entries = module.collect_staging_inventory(fd, uid=os.geteuid())
            encoded = module.encode_inventory(entries)
        assert os.fstat(fd).st_ino == root.stat().st_ino
    finally:
        os.close(fd)

    payload = json.loads(encoded)
    assert set(payload) == {"schema_version", "entries"}
    assert payload["schema_version"] == 1
    assert [entry["path"] for entry in payload["entries"]] == [
        ".",
        "bootstrap-wheels",
        "git-askpass",
        "overlay.qcow2",
        "payload-content",
        "payload-iso",
        "payload.iso",
        "seed",
        "seed.iso",
        "target.bundle",
        "target.git",
        "wheels",
        "wheels/sub",
        "wheels/sub/secret-canary",
    ]
    observed = payload["entries"][-1]
    assert observed == {
        "path": "wheels/sub/secret-canary",
        "kind": "regular",
        "device": before.st_dev,
        "inode": before.st_ino,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode": 0o600,
        "nlink": 1,
        "size": 33,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }
    assert b"fixture-secret-never-in-inventory" not in encoded
    assert leaf.read_bytes() == b"fixture-secret-never-in-inventory"
    assert module.encode_inventory(_collect(module, root)) == encoded
    assert (
        encoded
        == json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    )
    assert not encoded.endswith(b"\n")


@pytest.mark.parametrize("case", ["missing", "extra", "directory-as-file", "file-as-directory"])
def test_rejects_top_level_layout_mismatch(tmp_path: Path, case: str) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    if case == "missing":
        (root / "payload.iso").unlink()
    elif case == "extra":
        (root / "extra").mkdir()
    elif case == "directory-as-file":
        (root / "seed").rmdir()
        (root / "seed").write_bytes(b"wrong type")
    else:
        (root / "payload.iso").unlink()
        (root / "payload.iso").mkdir()
    with pytest.raises(module.InventoryError):
        _collect(module, root)


@pytest.mark.parametrize("case", ["symlink", "fifo", "socket", "hardlink"])
def test_rejects_unsafe_nested_objects(tmp_path: Path, case: str) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    path = root / "wheels/unsafe"
    sock = None
    if case == "symlink":
        path.symlink_to(tmp_path)
    elif case == "fifo":
        os.mkfifo(path, 0o600)
    elif case == "socket":
        sock = socket.socket(socket.AF_UNIX)
        # macOS AF_UNIX cannot bind pytest's long fixture pathname.
        with tempfile.TemporaryDirectory(prefix="inventory-socket-", dir="/tmp") as short:
            endpoint = Path(short) / "socket"
            sock.bind(str(endpoint))
            endpoint.rename(path)
    else:
        os.link(root / "target.bundle", path)
    try:
        with pytest.raises(module.InventoryError):
            _collect(module, root)
        assert path.lstat()
    finally:
        if sock is not None:
            sock.close()


@pytest.mark.parametrize("name", [".", "seed", "payload.iso"])
@pytest.mark.parametrize("mode", [0o702, 0o720])
def test_rejects_group_or_world_writable_entries(tmp_path: Path, name: str, mode: int) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    (root / name).chmod(mode)
    with pytest.raises(module.InventoryError):
        _collect(module, root)


def test_rejects_wrong_root_owner_and_type_without_closing_borrowed_fd(tmp_path: Path) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    for path, uid in [(root, os.geteuid() + 1), (root / "payload.iso", os.geteuid())]:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with pytest.raises(module.InventoryError):
                module.collect_staging_inventory(fd, uid=uid)
            assert os.fstat(fd).st_ino == path.stat().st_ino
        finally:
            os.close(fd)


def test_rejects_directory_inode_replacement_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    real_open = os.open
    replaced = False

    def replacing_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if path == "seed" and not replaced:
            replaced = True
            (root / "seed").rename(tmp_path / "old-seed")
            replacement.rename(root / "seed")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replacing_open)
    with pytest.raises(module.InventoryError):
        _collect(module, root)
    assert replaced


@pytest.mark.parametrize("change", ["file-mode", "file-time", "nested-add", "root-add", "remove"])
def test_rejects_metadata_or_layout_drift_during_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    real_stat = os.stat
    changed = False

    def changing_stat(path, *args, **kwargs):
        nonlocal changed
        info = real_stat(path, *args, **kwargs)
        if path == "target.bundle" and not changed:
            changed = True
            if change == "file-mode":
                (root / "git-askpass").chmod(0o640)
            elif change == "file-time":
                target = root / "git-askpass"
                before = real_stat(target)
                os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            elif change == "nested-add":
                (root / "bootstrap-wheels/added").mkdir(mode=0o700)
            elif change == "root-add":
                (root / "added").mkdir(mode=0o700)
            else:
                (root / "git-askpass").unlink()
        return info

    monkeypatch.setattr(os, "stat", changing_stat)
    with pytest.raises(module.InventoryError):
        _collect(module, root)
    assert changed


@pytest.mark.parametrize("total", [4096, 4097])
def test_bounds_total_entries_before_accepting_more_metadata(tmp_path: Path, total: int) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    for index in range(total - 12):
        (root / "wheels" / f"f{index:04d}").touch(mode=0o600)
    if total == 4096:
        assert len(_collect(module, root)) == 4096
    else:
        with pytest.raises(module.InventoryError):
            _collect(module, root)


@pytest.mark.parametrize("depth", [12, 13])
def test_bounds_depth_below_root(tmp_path: Path, depth: int) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    path = root / "wheels"
    for _ in range(depth - 1):
        path /= "d"
        path.mkdir(mode=0o700)
    if depth == 12:
        assert "wheels/" + "/".join(["d"] * 11) in {entry.path for entry in _collect(module, root)}
    else:
        with pytest.raises(module.InventoryError):
            _collect(module, root)


@pytest.mark.parametrize("elapsed", [60.0, 60.001])
def test_inspection_deadline_without_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, elapsed: float
) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    clock = iter([100.0])
    monkeypatch.setattr(module, "monotonic", lambda: next(clock, 100.0 + elapsed), raising=False)
    if elapsed == 60.0:
        assert len(_collect(module, root)) == 12
    else:
        with pytest.raises(module.InventoryError):
            _collect(module, root)


def test_canonical_encoding_sorts_detached_records(tmp_path: Path) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    entries = _collect(module, root)
    assert module.encode_inventory(tuple(reversed(entries))) == module.encode_inventory(entries)


def _synthetic_entries_at_json_limit(module: ModuleType, base):
    # Independent metadata fixtures: actual filename limits make these paths
    # impractical on macOS/Linux. No live-filesystem provenance is claimed.
    entries = [replace(base, path="\x01" * 280 + f"-{i:04d}", inode=i + 1) for i in range(1024)]
    payload = {"schema_version": 1, "entries": [asdict(entry) for entry in entries]}
    size = len(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    )
    remaining = 2 * 1024 * 1024 - size
    assert remaining > 0
    for i, entry in enumerate(entries):
        padding = min(remaining, 4096 - len(os.fsencode(entry.path)))
        entries[i] = replace(entry, path=entry.path + "x" * padding)
        remaining -= padding
        if not remaining:
            break
    assert remaining == 0
    return tuple(entries)


def test_canonical_json_byte_bound_accepts_exact_limit_and_rejects_next_byte(
    tmp_path: Path,
) -> None:
    module = _load_module()
    base = next(entry for entry in _collect(module, _staging(tmp_path)) if entry.kind == "regular")
    entries = _synthetic_entries_at_json_limit(module, base)
    assert len(module.encode_inventory(entries)) == 2 * 1024 * 1024
    oversized = entries[:-1] + (replace(entries[-1], path=entries[-1].path + "x"),)
    with pytest.raises(module.InventoryError):
        module.encode_inventory(oversized)


@pytest.mark.parametrize("length", [4096, 4097])
def test_encoding_bounds_filesystem_path_bytes(tmp_path: Path, length: int) -> None:
    module = _load_module()
    base = next(entry for entry in _collect(module, _staging(tmp_path)) if entry.kind == "regular")
    # Byte length differs from code-point count; this encoder-only fixture is
    # beyond native NAME_MAX, so it does not claim a real filesystem walk.
    entry = replace(base, path="é" * (length // 2) + "x" * (length % 2))
    if length == 4096:
        assert json.loads(module.encode_inventory((entry,)))["entries"][0]["path"] == entry.path
    else:
        with pytest.raises(module.InventoryError):
            module.encode_inventory((entry,))


@pytest.mark.parametrize("field", ["st_uid", "st_dev", "st_ino"])
def test_rejects_foreign_metadata_and_reused_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    real_stat = os.stat
    other = (root / "git-askpass").stat()

    def unsafe_stat(path, *args, **kwargs):
        info = real_stat(path, *args, **kwargs)
        if path != "target.bundle":
            return info
        values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        values[field] = other.st_ino if field == "st_ino" else getattr(info, field) + 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(os, "stat", unsafe_stat)
    with pytest.raises(module.InventoryError):
        _collect(module, root)


@pytest.mark.parametrize("path", ["", "/absolute", "a//b", "a/../b", "a/./b", "a\x00b"])
def test_encoder_rejects_noncanonical_relative_paths(tmp_path: Path, path: str) -> None:
    module = _load_module()
    base = next(entry for entry in _collect(module, _staging(tmp_path)) if entry.kind == "regular")
    with pytest.raises(module.InventoryError):
        module.encode_inventory((replace(base, path=path),))


def test_invalid_descriptor_has_generic_failure() -> None:
    module = _load_module()
    with pytest.raises(module.InventoryError):
        module.collect_staging_inventory(-1, uid=os.geteuid())


def test_rejects_noninteger_expected_uid(tmp_path: Path) -> None:
    module = _load_module()
    fd = os.open(_staging(tmp_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(module.InventoryError):
            module.collect_staging_inventory(fd, uid=float(os.geteuid()))
    finally:
        os.close(fd)


def test_fifo_rejection_is_prompt_in_a_bounded_disposable_child(tmp_path: Path) -> None:
    _load_module()
    root = _staging(tmp_path)
    os.mkfifo(root / "wheels/fifo", 0o600)
    program = """
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('inventory_fixture', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        module.collect_staging_inventory(fd, uid=os.geteuid())
    except module.InventoryError:
        assert os.fstat(fd)
    else:
        raise AssertionError('FIFO was accepted')
finally:
    os.close(fd)
"""
    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", program, str(MODULE), str(root)])
    try:
        assert child.wait(timeout=3) == 0
    finally:
        if child.poll() is None:
            child.kill()  # Only this disposable test process, never QEMU/orchestrator.
        child.wait()


def test_collection_json_budget_refuses_before_entry_count_limit(tmp_path: Path) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    fd = os.open(root / "wheels", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Descriptor-relative creation avoids macOS's short absolute PATH_MAX;
        # every component is native and depth stays below 12.
        for _ in range(8):
            name = "d" * 220
            os.mkdir(name, mode=0o700, dir_fd=fd)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        for index in range(1000):
            file_fd = os.open(
                f"{index:04d}" + "f" * 230, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd
            )
            os.close(file_fd)
    finally:
        os.close(fd)
    with pytest.raises(module.InventoryError):
        _collect(module, root)


def test_names_round_trip_and_directory_link_counts_are_allowed(tmp_path: Path) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    path = root / "wheels" / "control\n雪"
    path.mkdir(mode=0o700)
    (path / "nested").mkdir(mode=0o700)
    entries = _collect(module, root)
    payload = module.encode_inventory(entries)
    assert "wheels/control\n雪/nested" in {row["path"] for row in json.loads(payload)["entries"]}
    assert b"\\n" in payload and b"\\u96ea" in payload
    assert b"\n" not in payload
    assert all(entry.kind == "directory" for entry in entries if entry.path.endswith("nested"))


@pytest.mark.parametrize("failure", ["success", "unsafe", "limit", "stat", "open"])
def test_owned_descriptors_are_closed_and_errors_are_generic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    module = _load_module()
    root = _staging(tmp_path)
    if failure == "unsafe":
        (root / "seed/symlink").symlink_to(tmp_path)
    if failure == "limit":
        (root / "seed/extra").touch(mode=0o600)
        monkeypatch.setattr(module, "MAX_ENTRIES", 12)
    borrowed = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned: set[int] = set()
    real_open, real_dup, real_close, real_stat = os.open, os.dup, os.close, os.stat
    fd_root = Path("/dev/fd") if Path("/dev/fd").is_dir() else Path("/proc/self/fd")
    before = len(os.listdir(fd_root))

    def tracked_open(path, *args, **kwargs):
        if failure == "open" and path == "seed":
            raise OSError("fixture-private-canary")
        fd = real_open(path, *args, **kwargs)
        owned.add(fd)
        return fd

    def tracked_dup(fd):
        duplicate = real_dup(fd)
        owned.add(duplicate)
        return duplicate

    def tracked_close(fd):
        real_close(fd)
        owned.discard(fd)

    def failing_stat(path, *args, **kwargs):
        if failure == "stat" and path == "target.bundle":
            raise OSError("fixture-private-canary")
        return real_stat(path, *args, **kwargs)

    try:
        with monkeypatch.context() as guard:
            guard.setattr(os, "open", tracked_open)
            guard.setattr(os, "dup", tracked_dup)
            guard.setattr(os, "close", tracked_close)
            guard.setattr(os, "stat", failing_stat)
            if failure == "success":
                assert len(module.collect_staging_inventory(borrowed, uid=os.geteuid())) == 12
            else:
                with pytest.raises(module.InventoryError) as caught:
                    module.collect_staging_inventory(borrowed, uid=os.geteuid())
                assert str(caught.value) == "staging inventory rejected"
                assert caught.value.__cause__ is None
        assert not owned
        assert len(os.listdir(fd_root)) == before
        assert os.fstat(borrowed).st_ino == root.stat().st_ino
    finally:
        real_close(borrowed)
        for fd in owned:
            real_close(fd)


def test_encoder_rejects_unexpected_dataclass_fields(tmp_path: Path) -> None:
    module = _load_module()
    base = next(entry for entry in _collect(module, _staging(tmp_path)) if entry.kind == "regular")

    @dataclass(frozen=True, slots=True)
    class ExtendedEntry(module.InventoryEntry):
        unexpected: str = "fixture-private-canary"

    with pytest.raises(module.InventoryError):
        module.encode_inventory((ExtendedEntry(**asdict(base)),))


def test_rejects_oversized_path_before_filesystem_encoding_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    base = next(entry for entry in _collect(module, _staging(tmp_path)) if entry.kind == "regular")
    real_encode = os.fsencode

    def bounded_encode(path):
        assert len(path) <= 4096, "oversized path reached allocating filesystem encoder"
        return real_encode(path)

    monkeypatch.setattr(os, "fsencode", bounded_encode)
    with pytest.raises(module.InventoryError):
        module.encode_inventory((replace(base, path="x" * 4097),))
