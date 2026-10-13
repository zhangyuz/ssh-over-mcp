"""One approved incident only; no generic cleanup or marker recovery."""
from __future__ import annotations

import hashlib

# Fixed trusted sibling loading follows the already reviewed observer.
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from time import monotonic


def _sibling():
    source = Path(__file__).with_name("observe_recovery_root_metadata.py")
    spec = importlib.util.spec_from_file_location("_disposal_observer", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("incident authority unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


observer = _sibling()
preflight = observer.preflight
recovery = observer.recovery
DIR_FLAGS = observer._DIR_FLAGS
JOURNAL_NAME = "incident-disposition-20261013.jsonl"
MAX_JOURNAL_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 420
UID = 502
DEVICE = 16777220
# Full canonical inventory digests from operator-approved private observations.
CATALOG = (
    ("ssh-over-mcp-e2e-i8ow1ni6", 187176421, 18,
     "baf242d5bd2e9dc363bb1e0cbbc38d8f205b1b632afba952c02b695dc5283153"),
    ("ssh-over-mcp-e2e-recover.cc8Del", 186815322, 1332,
     "b331202dbc23cec8341b3f7946df680e730446238968775f7ea84d8007f2a9d1"),
    ("ssh-over-mcp-e2e-w_kn4rus", 186877220, 18,
     "008891ec4dfc438809dadac6b64d826498dfac5d39a8c06947382d5272e7d4a8"),
)
MARKER_META = {
    "ctime_ns": 1791315629879589515, "device": 16777220, "gid": 20,
    "inode": 187176420, "mode": 0o600, "mtime_ns": 1791315629879589515,
    "nlink": 1, "size": 75, "uid": UID,
}
_PHASE = "startup"


class DispositionError(RuntimeError):
    def __init__(self):
        super().__init__("approved incident disposition refused")


def _require(value):
    if not value:
        raise DispositionError()


def _encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def _digest(entries):
    return hashlib.sha256(_encode(entries)).hexdigest()


def _sync_directory(fd):
    os.fsync(fd)


class Journal:
    """Exclusive durable log. An existing log always refuses automatic replay."""

    def __init__(self, cache_fd, header):
        self.fd = None
        self.size = 0
        self.cache_fd = cache_fd
        try:
            fd = os.open(JOURNAL_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=cache_fd)
            self.fd = fd
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                     and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
            self.record = observer._record(JOURNAL_NAME, info)
            self.append({"event": "begin", **header})
            _sync_directory(cache_fd)
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        info = os.fstat(self.fd)
        _same_node(info, self.record)
        _same_node(os.stat(JOURNAL_NAME, dir_fd=self.cache_fd, follow_symlinks=False),
                   self.record)
        _require(info.st_size == self.size)

    def append(self, event):
        self.revalidate()
        payload = _encode(event) + b"\n"
        _require(len(payload) <= 16384 and self.size + len(payload) <= MAX_JOURNAL_BYTES)
        view = memoryview(payload)
        while view:
            written = os.write(self.fd, view)
            _require(written > 0)
            view = view[written:]
        self.size += len(payload)
        os.fsync(self.fd)
        updated = _same_node(os.fstat(self.fd), self.record, full=False)
        _require(updated["nlink"] == 1 and updated["size"] == self.size)
        self.record = updated
        self.revalidate()

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _same_node(info, expected, *, full=True):
    actual = observer._record(expected["path"], info)
    fields = tuple(expected) if full else ("kind", "device", "inode", "uid", "gid", "mode")
    _require(all(actual[k] == expected[k] for k in fields))
    return actual


def _children(fd, path, remaining):
    expected = {}
    for key, entry in remaining.items():
        if key == ".":
            continue
        parent, _, name = key.rpartition("/")
        if (parent or ".") == path:
            expected[name] = entry
    names = set()
    with os.scandir(fd) as iterator:
        for child in iterator:
            _require(len(names) < 4096 and child.name not in names)
            names.add(child.name)
    _require(names == set(expected))
    for name, entry in expected.items():
        _same_node(os.stat(name, dir_fd=fd, follow_symlinks=False), entry)


@contextmanager
def _parent(root_fd, path, remaining):
    owned = []
    fd = root_fd
    key = "."
    held = [(fd, key)]
    try:
        _same_node(os.fstat(fd), remaining[key])
        parts = path.split("/")[:-1]
        for part in parts:
            key = part if key == "." else key + "/" + part
            expected = remaining[key]
            _require(expected["kind"] == "directory")
            _same_node(os.stat(part, dir_fd=fd, follow_symlinks=False), expected)
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            owned.append(child)
            _same_node(os.fstat(child), expected)
            fd = child
            held.append((fd, key))

        def revalidate():
            for index, (item, entry_path) in enumerate(held):
                _same_node(os.fstat(item), remaining[entry_path])
                if index:
                    _same_node(os.stat(parts[index - 1], dir_fd=held[index - 1][0],
                                       follow_symlinks=False), remaining[entry_path])

        yield fd, key, revalidate
    finally:
        for item in reversed(owned):
            os.close(item)


def _empty_directory(fd):
    with os.scandir(fd) as iterator:
        _require(next(iterator, None) is None)


def _require_absent(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise DispositionError()


def _root_edge(parent_fd, name, root_fd, expected):
    _same_node(os.stat(name, dir_fd=parent_fd, follow_symlinks=False), expected)
    _same_node(os.fstat(root_fd), expected)


def _remove_root(parent_fd, name, root_fd, entries, journal, *, check, deadline):
    """Internal FD engine; no path or metadata parameters exposed by the CLI."""
    remaining = {entry["path"]: dict(entry) for entry in entries}
    _require(len(remaining) == len(entries) and 1 <= len(entries) <= 4096)
    _require("." in remaining)
    for entry in remaining.values():
        if entry["path"] != ".":
            observer._observe_path_key(entry["path"])
        _require(entry["kind"] in ("directory", "symlink"))
        _require(entry["uid"] == os.geteuid() and entry["device"] == entries[0]["device"])
        if entry["kind"] == "symlink":
            _require(entry["nlink"] == 1)
    _require(observer._collect_special_metadata(root_fd, uid=os.geteuid()) == tuple(entries))
    order = sorted(remaining, key=lambda p: (
        remaining[p]["kind"] != "symlink",
        -(0 if p == "." else len(p.split("/"))), p,
    ))
    for sequence, path in enumerate(order):
        _require(monotonic() < deadline)
        check()
        _root_edge(parent_fd, name, root_fd, remaining["."])
        expected = remaining[path]
        if path == ".":
            _require(len(remaining) == 1)
            _empty_directory(root_fd)
            _same_node(os.fstat(root_fd), expected)
            journal.append({"event": "intent", "root": name, "sequence": sequence,
                            "operation": "rmdir", "entry": expected})
            check()
            _root_edge(parent_fd, name, root_fd, expected)
            _empty_directory(root_fd)
            os.rmdir(name, dir_fd=parent_fd)
            _sync_directory(parent_fd)
            _require_absent(parent_fd, name)
            journal.append({"event": "confirmed", "root": name, "sequence": sequence})
            remaining.pop(path)
            continue
        with _parent(root_fd, path, remaining) as (fd, parent_path, revalidate):
            _children(fd, parent_path, remaining)
            leaf = path.rsplit("/", 1)[-1]
            _same_node(os.stat(leaf, dir_fd=fd, follow_symlinks=False), expected)
            operation = "unlink" if expected["kind"] == "symlink" else "rmdir"
            if operation == "rmdir":
                child = os.open(leaf, DIR_FLAGS, dir_fd=fd)
                try:
                    _same_node(os.fstat(child), expected)
                    _empty_directory(child)
                finally:
                    os.close(child)
            journal.append({"event": "intent", "root": name, "sequence": sequence,
                            "operation": operation, "entry": expected})
            check()
            _root_edge(parent_fd, name, root_fd, remaining["."])
            revalidate()
            _children(fd, parent_path, remaining)
            _same_node(os.stat(leaf, dir_fd=fd, follow_symlinks=False), expected)
            if operation == "unlink":
                os.unlink(leaf, dir_fd=fd)
            else:
                os.rmdir(leaf, dir_fd=fd)
            _sync_directory(fd)
            _require_absent(fd, leaf)
            previous_parent = remaining[parent_path]
            new_parent = _same_node(os.fstat(fd), previous_parent, full=False)
            # APFS directory nlink counts all children; Linux fixtures count subdirectories.
            decrement = 1 if sys.platform == "darwin" else int(operation == "rmdir")
            _require(new_parent["nlink"] == previous_parent["nlink"] - decrement)
            remaining.pop(path)
            remaining[parent_path] = new_parent
            _children(fd, parent_path, remaining)
            journal.append({"event": "confirmed", "root": name, "sequence": sequence})


def _validate_context():
    recovery._validate_context(os.environ)
    values = {k: os.environ.get(k, "") for k in (
        "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    _require(os.geteuid() == UID)
    _require(os.environ.get("GITHUB_WORKFLOW_REF") == (
        "zhangyuz/ssh-over-mcp/.github/workflows/"
        "live-local-e2e-dispose-historical.yml@refs/heads/main"))
    _require(os.environ.get("GITHUB_WORKFLOW_SHA") == values["GITHUB_SHA"])
    _require(re.fullmatch(r"[0-9a-f]{40}", values["GITHUB_SHA"]) is not None)
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", values["GITHUB_RUN_ID"]) is not None)
    _require(re.fullmatch(r"[1-9][0-9]{0,4}", values["GITHUB_RUN_ATTEMPT"]) is not None)
    return values


def _maintenance_window():
    # Avoid the scheduled cleaner window; this does not prove absence of a manual writer.
    _require(datetime.now().astimezone().hour not in (23, 0))
    result = subprocess.run(
        ["/bin/launchctl", "print", "system/com.apple.tmp_cleaner"],
        capture_output=True, timeout=5, check=True, env={"LC_ALL": "C"},
    )
    _require(len(result.stdout) <= 65536)
    _require(b"\tstate = not running\n" in result.stdout)


def dispose(*, apply):
    global _PHASE
    _PHASE = "context"
    context = _validate_context()
    deadline = monotonic() + MAX_SECONDS
    with ExitStack() as stack:
        _PHASE = "ancestry"
        parent = stack.enter_context(observer.private_tmp._pin_private_tmp())
        cache = stack.enter_context(preflight._pin_observed_fixed_cache_chain())
        parent_fd, cache_fd = parent._fds[-1], cache._fds[-1]
        _PHASE = "marker"
        marker = preflight._read_marker(cache_fd, uid=UID)
        _require(asdict(marker.metadata) == MARKER_META)
        roots = []
        for name, inode, count, digest in CATALOG:
            _PHASE = "catalog"
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _require(stat.S_ISDIR(before.st_mode)
                     and (before.st_dev, before.st_ino, before.st_uid, stat.S_IMODE(before.st_mode))
                     == (DEVICE, inode, UID, 0o700))
            fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
            stack.callback(os.close, fd)
            _require(observer._record(".", os.fstat(fd)) == observer._record(".", before))
            roots.append((name, fd, count, digest))

        sink = None

        def check():
            if sink is not None:
                sink.revalidate()
            _require(monotonic() < deadline)
            parent.revalidate()
            cache.revalidate()
            preflight._revalidate_marker(cache_fd, marker, uid=UID)
            preflight._require_fixed_marker_owner_absent()

        _PHASE = "process-a"
        _maintenance_window()
        check()
        preflight._observe_fixed_process_snapshot_checked()
        inventories = []
        _PHASE = "inventories"
        for name, fd, count, digest in roots:
            entries = observer._collect_special_metadata(fd, uid=UID)
            _require(len(entries) == count and _digest(entries) == digest)
            _require(observer._collect_special_metadata(fd, uid=UID) == entries)
            _require(all(e["kind"] in ("directory", "symlink") for e in entries))
            inventories.append(entries)
            check()
        _PHASE = "process-b"
        preflight._observe_fixed_process_snapshot_checked()
        check()
        _PHASE = "catalog-recheck"
        for (name, fd, _, _), entries in zip(roots, inventories, strict=True):
            _root_edge(parent_fd, name, fd, entries[0])
        if not apply:
            print("DISPOSITION_INSPECT directories=1362 symlinks=6 regular_files=0")
            return
        _PHASE = "journal"
        sink = stack.enter_context(Journal(cache_fd, {
            "schema_version": 1, "authority": context,
            "operator_approval": "2026-10-13T12:18:16-04:00",
            "catalog_digests": [r[3] for r in roots],
            "marker_metadata": MARKER_META,
            "maintenance_assumption": "operator-exclusive UID502 window; POSIX removal is not atomic",
        }))
        for (name, fd, _, _), entries in zip(roots, inventories, strict=True):
            _PHASE = "root-removal"
            _maintenance_window()
            preflight._observe_fixed_process_snapshot_checked()
            check()
            _remove_root(parent_fd, name, fd, entries, sink, check=check, deadline=deadline)
        _PHASE = "final"
        check()
        preflight._observe_fixed_process_snapshot_checked()
        for name, *_ in CATALOG:
            _require_absent(parent_fd, name)
        sink.append({"event": "complete", "removed_directories": 1362,
                     "removed_symlinks": 6, "marker_preserved": True})
    print("DISPOSITION_COMPLETE directories=1362 symlinks=6 marker_preserved=true")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    _require(args in ([], ["--apply"]))
    dispose(apply=bool(args))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):  # noqa: BLE001
        print(f"incident disposition refused at {_PHASE}; marker retained; "
              "journal may contain uncertain intentions", file=sys.stderr)
        raise SystemExit(70) from None
