"""Dormant, metadata-only staging inventory; no CLI or workflow caller."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass
from time import monotonic

MAX_ENTRIES = 4096
MAX_DEPTH = 12
MAX_PATH_BYTES = 4096
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 60
_PREFIX = b'{"entries":['
_SUFFIX = b'],"schema_version":1}'

_LAYOUT = {
    "bootstrap-wheels": "directory",
    "payload-content": "directory",
    "payload-iso": "directory",
    "seed": "directory",
    "target.git": "directory",
    "wheels": "directory",
    "git-askpass": "regular",
    "overlay.qcow2": "regular",
    "payload.iso": "regular",
    "seed.iso": "regular",
    "target.bundle": "regular",
}
_FAILURE = "staging inventory rejected"


class InventoryError(RuntimeError):
    """The inventory cannot be accepted safely."""


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    path: str
    kind: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _entry(path: str, info: os.stat_result) -> InventoryEntry:
    return InventoryEntry(
        path=path,
        kind=(
            "directory"
            if stat.S_ISDIR(info.st_mode)
            else "regular"
            if stat.S_ISREG(info.st_mode)
            else "unsupported"
        ),
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        nlink=info.st_nlink,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def _path_key(path: str) -> bytes:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > MAX_PATH_BYTES  # Lower bound on encoded bytes; reject before allocation.
        or "\x00" in path
        or (path != "." and any(part in {"", ".", ".."} for part in path.split("/")))
        or (path != "." and len(path.split("/")) > MAX_DEPTH)
    ):
        raise InventoryError(_FAILURE)
    raw = os.fsencode(path)
    if len(raw) > MAX_PATH_BYTES:
        raise InventoryError(_FAILURE)
    return raw


def _encode_entry(entry: InventoryEntry) -> bytes:
    if type(entry) is not InventoryEntry:
        raise InventoryError(_FAILURE)
    _path_key(entry.path)
    return json.dumps(
        asdict(entry), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()


def collect_staging_inventory(root_fd: int, *, uid: int) -> tuple[InventoryEntry, ...]:
    """Borrow a pinned root descriptor; return detached metadata records."""
    if type(root_fd) is not int or type(uid) is not int or uid < 0:
        raise InventoryError(_FAILURE)
    entries: list[InventoryEntry] = []
    identities: set[tuple[int, int]] = set()
    deadline = monotonic() + MAX_SECONDS
    reserved = 1  # Include the root; descendants are reserved during enumeration.
    encoded_size = len(_PREFIX) + len(_SUFFIX)

    def check_deadline() -> None:
        if monotonic() > deadline:
            raise InventoryError(_FAILURE)

    def append(record: InventoryEntry) -> None:
        nonlocal encoded_size
        check_deadline()
        encoded_size += len(_encode_entry(record)) + bool(entries)
        if len(entries) >= MAX_ENTRIES or encoded_size > MAX_JSON_BYTES:
            raise InventoryError(_FAILURE)
        check_deadline()
        entries.append(record)

    def names_at(fd: int, path: str, *, verify_count: int | None = None) -> list[str]:
        nonlocal reserved
        names: list[str] = []
        # scandir(fd) owns its internal duplicate, not the borrowed descriptor.
        with os.scandir(fd) as iterator:
            for item in iterator:
                check_deadline()
                relative = item.name if path == "." else f"{path}/{item.name}"
                _path_key(relative)
                if verify_count is None:
                    if reserved >= MAX_ENTRIES:
                        raise InventoryError(_FAILURE)
                    reserved += 1
                elif len(names) >= verify_count:
                    raise InventoryError(_FAILURE)
                names.append(item.name)
        check_deadline()
        return sorted(names, key=os.fsencode)

    def validated(path: str, info: os.stat_result) -> InventoryEntry:
        directory = stat.S_ISDIR(info.st_mode)
        regular = stat.S_ISREG(info.st_mode)
        identity = (info.st_dev, info.st_ino)
        if (
            not (directory or regular)
            or info.st_uid != uid
            or info.st_dev != device
            or stat.S_IMODE(info.st_mode) & 0o022
            or (regular and info.st_nlink != 1)
            or identity in identities
        ):
            raise InventoryError(_FAILURE)
        identities.add(identity)
        return _entry(path, info)

    def walk(fd: int, path: str, expected: InventoryEntry | None = None) -> None:
        record = validated(path, os.fstat(fd))
        if record.kind != "directory" or (expected is not None and record != expected):
            raise InventoryError(_FAILURE)
        append(record)
        names = names_at(fd, path)
        if path == "." and set(names) != set(_LAYOUT):
            raise InventoryError(_FAILURE)
        observed: dict[str, InventoryEntry] = {}
        for name in names:
            check_deadline()
            relative = name if path == "." else f"{path}/{name}"
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            snapshot = _entry(relative, info)
            observed[name] = snapshot
            if path == "." and snapshot.kind != _LAYOUT[name]:
                raise InventoryError(_FAILURE)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, relative, snapshot)
                finally:
                    os.close(child)
            else:
                append(validated(relative, info))
        if names != names_at(fd, path, verify_count=len(names)):
            raise InventoryError(_FAILURE)
        for name, snapshot in observed.items():
            check_deadline()
            if snapshot != _entry(snapshot.path, os.stat(name, dir_fd=fd, follow_symlinks=False)):
                raise InventoryError(_FAILURE)
        if record != _entry(path, os.fstat(fd)):
            raise InventoryError(_FAILURE)

    try:
        device = os.fstat(root_fd).st_dev
        owned = os.dup(root_fd)
        try:
            walk(owned, ".")
        finally:
            os.close(owned)
        check_deadline()
        result = tuple(sorted(entries, key=lambda entry: _path_key(entry.path)))
        check_deadline()
    except (OSError, ValueError, TypeError):
        raise InventoryError(_FAILURE) from None
    return result


def encode_inventory(entries: tuple[InventoryEntry, ...]) -> bytes:
    """Encode the detached inventory, without workflow provenance."""
    try:
        if len(entries) > MAX_ENTRIES:
            raise InventoryError(_FAILURE)
        result = bytearray(_PREFIX)
        for index, entry in enumerate(sorted(entries, key=lambda entry: _path_key(entry.path))):
            encoded = _encode_entry(entry)
            if len(result) + bool(index) + len(encoded) + len(_SUFFIX) > MAX_JSON_BYTES:
                raise InventoryError(_FAILURE)
            if index:
                result.extend(b",")
            result.extend(encoded)
        result.extend(_SUFFIX)
        return bytes(result)
    except (OSError, ValueError, TypeError):
        raise InventoryError(_FAILURE) from None
