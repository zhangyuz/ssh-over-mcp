from __future__ import annotations

import hashlib
import posixpath
import tarfile
from dataclasses import dataclass
from typing import BinaryIO, Literal

_PUBLIC_ERROR = "native archive validation failed"
_READ_CHUNK = 1024 * 1024


class NativeArchiveError(RuntimeError):
    """Raised when untrusted package data violates the fixed archive contract."""


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_entries: int
    max_expanded_bytes: int
    max_path_bytes: int
    max_file_bytes: int
    max_link_hops: int


DEFAULT_LIMITS = ArchiveLimits(
    max_entries=32_768,
    max_expanded_bytes=768 * 1024 * 1024,
    max_path_bytes=4_096,
    max_file_bytes=128 * 1024 * 1024,
    max_link_hops=40,
)


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    path: str
    kind: Literal["directory", "file", "symlink"]
    mode: int
    uid: int
    gid: int
    size: int
    sha256: str | None
    link_target: str | None


def _fail() -> NativeArchiveError:
    return NativeArchiveError(_PUBLIC_ERROR)


def _validate_limits(limits: ArchiveLimits) -> None:
    values = (
        limits.max_entries,
        limits.max_expanded_bytes,
        limits.max_path_bytes,
        limits.max_file_bytes,
        limits.max_link_hops,
    )
    if any(type(value) is not int or value <= 0 for value in values):
        raise _fail()


def _canonical_member_path(
    raw: str, *, limit: int, allow_trailing_slash: bool
) -> str:
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\x00" in raw:
        raise _fail()

    candidate = raw
    if candidate.startswith("./"):
        candidate = candidate[2:]
    if candidate.endswith("/"):
        if not allow_trailing_slash or candidate.endswith("//"):
            raise _fail()
        candidate = candidate[:-1]

    if not candidate or candidate == ".":
        raise _fail()
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _fail()
    if len(candidate.encode("utf-8")) > limit:
        raise _fail()
    return "/" + candidate


def _canonical_link_target(entry_path: str, raw: str, *, limit: int) -> str:
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\x00" in raw:
        raise _fail()
    if len(raw.encode("utf-8")) > limit:
        raise _fail()
    if any(part in {"", "."} for part in raw.split("/")):
        raise _fail()

    base = posixpath.dirname(entry_path)
    resolved = posixpath.normpath(posixpath.join(base, raw))
    if not resolved.startswith("/") or resolved == "/" or resolved.startswith("/../"):
        raise _fail()
    if len(resolved.lstrip("/").encode("utf-8")) > limit:
        raise _fail()
    # normpath can hide a traversal above root only if the joined path was already absolute.
    depth = 0
    for part in (base.lstrip("/") + "/" + raw).split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise _fail()
        else:
            depth += 1
    return resolved


def _hash_regular_file(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise _fail()
    digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        chunk = extracted.read(min(_READ_CHUNK, remaining))
        if not chunk:
            raise _fail()
        remaining -= len(chunk)
        digest.update(chunk)
    if extracted.read(1):
        raise _fail()
    return digest.hexdigest()


def _resolve_link_path(path: str, links: dict[str, str], *, max_hops: int) -> str:
    pending = path.lstrip("/").split("/")
    resolved: list[str] = []
    seen_links: set[str] = set()
    hops = 0

    while pending:
        resolved.append(pending.pop(0))
        prefix = "/" + "/".join(resolved)
        target = links.get(prefix)
        if target is None:
            continue
        if prefix in seen_links:
            raise _fail()
        seen_links.add(prefix)
        hops += 1
        if hops > max_hops:
            raise _fail()
        pending = target.lstrip("/").split("/") + pending
        resolved = []

    return "/" + "/".join(resolved)


def _validate_link_graph(links: dict[str, str], *, max_hops: int) -> None:
    for source in links:
        _resolve_link_path(source, links, max_hops=max_hops)


def read_data_tar(
    stream: BinaryIO, *, limits: ArchiveLimits = DEFAULT_LIMITS
) -> tuple[ArchiveEntry, ...]:
    """Read an uncompressed package data tar into a bounded immutable recipe.

    This function authenticates nothing and extracts nothing. Callers must supply
    bytes that have already passed the higher-level package/source trust checks.
    """

    try:
        _validate_limits(limits)
        entries: list[ArchiveEntry] = []
        paths: set[str] = set()
        links: dict[str, str] = {}
        expanded = 0

        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for member in archive:
                if len(entries) >= limits.max_entries:
                    raise _fail()
                if member.pax_headers:
                    raise _fail()

                path = _canonical_member_path(
                    member.name,
                    limit=limits.max_path_bytes,
                    allow_trailing_slash=member.isdir(),
                )
                if path in paths:
                    raise _fail()
                paths.add(path)

                mode = member.mode & 0o7777
                if mode & 0o6000:
                    raise _fail()

                if member.isdir():
                    if member.size != 0:
                        raise _fail()
                    entry = ArchiveEntry(
                        path=path,
                        kind="directory",
                        mode=mode,
                        uid=member.uid,
                        gid=member.gid,
                        size=0,
                        sha256=None,
                        link_target=None,
                    )
                elif member.isreg():
                    if member.size < 0 or member.size > limits.max_file_bytes:
                        raise _fail()
                    if member.size > limits.max_expanded_bytes - expanded:
                        raise _fail()
                    expanded += member.size
                    digest = _hash_regular_file(archive, member)
                    entry = ArchiveEntry(
                        path=path,
                        kind="file",
                        mode=mode,
                        uid=member.uid,
                        gid=member.gid,
                        size=member.size,
                        sha256=digest,
                        link_target=None,
                    )
                elif member.issym():
                    if member.size != 0:
                        raise _fail()
                    resolved = _canonical_link_target(
                        path, member.linkname, limit=limits.max_path_bytes
                    )
                    links[path] = resolved
                    entry = ArchiveEntry(
                        path=path,
                        kind="symlink",
                        mode=mode,
                        uid=member.uid,
                        gid=member.gid,
                        size=0,
                        sha256=None,
                        link_target=member.linkname,
                    )
                else:
                    raise _fail()

                entries.append(entry)

        _validate_link_graph(links, max_hops=limits.max_link_hops)
        return tuple(entries)
    except NativeArchiveError:
        raise
    except (OSError, OverflowError, tarfile.TarError, UnicodeError, ValueError):
        raise _fail() from None
