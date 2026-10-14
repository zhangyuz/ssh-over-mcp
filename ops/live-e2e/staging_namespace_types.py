"""Detached evidence for the dormant protected staging contract."""

from __future__ import annotations

from dataclasses import dataclass


class NamespaceError(RuntimeError):
    def __init__(self, reason: str, *, cleanup_uncertain: bool = False) -> None:
        super().__init__("protected staging inspection rejected")
        self.reason = reason
        self.cleanup_uncertain = cleanup_uncertain


@dataclass(frozen=True, slots=True)
class NativeTempParent:
    source: str
    canonical: str


@dataclass(frozen=True, slots=True)
class SelectorSnapshot:
    overrides: tuple[str | None, str | None, str | None]
    module_loaded: bool
    cached: str | None


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class AclSnapshot:
    serialized: bytes
    tags: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ParentSnapshot:
    label: str
    chain: tuple[DirectoryIdentity, ...]
    acls: tuple[AclSnapshot, ...]


@dataclass(frozen=True, slots=True)
class ProviderContext:
    uid: int
    euid: int
    gid: int
    egid: int
    groups: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class NamespaceSnapshot:
    native: NativeTempParent
    selectors: SelectorSnapshot
    context: ProviderContext
    protected_missing: tuple[str, ...]
    parents: tuple[ParentSnapshot, ...]
