"""Inactive candidate v5 visibility contract for future fs_list/fs_search.

Syntactic validation only. This is deliberately NOT wired into the live v3/v4
HostExecutionPolicy, SMCP v1 or MCP registry: a digest supplied by a caller is
not an authenticated policy snapshot, and lexical checks alone do not authorize
directory enumeration, reading an inode or returning content.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_VISIBILITY_PATH_BYTES = 4096
MAX_ALLOW_ROOTS = 16
MAX_DENY_SUBTREES = 64
VisibilityOperation = Literal["fs_list", "fs_search"]


def canonical_visibility_path(path: object) -> str:
    """Refuse ambiguous paths rather than normalize a policy-sensitive name."""

    if type(path) is not str or not path.startswith("/") or path.startswith("//"):
        raise ValueError("invalid canonical filesystem path")
    try:
        nbytes = len(path.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise ValueError("invalid canonical filesystem path") from exc
    if not 1 <= nbytes < MAX_VISIBILITY_PATH_BYTES:
        raise ValueError("invalid canonical filesystem path")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("invalid canonical filesystem path")
    if "\\" in path or any(char in path for char in "*?[]"):
        raise ValueError("invalid canonical filesystem path")
    if path != "/":
        parts = path[1:].split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("invalid canonical filesystem path")
    return path


def _within(path: str, root: str) -> bool:
    return root == "/" or path == root or path.startswith(root + "/")


class VisibilityRules(BaseModel):
    """Per-operation lexical rule shape, not a complete permission decision."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    allow_roots: tuple[str, ...] = Field(min_length=1, max_length=MAX_ALLOW_ROOTS)
    deny_subtrees: tuple[str, ...] = Field(default=(), max_length=MAX_DENY_SUBTREES)

    @field_validator("allow_roots", "deny_subtrees")
    @classmethod
    def validate_roots(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        roots = tuple(canonical_visibility_path(path) for path in values)
        if "/" in roots or len(set(roots)) != len(roots):
            raise ValueError("invalid or duplicated visibility rules")
        return roots

    @model_validator(mode="after")
    def validate_visibility_conflicts(self) -> VisibilityRules:
        allows = self.allow_roots
        denies = self.deny_subtrees
        if any(a != b and _within(a, b) for a in allows for b in allows):
            raise ValueError("overlapping allow roots are ambiguous")
        if any(
            not any(_within(denied, allowed) and denied != allowed for allowed in allows)
            for denied in denies
        ):
            raise ValueError("deny subtree must be a strict child of an allow root")
        if any(a != b and _within(a, b) for a in denies for b in denies):
            raise ValueError("overlapping deny subtrees are ambiguous")
        return self

    def matches(self, path: str) -> bool:
        path = canonical_visibility_path(path)
        return any(_within(path, root) for root in self.allow_roots) and not any(
            _within(path, root) for root in self.deny_subtrees
        )


class VisibilityPolicyV5(BaseModel):
    """Candidate v5 shape; the v1/v3/v4 runtime has no loader for this model."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[5]
    host: str = Field(min_length=1, max_length=128)
    profile: str = Field(min_length=1, max_length=128)
    policy_epoch: int = Field(strict=True, ge=1)
    central_policy_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    enabled: bool = False
    operations: dict[VisibilityOperation, VisibilityRules]

    @model_validator(mode="after")
    def validate_operations(self) -> VisibilityPolicyV5:
        if set(self.operations) != {"fs_list", "fs_search"}:
            raise ValueError("both typed visibility rules must be explicitly present")
        return self

    def visible(self, *, operation: str, path: str) -> bool:
        if not self.enabled or operation not in self.operations:
            return False
        try:
            return self.operations[operation].matches(path)
        except ValueError:
            return False
