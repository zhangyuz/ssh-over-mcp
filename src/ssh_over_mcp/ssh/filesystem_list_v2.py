"""Opt-in control-plane contracts; no default signer or epoch authority."""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Protocol

import asyncssh
from pydantic import BaseModel, ConfigDict, Field

from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    SignedVisibilitySnapshot,
    VisibilitySnapshotV5,
)
from ssh_over_mcp.policy.engine import PolicyEngine

MAX_LIST_RESPONSE_BYTES = 64 * 1024


class VisibilityAuthority(Protocol):
    """Trusted injection only, never constructed from tool arguments.

    Implementations must own host-specific signing and authenticated monotonic
    epoch/revocation state. No production implementation is supplied here.
    The engine and transport must use the same inventory object.
    """

    engine: PolicyEngine

    def current_epoch(self, *, host: str, policy_sha256: str) -> int: ...
    def sign(self, snapshot: VisibilitySnapshotV5) -> SignedVisibilitySnapshot: ...
    def is_active(self, snapshot: VisibilitySnapshotV5) -> bool: ...


def pinned_host_identity(key: str) -> str:
    # Hash the RFC 4253 public-key blob, excluding OpenSSH comments/whitespace.
    if "\n" in key or "\r" in key:
        raise ValueError("invalid inventory host key")
    public = asyncssh.import_public_key(key)
    return hashlib.sha256(public.public_data).hexdigest()


class FilesystemListEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str = Field(max_length=4096)
    kind: Literal["regular", "directory"]
    size: int = Field(ge=0, le=2**63 - 1)
    mode: int = Field(ge=0, le=0o7777)
    uid: int = Field(ge=0, le=2**32 - 1)
    gid: int = Field(ge=0, le=2**32 - 1)
    mtime_ns: int = Field(ge=-(2**63), le=2**63 - 1)


class SSHFilesystemListResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    request_id: str
    host: str
    root: str
    policy_epoch: int = Field(ge=1)
    snapshot_id: str
    entries: tuple[FilesystemListEntry, ...] = Field(max_length=64)


def decode_list_response(data: bytes) -> SSHFilesystemListResult:
    if len(data) > MAX_LIST_RESPONSE_BYTES:
        raise ValueError("response exceeds bound")
    # Bound nesting BEFORE invoking the recursive JSON parser. The schema needs
    # only object -> entries array -> entry object; strings cannot affect depth.
    depth = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 3:
                raise ValueError("response nesting exceeds bound")
        elif byte in (93, 125):
            depth -= 1

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate response member")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError("invalid JSON constant")

    value = json.loads(
        data.decode("utf-8", errors="strict"),
        object_pairs_hook=unique,
        parse_constant=invalid_constant,
    )
    # Strict Python validation avoids coercion, except JSON's array -> tuple.
    if not isinstance(value, dict) or type(value.get("entries")) is not list:
        raise ValueError("invalid response shape")
    value["entries"] = tuple(value["entries"])
    return SSHFilesystemListResult.model_validate(value)
