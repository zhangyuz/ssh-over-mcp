"""Strict, isolated SMCP v2 typed filesystem listing request framing.

No v2 request is processed by the production SMCP v1 Host Agent, and no
v2 Host Policy key or operation is activated by importing this module.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Mapping
from typing import BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ssh_over_mcp.host_agent.visibility_policy_v5 import canonical_visibility_path
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import SignedVisibilitySnapshot

MAGIC_V2 = b"SMCP\x00\x02"
MAX_METADATA_V2 = 64 * 1024
FORCE_COMMAND_V2 = "mcp-v2"


class ProtocolV2Error(ValueError):
    """Fail-closed SMCP v2 request framing or context error."""


class FSListRequestV2(BaseModel):
    """One complete directory (no pagination or cursor claims)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[2] = 2
    request_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    profile: str = Field(min_length=1, max_length=128)
    operation: Literal["fs_list"] = "fs_list"
    root: str
    max_entries: int = Field(strict=True, ge=1, le=64)
    signed_snapshot: SignedVisibilitySnapshot

    @model_validator(mode="after")
    def require_exact_binding(self) -> FSListRequestV2:
        expected = self.signed_snapshot.payload
        if (
            canonical_visibility_path(self.root) != self.root
            or expected.request_id != self.request_id
            or expected.profile != self.profile
            or expected.operation != self.operation
            or expected.root != self.root
            or expected.max_entries != self.max_entries
        ):
            raise ValueError("v2 snapshot does not match request")
        return self


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ProtocolV2Error("duplicate v2 request member")
        result[name] = value
    return result


def _decode_metadata(metadata: bytes) -> FSListRequestV2:
    try:
        value = json.loads(
            metadata.decode("utf-8", errors="strict"), object_pairs_hook=_unique_pairs
        )
        return FSListRequestV2.model_validate_json(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    except Exception as exc:
        raise ProtocolV2Error("invalid v2 metadata") from exc


def encode_request_v2(request: FSListRequestV2) -> bytes:
    if not isinstance(request, FSListRequestV2):
        raise ProtocolV2Error("invalid v2 request")
    metadata = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(metadata) > MAX_METADATA_V2:
        raise ProtocolV2Error("v2 metadata exceeds limit")
    return MAGIC_V2 + struct.pack(">I", len(metadata)) + metadata


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        data = stream.read(remaining)
        if not data:
            raise ProtocolV2Error("truncated v2 frame")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def validate_force_command_v2(env: Mapping[str, str]) -> None:
    if env.get("SSH_ORIGINAL_COMMAND") != FORCE_COMMAND_V2 or env.get("SSH_TTY"):
        raise ProtocolV2Error("invalid v2 SSH ForceCommand context")


def read_request_v2(stream: BinaryIO) -> FSListRequestV2:
    if _read_exact(stream, len(MAGIC_V2)) != MAGIC_V2:
        raise ProtocolV2Error("invalid v2 magic")
    (length,) = struct.unpack(">I", _read_exact(stream, 4))
    if length > MAX_METADATA_V2:
        raise ProtocolV2Error("v2 metadata exceeds limit")
    request = _decode_metadata(_read_exact(stream, length))
    if stream.read(1):
        raise ProtocolV2Error("unexpected v2 trailing payload")
    return request


def decode_request_v2(frame: bytes) -> FSListRequestV2:
    from io import BytesIO

    if not isinstance(frame, bytes):
        raise ProtocolV2Error("invalid v2 frame")
    return read_request_v2(BytesIO(frame))
