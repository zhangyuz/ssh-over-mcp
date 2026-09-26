from __future__ import annotations

import json
import struct
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAGIC = b"SMCP\x00\x01"
REMOTE_PROTOCOL_COMMAND = "mcp-v1"
MAX_METADATA_BYTES = 64 * 1024


class ExecutionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: float = Field(gt=0, le=3600)
    max_output_bytes: int = Field(gt=0, le=64 * 1024 * 1024)
    max_stdin_bytes: int = Field(ge=0, le=64 * 1024 * 1024)


class ExecEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    request_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    operation: Literal["exec"] = "exec"
    profile: str = Field(min_length=1, max_length=128)
    executable: str = Field(min_length=1)
    argv: tuple[str, ...] = ()
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    limits: ExecutionLimits


class ProtocolError(ValueError):
    pass


def encode_request(envelope: ExecEnvelope, stdin: bytes = b"") -> bytes:
    metadata = json.dumps(
        envelope.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(metadata) > MAX_METADATA_BYTES:
        raise ProtocolError("request metadata exceeds maximum frame size")
    if len(stdin) > envelope.limits.max_stdin_bytes:
        raise ProtocolError("stdin exceeds configured maximum")

    return MAGIC + struct.pack(">I", len(metadata)) + metadata + stdin


def decode_request(payload: bytes) -> tuple[ExecEnvelope, bytes]:
    """Decode a complete request payload.

    Phase 3's host agent will use a streaming equivalent of this framing.
    """

    header_len = len(MAGIC) + 4
    if len(payload) < header_len or payload[: len(MAGIC)] != MAGIC:
        raise ProtocolError("invalid protocol magic")

    (metadata_len,) = struct.unpack(
        ">I", payload[len(MAGIC) : header_len]
    )
    if metadata_len > MAX_METADATA_BYTES:
        raise ProtocolError("declared metadata frame exceeds maximum")

    end = header_len + metadata_len
    if len(payload) < end:
        raise ProtocolError("truncated metadata frame")

    try:
        envelope = ExecEnvelope.model_validate_json(payload[header_len:end])
    except Exception as exc:
        raise ProtocolError("invalid request metadata") from exc

    stdin = payload[end:]
    if len(stdin) > envelope.limits.max_stdin_bytes:
        raise ProtocolError("stdin exceeds configured maximum")

    return envelope, stdin
