from __future__ import annotations

import json
import struct
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

MAGIC = b"SMCP\x00\x01"
REMOTE_PROTOCOL_COMMAND = "mcp-v1"
MAX_METADATA_BYTES = 64 * 1024
MAX_FILESYSTEM_READ_BYTES = 64 * 1024 * 1024
MAX_FILESYSTEM_WRITE_BYTES = 64 * 1024 * 1024


class ExecutionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: float = Field(gt=0, le=3600)
    max_output_bytes: int = Field(gt=0, le=64 * 1024 * 1024)
    max_stdin_bytes: int = Field(ge=0, le=64 * 1024 * 1024)


class _RequestEnvelopeBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    request_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    profile: str = Field(min_length=1, max_length=128)


class ExecEnvelope(_RequestEnvelopeBase):
    operation: Literal["exec"] = "exec"
    executable: str = Field(min_length=1)
    argv: tuple[str, ...] = ()
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    limits: ExecutionLimits


class FsStatEnvelope(_RequestEnvelopeBase):
    operation: Literal["fs_stat"] = "fs_stat"
    path: str = Field(min_length=1)


class FsReadEnvelope(_RequestEnvelopeBase):
    operation: Literal["fs_read"] = "fs_read"
    path: str = Field(min_length=1)
    max_bytes: int = Field(
        strict=True,
        ge=1,
        le=MAX_FILESYSTEM_READ_BYTES,
    )


class FsMkdirEnvelope(_RequestEnvelopeBase):
    operation: Literal["fs_mkdir"] = "fs_mkdir"
    path: str = Field(min_length=1)


class FsWriteEnvelope(_RequestEnvelopeBase):
    operation: Literal["fs_write"] = "fs_write"
    path: str = Field(min_length=1)
    content_length: int = Field(
        strict=True,
        ge=0,
        le=MAX_FILESYSTEM_WRITE_BYTES,
    )


RequestEnvelope = Annotated[
    ExecEnvelope | FsStatEnvelope | FsReadEnvelope | FsMkdirEnvelope | FsWriteEnvelope,
    Field(discriminator="operation"),
]
_REQUEST_ADAPTER = TypeAdapter(RequestEnvelope)


class ProtocolError(ValueError):
    pass


def decode_envelope_metadata(metadata: bytes) -> RequestEnvelope:
    try:
        return _REQUEST_ADAPTER.validate_json(metadata)
    except Exception as exc:
        raise ProtocolError("invalid request metadata") from exc


def encode_request(
    envelope: RequestEnvelope,
    stdin: bytes = b"",
) -> bytes:
    if isinstance(envelope, FsWriteEnvelope):
        if len(stdin) != envelope.content_length:
            raise ProtocolError("filesystem write body length mismatch")
    elif not isinstance(envelope, ExecEnvelope) and stdin:
        raise ProtocolError("filesystem operations do not accept stdin")

    metadata = json.dumps(
        envelope.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(metadata) > MAX_METADATA_BYTES:
        raise ProtocolError("request metadata exceeds maximum frame size")
    if (
        isinstance(envelope, ExecEnvelope)
        and len(stdin) > envelope.limits.max_stdin_bytes
    ):
        raise ProtocolError("stdin exceeds configured maximum")

    return MAGIC + struct.pack(">I", len(metadata)) + metadata + stdin


def decode_request(payload: bytes) -> tuple[RequestEnvelope, bytes]:
    """Decode one complete SMCP v1 request payload."""

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

    envelope = decode_envelope_metadata(payload[header_len:end])
    stdin = payload[end:]

    if isinstance(envelope, ExecEnvelope):
        if len(stdin) > envelope.limits.max_stdin_bytes:
            raise ProtocolError("stdin exceeds configured maximum")
    elif isinstance(envelope, FsWriteEnvelope):
        if len(stdin) != envelope.content_length:
            raise ProtocolError("filesystem write body length mismatch")
    elif stdin:
        raise ProtocolError("filesystem operations do not accept stdin")

    return envelope, stdin
