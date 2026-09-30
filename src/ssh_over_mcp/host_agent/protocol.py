from __future__ import annotations

import io
import struct
from collections.abc import Mapping
from typing import BinaryIO

from ssh_over_mcp.ssh.protocol import (
    MAGIC,
    MAX_METADATA_BYTES,
    REMOTE_PROTOCOL_COMMAND,
    ExecEnvelope,
    FsWriteEnvelope,
    RequestEnvelope,
    decode_envelope_metadata,
)


class HostAgentProtocolError(ValueError):
    """A fail-closed host-agent invocation or framing error."""


def validate_ssh_context(env: Mapping[str, str]) -> None:
    """Validate the OpenSSH ForceCommand context before reading request data."""

    original_command = env.get("SSH_ORIGINAL_COMMAND", "")
    if original_command != REMOTE_PROTOCOL_COMMAND:
        raise HostAgentProtocolError("unexpected SSH original command")

    if env.get("SSH_TTY"):
        raise HostAgentProtocolError("PTY is not permitted for structured execution")


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size

    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise HostAgentProtocolError("truncated request frame")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _read_bounded_to_eof(stream: BinaryIO, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0

    while total < limit:
        chunk = stream.read(limit - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)

    return b"".join(chunks)


def read_envelope(stream: BinaryIO) -> RequestEnvelope:
    """Read only the fixed header and bounded JSON metadata."""

    magic = _read_exact(stream, len(MAGIC))
    if magic != MAGIC:
        raise HostAgentProtocolError("invalid protocol magic")

    metadata_length_bytes = _read_exact(stream, 4)
    (metadata_length,) = struct.unpack(">I", metadata_length_bytes)
    if metadata_length > MAX_METADATA_BYTES:
        raise HostAgentProtocolError("metadata frame exceeds maximum")

    metadata = _read_exact(stream, metadata_length)
    try:
        return decode_envelope_metadata(metadata)
    except Exception as exc:
        raise HostAgentProtocolError("invalid request metadata") from exc


def read_application_stdin(stream: BinaryIO, max_stdin_bytes: int) -> bytes:
    """Read application stdin with a caller-supplied server-side bound."""

    stdin = _read_bounded_to_eof(stream, max_stdin_bytes + 1)
    if len(stdin) > max_stdin_bytes:
        raise HostAgentProtocolError("stdin exceeds configured maximum")
    return stdin


def read_exact_application_body(stream: BinaryIO, expected_length: int) -> bytes:
    """Read one exact-length application body and require EOF afterward."""

    body = _read_bounded_to_eof(stream, expected_length + 1)
    if len(body) != expected_length:
        raise HostAgentProtocolError("request body length mismatch")
    return body


def read_request(
    stream: BinaryIO,
    *,
    max_stdin_bytes: int | None = None,
) -> tuple[RequestEnvelope, bytes]:
    """Convenience wrapper for a full request.

    The production host-agent CLI uses the two-stage API so host-local policy
    can authorize metadata and resource ceilings before application stdin is
    read.
    """

    envelope = read_envelope(stream)
    if isinstance(envelope, ExecEnvelope):
        bound = envelope.limits.max_stdin_bytes
        if max_stdin_bytes is not None:
            bound = min(bound, max_stdin_bytes)
        stdin = read_application_stdin(stream, bound)
    elif isinstance(envelope, FsWriteEnvelope):
        stdin = read_exact_application_body(stream, envelope.content_length)
    else:
        stdin = read_application_stdin(stream, 0)
    return envelope, stdin


def parse_request_bytes(payload: bytes) -> tuple[RequestEnvelope, bytes]:
    """Test/helper wrapper around the streaming parser."""

    return read_request(io.BytesIO(payload))
