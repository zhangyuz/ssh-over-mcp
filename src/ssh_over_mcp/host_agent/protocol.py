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


def read_request(stream: BinaryIO) -> tuple[ExecEnvelope, bytes]:
    """Read and validate one complete SMCP v1 request from a binary stream.

    This parser is deliberately bounded before allocating or reading variable
    request components. It does not execute the parsed command.
    """

    magic = _read_exact(stream, len(MAGIC))
    if magic != MAGIC:
        raise HostAgentProtocolError("invalid protocol magic")

    metadata_length_bytes = _read_exact(stream, 4)
    (metadata_length,) = struct.unpack(">I", metadata_length_bytes)
    if metadata_length > MAX_METADATA_BYTES:
        raise HostAgentProtocolError("metadata frame exceeds maximum")

    metadata = _read_exact(stream, metadata_length)
    try:
        envelope = ExecEnvelope.model_validate_json(metadata)
    except Exception as exc:
        raise HostAgentProtocolError("invalid request metadata") from exc

    # Read at most limit + 1 to detect an oversized stdin without accepting
    # unbounded input into memory.
    limit = envelope.limits.max_stdin_bytes
    stdin = stream.read(limit + 1)
    if len(stdin) > limit:
        raise HostAgentProtocolError("stdin exceeds configured maximum")

    # A compliant SSH client closes stdin after the framed request. If a custom
    # stream returns fewer than requested bytes without EOF, this extra read
    # catches trailing data without changing the normal blocking SSH behavior.
    if len(stdin) <= limit:
        trailing = stream.read(1)
        if trailing:
            raise HostAgentProtocolError("stdin exceeds configured maximum")

    return envelope, stdin


def parse_request_bytes(payload: bytes) -> tuple[ExecEnvelope, bytes]:
    """Test/helper wrapper around the streaming parser."""

    return read_request(io.BytesIO(payload))
