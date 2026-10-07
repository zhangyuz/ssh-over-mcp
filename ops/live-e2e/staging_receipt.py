"""Dormant receipt transport; consistency does not establish trusted origin."""

from __future__ import annotations

import base64
import hashlib

from staging_envelope import validate_envelope
from staging_wire import EnvelopeError, encode_wire, parse_wire

_RECEIPT = b"STAGING_RECEIPT "
_CHUNK = b"STAGING_CHUNK "


def _require(condition: bool) -> None:
    if not condition:
        raise EnvelopeError("staging envelope rejected") from None


def _decode_data(data: str) -> bytes:
    try:
        _require(type(data) is str and 1 <= len(data) <= 1368)
        raw = base64.b64decode(data, validate=True)
        _require(1 <= len(raw) <= 1024 and base64.b64encode(raw).decode("ascii") == data)
        return raw
    except (ValueError, TypeError):
        raise EnvelopeError("staging envelope rejected") from None


def encode_receipt(envelope: bytes) -> tuple[bytes, ...]:
    validate_envelope(envelope)
    count = (len(envelope) + 1023) // 1024
    receipt = {
        "schema_version": 1,
        "envelope_bytes": len(envelope),
        "chunks": count,
        "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
    }
    lines = [_RECEIPT + encode_wire(receipt, kind="receipt") + b"\n"]
    for index in range(count):
        chunk = {
            "index": index,
            "data": base64.b64encode(envelope[index * 1024 : (index + 1) * 1024]).decode("ascii"),
        }
        lines.append(_CHUNK + encode_wire(chunk, kind="chunk") + b"\n")
    return tuple(lines)


def decode_receipt(lines: tuple[bytes, ...]) -> bytes:
    _require(type(lines) is tuple and 2 <= len(lines) <= 2049)
    for index, line in enumerate(lines):
        _require(type(line) is bytes and len(line) <= (256 if index == 0 else 1536))
        _require(line.endswith(b"\n") and line.startswith(_RECEIPT if index == 0 else _CHUNK))
    receipt = parse_wire(lines[0][len(_RECEIPT) : -1], kind="receipt")
    _require(len(lines) == receipt["chunks"] + 1)
    _require(receipt["chunks"] == (receipt["envelope_bytes"] + 1023) // 1024)
    result = bytearray()
    for index, line in enumerate(lines[1:]):
        chunk = parse_wire(line[len(_CHUNK) : -1], kind="chunk")
        _require(chunk["index"] == index)
        raw = _decode_data(chunk["data"])
        expected = (
            1024 if index < receipt["chunks"] - 1 else receipt["envelope_bytes"] - 1024 * index
        )
        _require(len(raw) == expected and len(result) + len(raw) <= receipt["envelope_bytes"])
        result.extend(raw)
    envelope = bytes(result)
    _require(len(envelope) == receipt["envelope_bytes"])
    _require(hashlib.sha256(envelope).hexdigest() == receipt["envelope_sha256"])
    validate_envelope(envelope)
    return envelope
