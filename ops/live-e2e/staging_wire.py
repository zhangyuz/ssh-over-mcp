"""Dormant fixed-schema wire codec. No host observations or output authority."""

from __future__ import annotations

import json
from typing import Literal

MAX_BYTES = 2097152
_FAILURE = "staging envelope rejected"


class EnvelopeError(RuntimeError):
    """The data cannot be accepted as a canonical envelope/receipt."""


def _reject() -> None:
    raise EnvelopeError(_FAILURE) from None


def _budget(limit: int) -> None:
    if type(limit) is not int or not 1 <= limit <= MAX_BYTES:
        _reject()


def encode_integer(value: int, *, max_bytes: int) -> bytes:
    """Decimal conversion local to this call, independent of CPython's guard."""
    _budget(max_bytes)
    if type(value) is not int:
        _reject()
    negative = value < 0
    available = max_bytes - negative
    if available < 1 or value.bit_length() > 4 * available:
        _reject()
    value = abs(value)
    # Decimal width cannot exceed binary width. A tiny field must not build
    # a two-million-digit power merely because the envelope has that budget.
    available = min(available, max(1, value.bit_length()))
    if value >= 10**available:
        _reject()
    low, high = 1, available
    while low < high:
        middle = (low + high) // 2
        if value < 10**middle:
            high = middle
        else:
            low = middle + 1
    result = bytearray(b"-" if negative else b"")

    def render(number: int, width: int) -> None:
        if width <= 9:
            leaf = str(number).encode("ascii").rjust(width, b"0")
            if len(result) + len(leaf) > max_bytes:
                _reject()
            result.extend(leaf)
            return
        right_width = width // 2
        left, right = divmod(number, 10**right_width)
        render(left, width - right_width)
        render(right, right_width)

    render(value, low)
    return bytes(result)


def decode_integer(token: bytes, *, max_bytes: int) -> int:
    _budget(max_bytes)
    if type(token) is not bytes or not 1 <= len(token) <= max_bytes:
        _reject()
    negative = token[0] == 45
    start = int(negative)
    if start == len(token) or any(not 48 <= c <= 57 for c in token[start:]):
        _reject()
    if token[start] == 48 and (negative or len(token) - start != 1):
        _reject()

    def convert(left: int, right: int) -> int:
        if right - left <= 9:
            return int(token[left:right])
        middle = (left + right) // 2
        return convert(left, middle) * 10 ** (right - middle) + convert(middle, right)

    value = convert(start, len(token))
    return -value if negative else value


# Every descriptor is private and fixed. Traversal depth depends on these schemas,
# never on an input-selected tree. Arrays carry their bound before any iteration.
_ENTRY = {
    "path": "path",
    "kind": "kind",
    "device": "uint",
    "inode": "uint",
    "uid": "uint",
    "gid": "uint",
    "mode": "mode",
    "nlink": "uint",
    "size": "uint",
    "mtime_ns": "sint",
    "ctime_ns": "sint",
}
_ANCESTOR = {
    "path": "absolute",
    "device": "uint",
    "inode": "uint",
    "uid": "uint",
    "gid": "uint",
    "mode": "mode",
}
_PARENT = {"path": "absolute", "ancestors": (_ANCESTOR, 7, 7)}
_MARKER = {"device": "uint", "inode": "uint", "target": "sha40", "owner_pid": "pid"}
_STAGING = {
    "basename": "basename",
    "device": "uint",
    "inode": "uint",
    "uid": "uint",
    "mode": "mode",
    "expected_commit": "sha40",
}
_INSPECTION = {"authority_sha": "sha40", "run_id": "provenance", "attempt": "provenance"}
_INVENTORY = {
    "schema_version": "version",
    "incident": "incident",
    "parent": _PARENT,
    "marker": _MARKER,
    "staging": _STAGING,
    "entries": (_ENTRY, 13, 4096),
}
_ENVELOPE = {
    "schema_version": "version",
    "inventory": _INVENTORY,
    "inventory_sha256": "sha64",
    "inspection": _INSPECTION,
}
_RECEIPT = {
    "schema_version": "version",
    "envelope_bytes": "bytes",
    "chunks": "chunks",
    "envelope_sha256": "sha64",
}
_CHUNK = {"index": "index", "data": "data"}
_SCHEMAS = {"envelope": _ENVELOPE, "receipt": _RECEIPT, "chunk": _CHUNK}
_LIMITS = {"envelope": MAX_BYTES, "receipt": 256, "chunk": 1536}
_NUMBERS = {"uint", "sint", "mode", "pid", "version", "bytes", "chunks", "index"}
_RANGES = {
    "mode": (0, 4095),
    "pid": (38013, 38013),
    "version": (1, 1),
    "bytes": (1, MAX_BYTES),
    "chunks": (1, 2048),
    "index": (0, 2047),
}
_ENUMS = {
    "kind": ("directory", "regular"),
    "incident": ("stale-target", "older-target"),
    "basename": ("ssh-over-mcp-e2e-i8ow1ni6", "ssh-over-mcp-e2e-w_kn4rus"),
}
_STRING_LIMITS = {
    "path": 24578,
    "absolute": MAX_BYTES,
    "sha40": 42,
    "sha64": 66,
    "provenance": 21,
    "data": 1370,
    "kind": 11,
    "incident": 14,
    "basename": 29,
}


def _number_valid(value: int, descriptor: str) -> None:
    if type(value) is not int or (descriptor != "sint" and value < 0):
        _reject()
    if descriptor in _RANGES:
        lower, upper = _RANGES[descriptor]
        if not lower <= value <= upper:
            _reject()


def _string_valid(value: str, descriptor: str) -> None:
    if type(value) is not str:
        _reject()
    if descriptor in _ENUMS and value not in _ENUMS[descriptor]:
        _reject()
    if descriptor in {"sha40", "sha64"}:
        width = 40 if descriptor == "sha40" else 64
        if len(value) != width or any(c not in "0123456789abcdef" for c in value):
            _reject()
    if descriptor == "provenance" and (
        not 1 <= len(value) <= 19
        or value[0] == "0"
        or any(c not in "0123456789" for c in value)
        or int(value) > 2**63 - 1
    ):
        _reject()


def _string_bytes(value: str, descriptor: str, available: int) -> bytes:
    if type(value) is not str or len(value) + 2 > min(available, _STRING_LIMITS[descriptor]):
        _reject()
    _string_valid(value, descriptor)
    projected = 2
    for character in value:
        code = ord(character)
        projected += (
            2
            if character in '\\"\b\t\n\f\r'
            else 6
            if code < 32 or 127 <= code <= 65535
            else 12
            if code > 65535
            else 1
        )
        if projected > min(available, _STRING_LIMITS[descriptor]):
            _reject()
    return json.dumps(value, ensure_ascii=True).encode("ascii")


def _encode(value: dict, schema: dict, limit: int) -> bytes:
    result = bytearray()

    def append(raw: bytes) -> None:
        if len(result) + len(raw) > limit:
            _reject()
        result.extend(raw)

    def visit(item, descriptor) -> None:
        if type(descriptor) is dict:
            if (
                type(item) is not dict
                or len(item) != len(descriptor)
                or any(type(key) is not str or key not in descriptor for key in item)
            ):
                _reject()
            append(b"{")
            for index, key in enumerate(sorted(descriptor)):
                if index:
                    append(b",")
                append(b'"' + key.encode("ascii") + b'":')
                visit(item[key], descriptor[key])
            append(b"}")
        elif type(descriptor) is tuple:
            element, lower, upper = descriptor
            if type(item) is not list or not lower <= len(item) <= upper:
                _reject()
            append(b"[")
            for index, child in enumerate(item):
                if index:
                    append(b",")
                visit(child, element)
            append(b"]")
        elif descriptor in _NUMBERS:
            _number_valid(item, descriptor)
            append(encode_integer(item, max_bytes=limit - len(result)))
        else:
            append(_string_bytes(item, descriptor, limit - len(result)))

    visit(value, schema)
    return bytes(result)


def encode_inventory_payload(value: dict) -> bytes:
    return _encode(value, _INVENTORY, MAX_BYTES)


def encode_wire(value: dict, *, kind: Literal["envelope", "receipt", "chunk"]) -> bytes:
    if type(kind) is not str or kind not in _SCHEMAS:
        _reject()
    return _encode(value, _SCHEMAS[kind], _LIMITS[kind])


class _Scanner:
    def __init__(self, raw: bytes, materialize: bool):
        self.raw = raw
        self.position = 0
        self.materialize = materialize

    def take(self, literal: bytes) -> None:
        if not self.raw.startswith(literal, self.position):
            _reject()
        self.position += len(literal)

    def peek(self) -> int:
        if self.position >= len(self.raw):
            _reject()
        return self.raw[self.position]

    def string(self, descriptor: str):
        start = self.position
        self.take(b'"')
        limit = min(_STRING_LIMITS[descriptor], len(self.raw) - start)
        while self.position - start < limit:
            character = self.peek()
            self.position += 1
            if character == 34:
                if not self.materialize:
                    return None
                value = json.loads(self.raw[start : self.position])
                _string_valid(value, descriptor)
                return value
            if character == 92:
                escaped = self.peek()
                self.position += 1
                if escaped == 117:
                    for _ in range(4):
                        if self.peek() not in b"0123456789abcdefABCDEF":
                            _reject()
                        self.position += 1
                elif escaped not in b'"\\/bfnrt':
                    _reject()
            elif character < 32 or character > 126:
                _reject()
            if self.position - start >= limit:
                _reject()
        _reject()

    def number(self, descriptor: str):
        start = self.position
        negative = self.peek() == 45
        if negative:
            if descriptor != "sint":
                _reject()
            self.position += 1
        if not 48 <= self.peek() <= 57:
            _reject()
        zero = self.peek() == 48
        self.position += 1
        while self.position < len(self.raw) and 48 <= self.raw[self.position] <= 57:
            if zero:
                _reject()
            self.position += 1
        if zero and negative:
            _reject()
        if descriptor in _RANGES:
            lower, upper = _RANGES[descriptor]
            # The permitted small range rejects excessive tokens before conversion.
            if self.position - start > len(str(upper)):
                _reject()
            value = decode_integer(self.raw[start : self.position], max_bytes=MAX_BYTES)
            if not lower <= value <= upper:
                _reject()
            return value if self.materialize else None
        if self.materialize:
            return decode_integer(self.raw[start : self.position], max_bytes=MAX_BYTES)
        return None

    def visit(self, descriptor):
        if type(descriptor) is dict:
            self.take(b"{")
            result = {} if self.materialize else None
            for index, key in enumerate(sorted(descriptor)):
                if index:
                    self.take(b",")
                self.take(b'"' + key.encode("ascii") + b'":')
                value = self.visit(descriptor[key])
                if self.materialize:
                    result[key] = value
            self.take(b"}")
            return result
        if type(descriptor) is tuple:
            element, lower, upper = descriptor
            self.take(b"[")
            count = 0
            result = [] if self.materialize else None
            if self.peek() != 93:
                while True:
                    if count >= upper:
                        _reject()
                    value = self.visit(element)
                    if self.materialize:
                        result.append(value)
                    count += 1
                    if self.peek() != 44:
                        break
                    self.take(b",")
            self.take(b"]")
            if count < lower:
                _reject()
            return result
        if descriptor in _NUMBERS:
            return self.number(descriptor)
        return self.string(descriptor)


def _materialize_wire(raw: bytes, kind: str) -> dict:
    return _Scanner(raw, True).visit(_SCHEMAS[kind])


def parse_wire(raw: bytes, *, kind: Literal["envelope", "receipt", "chunk"]) -> dict:
    """Refuse hostile structure before retaining a decoded tree."""
    try:
        if (
            type(kind) is not str
            or kind not in _SCHEMAS
            or type(raw) is not bytes
            or not 1 <= len(raw) <= _LIMITS[kind]
        ):
            _reject()
        scanner = _Scanner(raw, False)
        scanner.visit(_SCHEMAS[kind])
        if scanner.position != len(raw):
            _reject()
        result = _materialize_wire(raw, kind)
        if encode_wire(result, kind=kind) != raw:
            _reject()
        return result
    except (ValueError, TypeError, OverflowError, RecursionError):
        _reject()
