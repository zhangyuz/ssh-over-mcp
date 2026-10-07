from __future__ import annotations

import base64
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from .test_live_e2e_staging_envelope import FIXTURE, byte_boundary, unchecked_envelope

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def codec(monkeypatch):
    path = ROOT / "ops/live-e2e"
    assert (path / "staging_receipt.py").is_file(), "dormant receipt is not implemented"
    monkeypatch.syspath_prepend(str(path))
    return importlib.import_module("staging_receipt")


def golden_lines():
    return tuple((FIXTURE / "receipt.log").read_bytes().splitlines(keepends=True))


def literal_line(prefix, value):
    return (
        prefix
        + json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )


def test_literal_multichunk_receipt_roundtrip(codec):
    raw = (FIXTURE / "envelope.json").read_bytes()
    assert codec.encode_receipt(raw) == golden_lines()
    assert codec.decode_receipt(golden_lines()) == raw
    chunks = [json.loads(line[len(b"STAGING_CHUNK ") :]) for line in golden_lines()[1:]]
    assert chunks[0]["data"].endswith("==")
    assert len(base64.b64decode(chunks[0]["data"], validate=True)) == 1024


@pytest.mark.parametrize(
    "change", ["loss", "duplicate", "order", "truncate", "no-lf", "extra-line", "empty"]
)
def test_incomplete_receipts_never_return_partial_data(codec, change):
    lines = list(golden_lines())
    if change == "loss":
        lines.pop(2)
    elif change == "duplicate":
        lines[2] = lines[1]
    elif change == "order":
        lines[1], lines[2] = lines[2], lines[1]
    elif change == "truncate":
        lines[-1] = lines[-1][:-12]
    elif change == "no-lf":
        lines[-1] = lines[-1][:-1]
    elif change == "extra-line":
        lines.append(b"other-log-line\n")
    elif change == "empty":
        lines.clear()
    with pytest.raises(codec.EnvelopeError, match="^staging envelope rejected$"):
        codec.decode_receipt(tuple(lines))


@pytest.mark.parametrize("data,want", [("+/8=", b"\xfb\xff"), ("/w==", b"\xff")])
def test_canonical_base64_primitives(codec, data, want):
    assert codec._decode_data(data) == want


@pytest.mark.parametrize("data", ["-_8=", "+/8", "/x==", "/w===", "/w==\n", " /w==", "", "%%%%"])
def test_noncanonical_base64_primitives(codec, data):
    with pytest.raises(codec.EnvelopeError):
        codec._decode_data(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("chunks", "4"),
        ("chunks", 3),
        ("envelope_bytes", 3252),
        ("envelope_bytes", 2097153),
        ("envelope_sha256", "A" * 64),
        ("envelope_sha256", "sha256:" + "a" * 64),
        ("envelope_sha256", "0" * 64),
    ],
)
def test_bad_receipt_fields(codec, field, value):
    lines = list(golden_lines())
    receipt = json.loads(lines[0][len(b"STAGING_RECEIPT ") :])
    receipt[field] = value
    lines[0] = literal_line(b"STAGING_RECEIPT ", receipt)
    with pytest.raises(codec.EnvelopeError):
        codec.decode_receipt(tuple(lines))


@pytest.mark.parametrize(
    "field,value",
    [
        ("index", True),
        ("index", "0"),
        ("index", 1),
        ("data", False),
        ("data", ""),
        ("data", base64.b64encode(b"x" * 1023).decode()),
        ("data", base64.b64encode(b"x" * 1025).decode()),
        ("data", "x" * 2000),
    ],
)
def test_bad_chunk_fields(codec, field, value):
    lines = list(golden_lines())
    chunk = json.loads(lines[1][len(b"STAGING_CHUNK ") :])
    chunk[field] = value
    lines[1] = literal_line(b"STAGING_CHUNK ", chunk)
    with pytest.raises(codec.EnvelopeError):
        codec.decode_receipt(tuple(lines))


@pytest.mark.parametrize(
    "mutation",
    ["duplicate-key", "whitespace", "escape", "extra-key", "long-line", "too-many-lines", "list"],
)
def test_transport_structure_limits(codec, mutation):
    lines = list(golden_lines())
    if mutation == "duplicate-key":
        lines[0] = lines[0].replace(b'"chunks":4,', b'"chunks":4,"chunks":4,')
    elif mutation == "whitespace":
        lines[0] = lines[0].replace(b"{", b"{ ", 1)
    elif mutation == "escape":
        lines[0] = lines[0].replace(b'"chunks"', b'"chun\\u006bs"')
    elif mutation == "extra-key":
        lines[1] = lines[1][:-2] + b',"z":0}\n'
    elif mutation == "long-line":
        lines[0] = b"STAGING_RECEIPT " + b"x" * 300 + b"\n"
    elif mutation == "too-many-lines":
        lines = [lines[0]] * 2050
    elif mutation == "list":
        with pytest.raises(codec.EnvelopeError):
            codec.decode_receipt(lines)
        return
    with pytest.raises(codec.EnvelopeError):
        codec.decode_receipt(tuple(lines))


def test_hash_consistent_invalid_envelope_still_refuses(codec):
    raw = (
        (FIXTURE / "envelope.json").read_bytes().replace(b'"owner_pid":38013', b'"owner_pid":38014')
    )
    # Neither a matching envelope hash nor complete transport can authorize invalid metadata.
    chunks = [raw[index : index + 1024] for index in range(0, len(raw), 1024)]
    receipt = {
        "schema_version": 1,
        "chunks": len(chunks),
        "envelope_bytes": len(raw),
        "envelope_sha256": hashlib.sha256(raw).hexdigest(),
    }
    lines = (
        literal_line(b"STAGING_RECEIPT ", receipt),
        *(
            literal_line(
                b"STAGING_CHUNK ", {"index": index, "data": base64.b64encode(chunk).decode()}
            )
            for index, chunk in enumerate(chunks)
        ),
    )
    with pytest.raises(codec.EnvelopeError):
        codec.decode_receipt(lines)
    with pytest.raises(codec.EnvelopeError):
        codec.encode_receipt(raw)


def test_maximum_complete_envelope_receipt_and_overflow(codec):
    inventory, inspection = byte_boundary(2097152)
    raw = unchecked_envelope(inventory, inspection)
    lines = codec.encode_receipt(raw)
    assert len(lines) == 2049
    assert codec.decode_receipt(lines) == raw
    inventory, inspection = byte_boundary(2097153)
    with pytest.raises(codec.EnvelopeError):
        codec.encode_receipt(unchecked_envelope(inventory, inspection))


def test_receipt_codec_performs_no_host_observations_or_output(codec, monkeypatch, capsys):
    import builtins
    import os
    import socket
    import subprocess

    raw = (FIXTURE / "envelope.json").read_bytes()
    lines = golden_lines()

    def forbidden(*args, **kwargs):
        pytest.fail("data-only codec attempted host access")

    with monkeypatch.context() as patch:
        for module, name in [
            (builtins, "open"),
            (os, "open"),
            (os, "stat"),
            (os, "scandir"),
            (os, "kill"),
            (os, "getenv"),
            (subprocess, "Popen"),
            (socket, "socket"),
        ]:
            patch.setattr(module, name, forbidden)
        assert codec.encode_receipt(raw) == lines
        assert codec.decode_receipt(lines) == raw
    assert capsys.readouterr() == ("", "")
