"""Fail-closed v2 filesystem protocol; v1 must remain incompatible."""

from __future__ import annotations

import hashlib
import io
import json
import struct

import pytest
from pydantic import ValidationError

from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    VisibilitySnapshotV5,
    sign_snapshot,
)
from ssh_over_mcp.ssh.protocol import ProtocolError, decode_request
from ssh_over_mcp.ssh.protocol_v2 import (
    MAGIC_V2,
    MAX_METADATA_V2,
    FSListRequestV2,
    ProtocolV2Error,
    decode_request_v2,
    encode_request_v2,
    read_request_v2,
    validate_force_command_v2,
)

_KEY = bytes(range(32))


def _request():
    signed = sign_snapshot(
        VisibilitySnapshotV5.model_validate(
            {
                "version": 5,
                "request_id": "req-0123456789",
                "host": "node01",
                "host_key_sha256": hashlib.sha256(b"testhostkey").hexdigest(),
                "principal": "alice",
                "profile": "operator",
                "operation": "fs_list",
                "root": "/srv/data",
                "policy_epoch": 9,
                "central_policy_sha256": "a" * 64,
                "snapshot_id": "b" * 32,
                "issued_at": 1_800_000_000,
                "expires_at": 1_800_000_030,
                "max_entries": 64,
                "rules": {
                    "allow_roots": ("/srv/data",),
                    "deny_subtrees": ("/srv/data/secret",),
                },
            }
        ),
        key=_KEY,
    )
    return FSListRequestV2(
        request_id="req-0123456789",
        profile="operator",
        root="/srv/data",
        max_entries=64,
        signed_snapshot=signed,
    )


def test_roundtrip_standalone_v2_frame():
    req = _request()
    encoded = encode_request_v2(req)
    assert encoded.startswith(MAGIC_V2)
    assert decode_request_v2(encoded) == req
    assert read_request_v2(io.BytesIO(encoded)) == req


def test_v1_decoder_rejects_v2_magic_and_v2_rejects_v1():
    v2 = encode_request_v2(_request())
    with pytest.raises(ProtocolError):
        decode_request(v2)
    with pytest.raises(ProtocolV2Error):
        decode_request_v2(b"SMCP\x00\x01" + v2[len(MAGIC_V2) :])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p[:3],
        lambda p: p[: len(MAGIC_V2)] + struct.pack(">I", MAX_METADATA_V2 + 1),
        lambda p: p[:-1],
        lambda p: p + b"trailing",
        lambda p: p[: len(MAGIC_V2)] + struct.pack(">I", 2) + b"{}",
    ],
)
def test_v2_rejects_truncated_oversized_or_trailing_bytes(mutation):
    with pytest.raises(ProtocolV2Error):
        decode_request_v2(mutation(encode_request_v2(_request())))


def test_v2_rejects_duplicate_json_keys_even_when_last_matches():
    request = _request()
    metadata = request.model_dump(mode="json")
    body = json.dumps(metadata).encode()
    body = b'{"version":2,' + body[1:]
    frame = MAGIC_V2 + struct.pack(">I", len(body)) + body
    with pytest.raises(ProtocolV2Error):
        decode_request_v2(frame)


@pytest.mark.parametrize(
    "change",
    [
        {"version": 1},
        {"operation": "exec"},
        {"root": "/srv/data/../etc"},
        {"root": "/srv/private"},
        {"request_id": "different"},
        {"profile": "guest"},
        {"max_entries": 65},
        {"max_entries": 12},
        {"extra": True},
    ],
)
def test_v2_schema_refuses_unknown_or_mismatched_fields(change):
    raw = _request().model_dump(mode="json")
    raw.update(change)
    with pytest.raises((ValidationError, ValueError)):
        FSListRequestV2.model_validate(raw)


def test_v2_force_command_explicit_and_no_pty():
    validate_force_command_v2({"SSH_ORIGINAL_COMMAND": "mcp-v2"})
    for env in (
        {"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        {"SSH_ORIGINAL_COMMAND": "mcp-v2", "SSH_TTY": "/dev/pts/3"},
        {},
        {"SSH_ORIGINAL_COMMAND": "mcp-v2 trailing"},
    ):
        with pytest.raises(ProtocolV2Error):
            validate_force_command_v2(env)


def test_streaming_parser_rejects_extra_application_stdin():
    body = encode_request_v2(_request())
    with pytest.raises(ProtocolV2Error):
        read_request_v2(io.BytesIO(body + b"x"))


@pytest.mark.parametrize("nesting", [6, 64, 20_000])
def test_v2_bounds_nesting_before_invoking_recursive_json_parser(nesting, monkeypatch):
    import ssh_over_mcp.ssh.protocol_v2 as module

    parsed: list[object] = []
    real_loads = module.json.loads

    def tracking_loads(*args, **kwargs):
        parsed.append(args)
        return real_loads(*args, **kwargs)

    monkeypatch.setattr(module.json, "loads", tracking_loads)
    metadata = b"[" * nesting + b"]" * nesting
    frame = MAGIC_V2 + struct.pack(">I", len(metadata)) + metadata
    with pytest.raises(ProtocolV2Error):
        decode_request_v2(frame)
    assert parsed == []


def test_v2_brackets_inside_strings_do_not_count_toward_nesting():
    base = _request().signed_snapshot.payload
    snapshot = base.model_copy(update={"principal": 'alice[[[[{{{{\\"]]]]'})
    signed = sign_snapshot(VisibilitySnapshotV5.model_validate(snapshot.model_dump()), key=_KEY)
    request = _request().model_copy(update={"signed_snapshot": signed})
    assert decode_request_v2(encode_request_v2(request)) == request
