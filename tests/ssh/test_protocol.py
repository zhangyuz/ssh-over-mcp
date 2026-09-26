import pytest

from ssh_over_mcp.ssh.protocol import (
    ExecEnvelope,
    ExecutionLimits,
    ProtocolError,
    decode_request,
    encode_request,
)


def envelope() -> ExecEnvelope:
    return ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable="/usr/bin/git",
        argv=("status",),
        cwd="/srv/app",
        env={"CI": "1"},
        limits=ExecutionLimits(
            timeout_seconds=30,
            max_output_bytes=1024,
            max_stdin_bytes=16,
        ),
    )


def test_frame_roundtrip():
    expected = envelope()
    payload = encode_request(expected, b"hello")

    actual, stdin = decode_request(payload)

    assert actual == expected
    assert stdin == b"hello"


def test_stdin_limit_enforced():
    with pytest.raises(ProtocolError):
        encode_request(envelope(), b"x" * 17)


def test_bad_magic_rejected():
    with pytest.raises(ProtocolError):
        decode_request(b"bad")
