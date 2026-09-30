import pytest

from ssh_over_mcp.ssh.protocol import (
    ExecEnvelope,
    ExecutionLimits,
    FsReadEnvelope,
    FsStatEnvelope,
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



def test_fs_stat_frame_roundtrip_has_no_application_stdin():
    expected = FsStatEnvelope(
        request_id="req_fs_stat_1234",
        profile="developer",
        path="/srv/app/README.md",
    )

    actual, stdin = decode_request(encode_request(expected))

    assert actual == expected
    assert stdin == b""


def test_fs_read_frame_roundtrip_has_strict_bound():
    expected = FsReadEnvelope(
        request_id="req_fs_read_1234",
        profile="developer",
        path="/srv/app/data.bin",
        max_bytes=4096,
    )

    actual, stdin = decode_request(encode_request(expected))

    assert actual == expected
    assert stdin == b""


def test_filesystem_request_rejects_application_stdin():
    request = FsReadEnvelope(
        request_id="req_fs_read_1234",
        profile="developer",
        path="/srv/app/data.bin",
        max_bytes=4096,
    )

    with pytest.raises(ProtocolError, match="do not accept stdin"):
        encode_request(request, b"x")

    with pytest.raises(ProtocolError, match="do not accept stdin"):
        decode_request(encode_request(request) + b"x")


def test_fs_read_bound_rejects_boolean():
    with pytest.raises(ValueError):
        FsReadEnvelope(
            request_id="req_fs_read_1234",
            profile="developer",
            path="/srv/app/data.bin",
            max_bytes=True,
        )
