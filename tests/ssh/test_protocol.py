import pytest

from ssh_over_mcp.ssh.protocol import (
    ExecEnvelope,
    ExecutionLimits,
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    ProtocolError,
    decode_envelope_metadata,
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


def test_fs_mkdir_frame_roundtrip_is_metadata_only():
    expected = FsMkdirEnvelope(
        request_id="req_fs_mkdir_1234",
        profile="developer",
        path="/srv/app/new-directory",
    )

    actual, stdin = decode_request(encode_request(expected))

    assert actual == expected
    assert stdin == b""


def test_fs_mkdir_rejects_application_stdin():
    envelope = FsMkdirEnvelope(
        request_id="req_fs_mkdir_1234",
        profile="developer",
        path="/srv/app/new-directory",
    )

    with pytest.raises(ProtocolError, match="do not accept stdin"):
        encode_request(envelope, b"x")


def test_fs_mkdir_rejects_mode_or_recursive_metadata():
    for extra in (
        (
            b'{"operation":"fs_mkdir","path":"/srv/app/new","profile":"developer",'
            b'"request_id":"req_fs_mkdir_1234","version":1,"mode":493}'
        ),
        (
            b'{"operation":"fs_mkdir","path":"/srv/app/new","profile":"developer",'
            b'"request_id":"req_fs_mkdir_1234","version":1,"recursive":true}'
        ),
    ):
        with pytest.raises(ProtocolError):
            decode_envelope_metadata(extra)


def test_fs_write_frame_roundtrip_requires_exact_body():
    expected = FsWriteEnvelope(
        request_id="req_fs_write_1234",
        profile="developer",
        path="/srv/app/new.bin",
        content_length=4,
    )

    actual, body = decode_request(encode_request(expected, b"\x00\xffAB"))

    assert actual == expected
    assert body == b"\x00\xffAB"


@pytest.mark.parametrize("body", [b"abc", b"abcde"])
def test_fs_write_encode_rejects_body_length_mismatch(body: bytes):
    request = FsWriteEnvelope(
        request_id="req_fs_write_1234",
        profile="developer",
        path="/srv/app/new.bin",
        content_length=4,
    )

    with pytest.raises(ProtocolError, match="body length mismatch"):
        encode_request(request, body)


def test_fs_write_decode_rejects_body_length_mismatch():
    request = FsWriteEnvelope(
        request_id="req_fs_write_1234",
        profile="developer",
        path="/srv/app/new.bin",
        content_length=4,
    )
    framed = encode_request(request, b"ABCD")

    with pytest.raises(ProtocolError, match="body length mismatch"):
        decode_request(framed[:-1])

    with pytest.raises(ProtocolError, match="body length mismatch"):
        decode_request(framed + b"x")


def test_fs_write_content_length_is_strict_and_nonnegative():
    with pytest.raises(ValueError):
        FsWriteEnvelope(
            request_id="req_fs_write_1234",
            profile="developer",
            path="/srv/app/new.bin",
            content_length=True,
        )

    with pytest.raises(ValueError):
        FsWriteEnvelope(
            request_id="req_fs_write_1234",
            profile="developer",
            path="/srv/app/new.bin",
            content_length=-1,
        )


def test_fs_write_rejects_overwrite_or_mode_metadata():
    for metadata in (
        (
            b'{"content_length":0,"operation":"fs_write","path":"/srv/app/new",'
            b'"profile":"developer","request_id":"req_fs_write_1234","version":1,'
            b'"overwrite":true}'
        ),
        (
            b'{"content_length":0,"operation":"fs_write","path":"/srv/app/new",'
            b'"profile":"developer","request_id":"req_fs_write_1234","version":1,'
            b'"mode":384}'
        ),
    ):
        with pytest.raises(ProtocolError):
            decode_envelope_metadata(metadata)
