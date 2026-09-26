import io
import struct

import pytest

from ssh_over_mcp.host_agent.protocol import (
    HostAgentProtocolError,
    read_request,
    validate_ssh_context,
)
from ssh_over_mcp.ssh.protocol import (
    MAGIC,
    MAX_METADATA_BYTES,
    ExecEnvelope,
    ExecutionLimits,
    encode_request,
)


def envelope(max_stdin_bytes: int = 16) -> ExecEnvelope:
    return ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable="/usr/bin/git",
        argv=("status",),
        cwd="/srv/app",
        limits=ExecutionLimits(
            timeout_seconds=30,
            max_output_bytes=1024,
            max_stdin_bytes=max_stdin_bytes,
        ),
    )


def test_valid_forcecommand_context():
    validate_ssh_context({"SSH_ORIGINAL_COMMAND": "mcp-v1"})


def test_wrong_original_command_is_rejected():
    with pytest.raises(HostAgentProtocolError):
        validate_ssh_context({"SSH_ORIGINAL_COMMAND": "bash"})


def test_pty_is_rejected():
    with pytest.raises(HostAgentProtocolError):
        validate_ssh_context(
            {
                "SSH_ORIGINAL_COMMAND": "mcp-v1",
                "SSH_TTY": "/dev/pts/1",
            }
        )


def test_streaming_frame_round_trip():
    payload = encode_request(envelope(), b"hello")
    actual, stdin = read_request(io.BytesIO(payload))

    assert actual.executable == "/usr/bin/git"
    assert actual.argv == ("status",)
    assert stdin == b"hello"


def test_truncated_frame_is_rejected():
    with pytest.raises(HostAgentProtocolError):
        read_request(io.BytesIO(MAGIC[:3]))


def test_oversized_metadata_declaration_is_rejected_before_body_read():
    payload = MAGIC + struct.pack(">I", MAX_METADATA_BYTES + 1)

    with pytest.raises(HostAgentProtocolError):
        read_request(io.BytesIO(payload))


def test_oversized_stdin_is_rejected():
    payload = encode_request(envelope(max_stdin_bytes=4), b"1234") + b"5"

    with pytest.raises(HostAgentProtocolError):
        read_request(io.BytesIO(payload))
