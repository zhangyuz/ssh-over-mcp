import io

from ssh_over_mcp.host_agent.cli import EX_PROTOCOL, EX_UNAVAILABLE, run
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits, encode_request


def payload() -> bytes:
    envelope = ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable="/usr/bin/id",
        limits=ExecutionLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_stdin_bytes=0,
        ),
    )
    return encode_request(envelope)


def test_valid_request_fails_closed_until_execution_phase():
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload()),
        stderr=stderr,
    )

    assert status == EX_UNAVAILABLE
    assert "execution unavailable" in stderr.getvalue()


def test_invalid_forcecommand_is_rejected_without_parsing():
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "bash"},
        stdin=io.BytesIO(b"not-a-frame"),
        stderr=stderr,
    )

    assert status == EX_PROTOCOL
    assert "rejected" in stderr.getvalue()
