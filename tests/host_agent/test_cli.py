import io

from ssh_over_mcp.host_agent.cli import (
    EX_NOPERM,
    EX_PROTOCOL,
    EX_UNAVAILABLE,
    run,
)
from ssh_over_mcp.host_agent.policy import HostExecutionPolicy
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits, encode_request


def payload(
    executable: str = "/usr/bin/id",
    *,
    max_stdin_bytes: int = 0,
    stdin: bytes = b"",
) -> bytes:
    envelope = ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable=executable,
        limits=ExecutionLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_stdin_bytes=max_stdin_bytes,
        ),
    )
    return encode_request(envelope, stdin)


def policy(
    *executables: str,
    max_stdin_bytes: int = 0,
) -> HostExecutionPolicy:
    return HostExecutionPolicy(
        allowed_profiles=frozenset({"developer"}),
        allowed_executables=frozenset(executables or {"/usr/bin/id"}),
        max_timeout_seconds=30,
        max_output_bytes=4096,
        max_stdin_bytes=max_stdin_bytes,
    )


def test_valid_authorized_request_still_fails_closed_until_execution_phase():
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload()),
        stderr=stderr,
        policy=policy(),
    )

    assert status == EX_UNAVAILABLE
    assert "execution unavailable" in stderr.getvalue()


def test_host_policy_denial_stops_before_execution():
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload("/bin/bash")),
        stderr=stderr,
        policy=policy("/usr/bin/id"),
    )

    assert status == EX_NOPERM
    assert "denied" in stderr.getvalue()


def test_resource_ceiling_denial_does_not_read_application_stdin():
    framed = payload(
        max_stdin_bytes=16,
        stdin=b"0123456789abcdef",
    )
    stream = io.BytesIO(framed)
    stderr = io.StringIO()

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=stream,
        stderr=stderr,
        policy=policy(max_stdin_bytes=0),
    )

    assert status == EX_NOPERM
    assert stream.tell() < len(framed)


def test_invalid_forcecommand_is_rejected_without_parsing():
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "bash"},
        stdin=io.BytesIO(b"not-a-frame"),
        stderr=stderr,
        policy=policy(),
    )

    assert status == EX_PROTOCOL
    assert "rejected" in stderr.getvalue()
