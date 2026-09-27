import io
from pathlib import Path

from ssh_over_mcp.host_agent.cli import (
    EX_NOPERM,
    EX_PROTOCOL,
    EX_UNAVAILABLE,
    run,
)
from ssh_over_mcp.host_agent.policy import (
    HostArgvRule,
    HostChildLimits,
    HostCommandRule,
    HostExecutionPolicy,
)
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits, encode_request


def _child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024 * 1024,
        max_processes=64,
        file_size_bytes=64 * 1024 * 1024,
        open_files=128,
    )


def make_executable(tmp_path: Path, name: str = "tool") -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def payload(
    executable: Path,
    cwd: Path | None,
    *,
    argv: tuple[str, ...] = (),
    max_stdin_bytes: int = 0,
    stdin: bytes = b"",
) -> bytes:
    envelope = ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable=str(executable),
        argv=argv,
        cwd=str(cwd) if cwd is not None else None,
        limits=ExecutionLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_stdin_bytes=max_stdin_bytes,
        ),
    )
    return encode_request(envelope, stdin)


def policy(
    executable: Path,
    *,
    cwd_root: Path | None = None,
    max_stdin_bytes: int = 0,
) -> HostExecutionPolicy:
    return HostExecutionPolicy(
        allowed_profiles=frozenset({"developer"}),
        child_limits=_child_limits(),
        commands={
            str(executable): HostCommandRule(
                resolved_path=str(executable.resolve()),
                argv=(HostArgvRule(mode="exact", args=()),),
                cwd_roots=(str(cwd_root.resolve()),) if cwd_root else (),
                allow_no_cwd=cwd_root is None,
                require_root_owned=False,
            )
        },
        max_timeout_seconds=30,
        max_output_bytes=4096,
        max_stdin_bytes=max_stdin_bytes,
    )


def test_valid_authorized_request_still_fails_closed_until_execution_phase(
    tmp_path: Path,
):
    executable = make_executable(tmp_path)
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(executable, None)),
        stderr=stderr,
        policy=policy(executable),
    )

    assert status == EX_UNAVAILABLE
    assert "execution unavailable" in stderr.getvalue()


def test_host_policy_denial_stops_before_execution(tmp_path: Path):
    allowed = make_executable(tmp_path, "allowed")
    denied = make_executable(tmp_path, "denied")
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(denied, None)),
        stderr=stderr,
        policy=policy(allowed),
    )

    assert status == EX_NOPERM
    assert "denied" in stderr.getvalue()


def test_argv_denial_stops_before_execution(tmp_path: Path):
    executable = make_executable(tmp_path)
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            payload(executable, None, argv=("unexpected",))
        ),
        stderr=stderr,
        policy=policy(executable),
    )

    assert status == EX_NOPERM
    assert "argv" in stderr.getvalue()


def test_resource_ceiling_denial_does_not_read_application_stdin(
    tmp_path: Path,
):
    executable = make_executable(tmp_path)
    framed = payload(
        executable,
        None,
        max_stdin_bytes=16,
        stdin=b"0123456789abcdef",
    )
    stream = io.BytesIO(framed)
    stderr = io.StringIO()

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=stream,
        stderr=stderr,
        policy=policy(executable, max_stdin_bytes=0),
    )

    assert status == EX_NOPERM
    assert stream.tell() < len(framed)


def test_invalid_forcecommand_is_rejected_without_parsing(tmp_path: Path):
    executable = make_executable(tmp_path)
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "bash"},
        stdin=io.BytesIO(b"not-a-frame"),
        stderr=stderr,
        policy=policy(executable),
    )

    assert status == EX_PROTOCOL
    assert "rejected" in stderr.getvalue()
