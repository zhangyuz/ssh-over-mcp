import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.policy import (
    HostArgvRule,
    HostCommandRule,
    HostExecutionPolicy,
    authorize_request,
)
from ssh_over_mcp.host_agent.prepare import (
    CommandPreparationError,
    prepare_command,
)
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits


def make_executable(tmp_path: Path, name: str = "tool") -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def make_policy(executable: Path, cwd: Path | None) -> HostExecutionPolicy:
    return HostExecutionPolicy(
        allowed_profiles=frozenset({"developer"}),
        commands={
            str(executable): HostCommandRule(
                resolved_path=str(executable.resolve()),
                argv=(HostArgvRule(mode="exact", args=()),),
                cwd_roots=(str(cwd.resolve()),) if cwd else (),
                allow_no_cwd=cwd is None,
                require_root_owned=False,
            )
        },
        max_timeout_seconds=30,
        max_output_bytes=4096,
        max_stdin_bytes=0,
    )


def make_envelope(executable: Path, cwd: Path | None) -> ExecEnvelope:
    return ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable=str(executable),
        argv=(),
        cwd=str(cwd) if cwd else None,
        limits=ExecutionLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_stdin_bytes=0,
        ),
    )


def authorize(policy, envelope):
    decision = authorize_request(policy, envelope)
    assert decision.allowed is True
    assert decision.executable_identity is not None
    return decision


def test_prepare_pins_authorized_executable_and_cwd(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)
    envelope = make_envelope(executable, cwd)
    decision = authorize(policy, envelope)

    prepared = prepare_command(policy, envelope, decision)
    try:
        executable_info = os.fstat(prepared.executable_fd)
        cwd_info = os.fstat(prepared.cwd_fd)

        assert executable_info.st_ino == decision.executable_identity.inode
        assert executable_info.st_dev == decision.executable_identity.device
        assert cwd_info.st_ino == decision.cwd_identity.inode
        assert prepared.executable_format == "script"
        assert isinstance(prepared.fd_exec_supported, bool)
    finally:
        prepared.close()


def test_prepared_command_context_closes_descriptors(tmp_path: Path):
    executable = make_executable(tmp_path)
    policy = make_policy(executable, None)
    envelope = make_envelope(executable, None)
    decision = authorize(policy, envelope)

    with prepare_command(policy, envelope, decision) as prepared:
        fd = prepared.executable_fd
        os.fstat(fd)

    with pytest.raises(OSError):
        os.fstat(fd)


def test_executable_replacement_after_authorization_is_denied(tmp_path: Path):
    executable = make_executable(tmp_path)
    policy = make_policy(executable, None)
    envelope = make_envelope(executable, None)
    decision = authorize(policy, envelope)

    old = tmp_path / "old"
    executable.rename(old)
    make_executable(tmp_path)

    with pytest.raises(
        CommandPreparationError,
        match="changed after authorization",
    ):
        prepare_command(policy, envelope, decision)


def test_cwd_replacement_after_authorization_is_denied(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)
    envelope = make_envelope(executable, cwd)
    decision = authorize(policy, envelope)

    old = tmp_path / "old-work"
    cwd.rename(old)
    cwd.mkdir()

    with pytest.raises(
        CommandPreparationError,
        match="working directory changed",
    ):
        prepare_command(policy, envelope, decision)


def test_permission_change_after_authorization_is_rechecked(tmp_path: Path):
    executable = make_executable(tmp_path)
    policy = make_policy(executable, None)
    envelope = make_envelope(executable, None)
    decision = authorize(policy, envelope)

    executable.chmod(0o775)

    with pytest.raises(
        CommandPreparationError,
        match="group/other writable",
    ):
        prepare_command(policy, envelope, decision)


def test_file_capabilities_are_rechecked_on_pinned_fd(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    policy = make_policy(executable, None)
    envelope = make_envelope(executable, None)
    decision = authorize(policy, envelope)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.prepare.os.getxattr",
        lambda *args, **kwargs: b"capability",
    )

    with pytest.raises(
        CommandPreparationError,
        match="file capabilities",
    ):
        prepare_command(policy, envelope, decision)


def test_denied_authorization_cannot_be_prepared(tmp_path: Path):
    executable = make_executable(tmp_path)
    policy = make_policy(executable, None)
    envelope = make_envelope(executable, None)
    decision = authorize_request(
        policy,
        envelope.model_copy(update={"profile": "admin"}),
    )
    assert decision.allowed is False

    with pytest.raises(CommandPreparationError, match="denied"):
        prepare_command(policy, envelope, decision)
