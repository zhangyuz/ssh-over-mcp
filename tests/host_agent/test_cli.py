import io
import os

import pytest
from pathlib import Path

from ssh_over_mcp.host_agent.cli import (
    EX_NOPERM,
    EX_PROTOCOL,
    EX_UNAVAILABLE,
    OutputDeliveryError,
    _deliver_execution_output,
    run,
)
from ssh_over_mcp.host_agent.containment import ContainmentStats
from ssh_over_mcp.host_agent.policy import (
    HostArgvRule,
    HostChildLimits,
    HostCommandRule,
    HostContainmentLimits,
    HostContainmentPolicy,
    HostExecutionPolicy,
    HostLinuxIdentity,
)
from ssh_over_mcp.host_agent.run import SupervisedExecutionResult
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits, encode_request


def _child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024 * 1024,
        max_processes=64,
        file_size_bytes=64 * 1024 * 1024,
        open_files=128,
    )


def _containment_policy() -> HostContainmentPolicy:
    return HostContainmentPolicy(
        manager_endpoint="/run/ssh-over-mcp/containment-manager.sock",
        manager=HostLinuxIdentity(uid=2101, gid=3101),
        host_agent=HostLinuxIdentity(uid=2102, gid=3102),
        workload=HostLinuxIdentity(uid=2103, gid=3103),
        manager_client_gid=3199,
        limits=HostContainmentLimits(
            memory_max_bytes=256 * 1024 * 1024,
            pids_max=32,
            cpu_quota_us=25_000,
            cpu_period_us=100_000,
        ),
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


def test_policy_v4_executes_through_manager_and_server_owned_containment(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    base_policy = policy(executable, max_stdin_bytes=16)
    values = base_policy.model_dump()
    values["version"] = 4
    values["containment"] = _containment_policy().model_dump()
    execution_policy = HostExecutionPolicy.model_validate(values)

    class FakeClient:
        name = "containment-manager"

        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    client = FakeClient()
    observed: dict[str, object] = {}

    def fake_connect(path, *, identity_plan, timeout_seconds=2.0):
        observed["endpoint"] = str(path)
        observed["identity_plan"] = identity_plan
        observed["connect_timeout"] = timeout_seconds
        return client

    def fake_run(
        prepared,
        application_stdin,
        limits,
        *,
        workload_identity_policy,
        containment_backend,
        containment_request,
    ):
        observed["prepared_request_id"] = prepared.request_id
        observed["stdin"] = application_stdin
        observed["limits"] = limits
        observed["workload_identity_policy"] = workload_identity_policy
        observed["backend"] = containment_backend
        observed["containment_request"] = containment_request
        return SupervisedExecutionResult(
            returncode=7,
            stdout=b"stdout-\xff",
            stderr=b"stderr-\xfe",
            timed_out=False,
            output_exceeded=False,
            duration_seconds=0.01,
            containment_stats=ContainmentStats(populated=False),
        )

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.connect_authenticated_containment_manager",
        fake_connect,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.run_prepared_native",
        fake_run,
    )

    stdout = io.BytesIO()
    execution_stderr = io.BytesIO()
    control_stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            payload(
                executable,
                None,
                max_stdin_bytes=16,
                stdin=b"request-stdin",
            )
        ),
        stdout=stdout,
        stderr=control_stderr,
        execution_stderr=execution_stderr,
        policy=execution_policy,
    )

    assert status == 7
    assert stdout.getvalue() == b"stdout-\xff"
    assert execution_stderr.getvalue() == b"stderr-\xfe"
    assert control_stderr.getvalue() == ""
    assert client.closed is True
    assert observed["endpoint"] == "/run/ssh-over-mcp/containment-manager.sock"
    assert observed["prepared_request_id"] == "req_12345678"
    assert observed["stdin"] == b"request-stdin"
    assert observed["backend"] is client

    identity_plan = observed["identity_plan"]
    assert identity_plan.manager.uid == 2101
    assert identity_plan.host_agent.uid == 2102
    assert identity_plan.workload.uid == 2103
    assert identity_plan.manager_client_gid == 3199

    workload_policy = observed["workload_identity_policy"]
    assert workload_policy.identity.uid == 2103
    assert workload_policy.identity.gid == 3103
    assert workload_policy.supplementary_gids == frozenset()

    containment_request = observed["containment_request"]
    assert containment_request.request_id == "req_12345678"
    assert containment_request.limits.memory_max_bytes == 256 * 1024 * 1024
    assert containment_request.limits.pids_max == 32
    assert containment_request.limits.cpu_quota_us == 25_000
    assert containment_request.limits.cpu_period_us == 100_000


def test_policy_v4_maps_signal_returncode_to_ssh_exit_status(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    values = policy(executable).model_dump()
    values["version"] = 4
    values["containment"] = _containment_policy().model_dump()
    execution_policy = HostExecutionPolicy.model_validate(values)

    class FakeClient:
        name = "containment-manager"

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.connect_authenticated_containment_manager",
        lambda *_args, **_kwargs: FakeClient(),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.run_prepared_native",
        lambda *_args, **_kwargs: SupervisedExecutionResult(
            returncode=-9,
            stdout=b"",
            stderr=b"",
            timed_out=False,
            output_exceeded=False,
            duration_seconds=0.01,
            containment_stats=ContainmentStats(populated=False),
        ),
    )

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(executable, None)),
        stdout=io.BytesIO(),
        stderr=io.StringIO(),
        execution_stderr=io.BytesIO(),
        policy=execution_policy,
    )

    assert status == 137


def test_policy_v4_manager_failure_is_generic_and_fail_closed(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    values = policy(executable).model_dump()
    values["version"] = 4
    values["containment"] = _containment_policy().model_dump()
    execution_policy = HostExecutionPolicy.model_validate(values)

    def fail_connect(*_args, **_kwargs):
        raise RuntimeError("sensitive manager detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.connect_authenticated_containment_manager",
        fail_connect,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(executable, None)),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=execution_policy,
    )

    assert status == EX_UNAVAILABLE
    assert stderr.getvalue() == "ssh-over-mcp-host-agent: execution failed\n"
    assert "sensitive manager detail" not in stderr.getvalue()


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


def test_output_delivery_times_out_when_ssh_peer_stops_reading():
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    stdout = os.fdopen(stdout_write, "wb", buffering=0)
    execution_stderr = os.fdopen(stderr_write, "wb", buffering=0)
    try:
        with pytest.raises(OutputDeliveryError, match="timed out"):
            _deliver_execution_output(
                stdout,
                execution_stderr,
                b"x" * (1024 * 1024),
                b"",
                timeout_seconds=0.02,
            )
    finally:
        stdout.close()
        execution_stderr.close()
        os.close(stdout_read)
        os.close(stderr_read)
