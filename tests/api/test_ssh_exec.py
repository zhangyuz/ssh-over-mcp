from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_over_mcp.api import models


def test_ssh_exec_request_is_closed_world_and_bounded() -> None:
    request_type = models.SSHExecRequest

    request = request_type(
        host="dev01",
        executable="/usr/bin/git",
        args=("status", "--short"),
        cwd="/srv/app",
        env={"LANG": "C"},
        stdin="hello",
        timeout_seconds=30,
    )

    assert request.stdin == "hello"
    assert request.timeout_seconds == 30

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            profile="ops",
        )

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            stdin="x" * ((64 * 1024) + 1),
        )

    with pytest.raises(ValidationError):
        request_type(
            host="dev01",
            executable="/bin/echo",
            timeout_seconds=60.001,
        )


def test_ssh_exec_result_uses_explicit_lossless_base64_fields() -> None:
    result_type = models.SSHExecResult

    result = result_type(
        request_id="req_12345678",
        host="dev01",
        exit_status=0,
        stdout_base64="/wA=",
        stderr_base64="/g==",
        duration_ms=12,
        timed_out=False,
        truncated=False,
    )

    assert result.stdout_base64 == "/wA="
    assert result.stderr_base64 == "/g=="
    assert set(result_type.model_fields) == {
        "request_id",
        "host",
        "exit_status",
        "exit_signal",
        "stdout_base64",
        "stderr_base64",
        "duration_ms",
        "timed_out",
        "truncated",
    }
