from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.policy import (
    HostExecutionPolicy,
    HostPolicyError,
    authorize_request,
    load_host_policy,
)
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits


def policy() -> HostExecutionPolicy:
    return HostExecutionPolicy(
        allowed_profiles=frozenset({"developer"}),
        allowed_executables=frozenset({"/usr/bin/git"}),
        env_allow=frozenset({"CI"}),
        max_timeout_seconds=60,
        max_output_bytes=1024,
        max_stdin_bytes=16,
    )


def envelope(**overrides) -> ExecEnvelope:
    values = {
        "request_id": "req_12345678",
        "profile": "developer",
        "executable": "/usr/bin/git",
        "argv": ("status",),
        "env": {"CI": "1"},
        "limits": ExecutionLimits(
            timeout_seconds=30,
            max_output_bytes=512,
            max_stdin_bytes=8,
        ),
    }
    values.update(overrides)
    return ExecEnvelope(**values)


def test_allowed_request():
    result = authorize_request(policy(), envelope(), b"hello")
    assert result.allowed is True


def test_profile_is_exactly_allowlisted():
    result = authorize_request(
        policy(),
        envelope(profile="admin"),
        b"",
    )
    assert result.allowed is False


def test_executable_is_exactly_allowlisted():
    result = authorize_request(
        policy(),
        envelope(executable="/bin/bash"),
        b"",
    )
    assert result.allowed is False


def test_unlisted_environment_variable_is_denied():
    result = authorize_request(
        policy(),
        envelope(env={"HOME": "/tmp"}),
        b"",
    )
    assert result.allowed is False


def test_loader_environment_is_hard_denied():
    result = authorize_request(
        policy(),
        envelope(env={"LD_PRELOAD": "/tmp/evil.so"}),
        b"",
    )
    assert result.allowed is False


@pytest.mark.parametrize(
    ("limits", "reason"),
    [
        (
            ExecutionLimits(
                timeout_seconds=61,
                max_output_bytes=512,
                max_stdin_bytes=8,
            ),
            "timeout",
        ),
        (
            ExecutionLimits(
                timeout_seconds=30,
                max_output_bytes=1025,
                max_stdin_bytes=8,
            ),
            "output",
        ),
        (
            ExecutionLimits(
                timeout_seconds=30,
                max_output_bytes=512,
                max_stdin_bytes=17,
            ),
            "stdin",
        ),
    ],
)
def test_resource_ceiling_is_enforced(limits, reason):
    result = authorize_request(policy(), envelope(limits=limits), b"")
    assert result.allowed is False
    assert reason in result.reason


def test_policy_loader_rejects_duplicate_keys(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
version: 1
allowed_profiles: [developer]
allowed_profiles: [admin]
allowed_executables: [/usr/bin/git]
max_timeout_seconds: 60
max_output_bytes: 1024
max_stdin_bytes: 16
""",
        encoding="utf-8",
    )

    with pytest.raises(HostPolicyError, match="duplicate"):
        load_host_policy(path, require_root_owner=False)


def test_policy_loader_rejects_group_writable_file(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
version: 1
allowed_profiles: [developer]
allowed_executables: [/usr/bin/git]
max_timeout_seconds: 60
max_output_bytes: 1024
max_stdin_bytes: 16
""",
        encoding="utf-8",
    )
    path.chmod(0o660)

    with pytest.raises(HostPolicyError, match="group/other writable"):
        load_host_policy(path, require_root_owner=False)


def test_policy_rejects_noncanonical_executable():
    with pytest.raises(ValueError):
        HostExecutionPolicy(
            allowed_profiles=frozenset({"developer"}),
            allowed_executables=frozenset({"/usr/bin/../bin/git"}),
            max_timeout_seconds=60,
            max_output_bytes=1024,
            max_stdin_bytes=16,
        )
