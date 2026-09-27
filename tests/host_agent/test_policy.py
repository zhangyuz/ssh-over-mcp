from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.policy import (
    HostArgvRule,
    HostChildLimits,
    HostCommandRule,
    HostExecutionPolicy,
    HostPolicyError,
    authorize_request,
    load_host_policy,
)
from ssh_over_mcp.ssh.protocol import ExecEnvelope, ExecutionLimits


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


def make_policy(
    executable: Path,
    cwd_root: Path,
    *,
    argv: tuple[HostArgvRule, ...] | None = None,
    requested_path: Path | None = None,
    resolved_path: Path | None = None,
    allow_no_cwd: bool = False,
    max_stdin_bytes: int = 16,
) -> HostExecutionPolicy:
    requested = requested_path or executable
    resolved = resolved_path or executable.resolve()
    return HostExecutionPolicy(
        commands={
            str(requested): HostCommandRule(
                resolved_path=str(resolved),
                argv=argv
                or (
                    HostArgvRule(
                        mode="prefix",
                        args=("status",),
                    ),
                ),
                cwd_roots=() if allow_no_cwd else (str(cwd_root.resolve()),),
                allow_no_cwd=allow_no_cwd,
                require_root_owned=False,
            )
        },
        allowed_profiles=frozenset({"developer"}),
        child_limits=_child_limits(),
        env_allow=frozenset({"CI"}),
        max_timeout_seconds=60,
        max_output_bytes=1024,
        max_stdin_bytes=max_stdin_bytes,
    )


def envelope(
    executable: Path,
    cwd: Path | None,
    **overrides,
) -> ExecEnvelope:
    values = {
        "request_id": "req_12345678",
        "profile": "developer",
        "executable": str(executable),
        "argv": ("status", "--short"),
        "cwd": str(cwd) if cwd is not None else None,
        "env": {"CI": "1"},
        "limits": ExecutionLimits(
            timeout_seconds=30,
            max_output_bytes=512,
            max_stdin_bytes=8,
        ),
    }
    values.update(overrides)
    return ExecEnvelope(**values)


def test_allowed_request_returns_canonical_paths(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    result = authorize_request(policy, envelope(executable, cwd))

    assert result.allowed is True
    assert result.resolved_executable == str(executable.resolve())
    assert result.executable_identity is not None
    assert result.executable_identity.inode == executable.stat().st_ino
    assert result.resolved_cwd == str(cwd.resolve())
    assert result.cwd_identity is not None
    assert result.cwd_identity.inode == cwd.stat().st_ino


def test_profile_is_exactly_allowlisted(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    result = authorize_request(
        policy,
        envelope(executable, cwd, profile="admin"),
    )

    assert result.allowed is False


def test_unlisted_executable_is_denied(tmp_path: Path):
    executable = make_executable(tmp_path, "allowed")
    other = make_executable(tmp_path, "other")
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    result = authorize_request(policy, envelope(other, cwd))

    assert result.allowed is False


def test_argv_prefix_is_token_based(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    allowed = authorize_request(
        policy,
        envelope(executable, cwd, argv=("status", "--short")),
    )
    denied = authorize_request(
        policy,
        envelope(executable, cwd, argv=("statusx",)),
    )

    assert allowed.allowed is True
    assert denied.allowed is False


def test_exact_argv_rule_can_allow_no_arguments(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(
        executable,
        cwd,
        argv=(HostArgvRule(mode="exact", args=()),),
    )

    result = authorize_request(
        policy,
        envelope(executable, cwd, argv=()),
    )

    assert result.allowed is True


def test_empty_prefix_rule_is_rejected():
    with pytest.raises(ValueError):
        HostArgvRule(mode="prefix", args=())


def test_unlisted_environment_variable_is_denied(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    result = authorize_request(
        policy,
        envelope(executable, cwd, env={"HOME": "/tmp"}),
    )

    assert result.allowed is False


def test_loader_environment_is_hard_denied(tmp_path: Path):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    result = authorize_request(
        policy,
        envelope(executable, cwd, env={"LD_PRELOAD": "/tmp/evil.so"}),
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
def test_resource_ceiling_is_enforced(
    tmp_path: Path,
    limits: ExecutionLimits,
    reason: str,
):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    result = authorize_request(
        policy,
        envelope(executable, cwd, limits=limits),
    )

    assert result.allowed is False
    assert reason in result.reason


def test_requested_symlink_is_allowed_only_for_pinned_realpath(tmp_path: Path):
    target = make_executable(tmp_path, "target")
    link = tmp_path / "tool"
    link.symlink_to(target)
    policy = make_policy(
        target,
        tmp_path,
        requested_path=link,
        resolved_path=target,
        allow_no_cwd=True,
        argv=(HostArgvRule(mode="exact", args=()),),
    )

    result = authorize_request(
        policy,
        envelope(link, None, argv=()),
    )

    assert result.allowed is True
    assert result.resolved_executable == str(target.resolve())


def test_symlink_retarget_is_denied(tmp_path: Path):
    expected = make_executable(tmp_path, "expected")
    replacement = make_executable(tmp_path, "replacement")
    link = tmp_path / "tool"
    link.symlink_to(expected)
    policy = make_policy(
        expected,
        tmp_path,
        requested_path=link,
        resolved_path=expected,
        allow_no_cwd=True,
        argv=(HostArgvRule(mode="exact", args=()),),
    )

    link.unlink()
    link.symlink_to(replacement)

    result = authorize_request(
        policy,
        envelope(link, None, argv=()),
    )

    assert result.allowed is False
    assert "resolved target" in result.reason


def test_group_writable_executable_is_denied(tmp_path: Path):
    executable = make_executable(tmp_path)
    executable.chmod(0o775)
    policy = make_policy(
        executable,
        tmp_path,
        allow_no_cwd=True,
        argv=(HostArgvRule(mode="exact", args=()),),
    )

    result = authorize_request(
        policy,
        envelope(executable, None, argv=()),
    )

    assert result.allowed is False
    assert "writable" in result.reason


def test_cwd_symlink_escape_is_denied(tmp_path: Path):
    executable = make_executable(tmp_path)
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    escape = root / "escape"
    escape.symlink_to(outside, target_is_directory=True)
    policy = make_policy(executable, root)

    result = authorize_request(
        policy,
        envelope(executable, escape),
    )

    assert result.allowed is False
    assert "outside allowed roots" in result.reason


def test_missing_cwd_is_denied_unless_explicitly_allowed(tmp_path: Path):
    executable = make_executable(tmp_path)
    root = tmp_path / "root"
    root.mkdir()
    policy = make_policy(executable, root)

    result = authorize_request(
        policy,
        envelope(executable, None),
    )

    assert result.allowed is False
    assert "required" in result.reason


def _valid_policy_text() -> str:
    return """
version: 3
allowed_profiles: [developer]
child_limits:
  cpu_seconds: 10
  address_space_bytes: 536870912
  max_processes: 64
  file_size_bytes: 67108864
  open_files: 128
commands:
  /usr/bin/git:
    resolved_path: /usr/bin/git
    argv:
      - mode: prefix
        args: [status]
    cwd_roots: [/srv/projects]
env_allow: [CI]
max_timeout_seconds: 60
max_output_bytes: 1024
max_stdin_bytes: 16
"""


def test_policy_loader_accepts_secure_regular_file(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text(_valid_policy_text(), encoding="utf-8")
    path.chmod(0o640)

    loaded = load_host_policy(path, require_root_owner=False)

    assert loaded.allowed_profiles == frozenset({"developer"})
    assert "/usr/bin/git" in loaded.commands


def test_policy_loader_rejects_duplicate_keys(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        _valid_policy_text() + "\nallowed_profiles: [admin]\n",
        encoding="utf-8",
    )

    with pytest.raises(HostPolicyError, match="duplicate"):
        load_host_policy(path, require_root_owner=False)


def test_policy_loader_rejects_group_writable_file(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text(_valid_policy_text(), encoding="utf-8")
    path.chmod(0o660)

    with pytest.raises(HostPolicyError, match="group/other writable"):
        load_host_policy(path, require_root_owner=False)


def test_policy_loader_rejects_symlink(tmp_path: Path):
    target = tmp_path / "target.yaml"
    target.write_text(_valid_policy_text(), encoding="utf-8")
    link = tmp_path / "policy.yaml"
    link.symlink_to(target)

    with pytest.raises(HostPolicyError):
        load_host_policy(link, require_root_owner=False)


def test_policy_rejects_noncanonical_requested_executable():
    with pytest.raises(ValueError):
        HostExecutionPolicy(
            allowed_profiles=frozenset({"developer"}),
            child_limits=_child_limits(),
            commands={
                "/usr/bin/../bin/git": HostCommandRule(
                    resolved_path="/usr/bin/git",
                    argv=(HostArgvRule(mode="exact", args=()),),
                    allow_no_cwd=True,
                )
            },
            max_timeout_seconds=60,
            max_output_bytes=1024,
            max_stdin_bytes=16,
        )


def test_policy_cannot_allow_hard_denied_environment():
    with pytest.raises(ValueError):
        HostExecutionPolicy(
            allowed_profiles=frozenset({"developer"}),
            child_limits=_child_limits(),
            commands={
                "/usr/bin/git": HostCommandRule(
                    resolved_path="/usr/bin/git",
                    argv=(HostArgvRule(mode="exact", args=()),),
                    allow_no_cwd=True,
                )
            },
            env_allow=frozenset({"LD_PRELOAD"}),
            max_timeout_seconds=60,
            max_output_bytes=1024,
            max_stdin_bytes=16,
        )


def test_older_policy_versions_are_rejected(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        _valid_policy_text().replace("version: 3", "version: 2"),
        encoding="utf-8",
    )

    with pytest.raises(HostPolicyError):
        load_host_policy(path, require_root_owner=False)


@pytest.mark.parametrize(
    "overrides",
    [
        {"argv": ("status", "bad\x00arg")},
        {"cwd": "bad\x00cwd"},
        {"env": {"CI": "bad\x00value"}},
    ],
)
def test_nul_bearing_request_fields_fail_closed(tmp_path: Path, overrides):
    executable = make_executable(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()
    policy = make_policy(executable, cwd)

    request_cwd = overrides.get("cwd", cwd)
    other_overrides = {
        key: value
        for key, value in overrides.items()
        if key != "cwd"
    }
    result = authorize_request(
        policy,
        envelope(executable, request_cwd, **other_overrides),
    )

    assert result.allowed is False


def test_setuid_or_setgid_executable_is_denied_by_default(tmp_path: Path):
    executable = make_executable(tmp_path)
    executable.chmod(0o4755)
    policy = make_policy(
        executable,
        tmp_path,
        allow_no_cwd=True,
        argv=(HostArgvRule(mode="exact", args=()),),
    )

    result = authorize_request(
        policy,
        envelope(executable, None, argv=()),
    )

    assert result.allowed is False
    assert "setuid/setgid" in result.reason


def test_file_capability_executable_is_denied_by_default(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    policy = make_policy(
        executable,
        tmp_path,
        allow_no_cwd=True,
        argv=(HostArgvRule(mode="exact", args=()),),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.policy.os.getxattr",
        lambda *args, **kwargs: b"capability",
    )

    result = authorize_request(
        policy,
        envelope(executable, None, argv=()),
    )

    assert result.allowed is False
    assert "capabilities" in result.reason


def test_policy_rejects_double_slash_command_path():
    with pytest.raises(ValueError):
        HostExecutionPolicy(
            allowed_profiles=frozenset({"developer"}),
            child_limits=_child_limits(),
            commands={
                "//usr/bin/git": HostCommandRule(
                    resolved_path="/usr/bin/git",
                    argv=(HostArgvRule(mode="exact", args=()),),
                    allow_no_cwd=True,
                )
            },
            max_timeout_seconds=60,
            max_output_bytes=1024,
            max_stdin_bytes=16,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cpu_seconds", 0),
        ("address_space_bytes", 1024),
        ("max_processes", 0),
        ("file_size_bytes", -1),
        ("open_files", 3),
    ],
)
def test_child_limit_invalid_values_are_rejected(field, value):
    values = _child_limits().model_dump()
    values[field] = value

    with pytest.raises(ValueError):
        HostChildLimits(**values)
