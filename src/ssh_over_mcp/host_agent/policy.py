from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from ssh_over_mcp.policy.commands import normalize_executable
from ssh_over_mcp.ssh.protocol import ExecEnvelope

MAX_POLICY_BYTES = 256 * 1024
DEFAULT_POLICY_PATH = Path("/etc/ssh-over-mcp/host-policy.yaml")

_ALWAYS_DENIED_ENV = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PERL5OPT",
        "RUBYOPT",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
    }
)


class HostPolicyError(ValueError):
    """Host-local policy loading or validation failed."""


class HostArgvRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["exact", "prefix"] = "exact"
    args: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_rule(self) -> "HostArgvRule":
        if self.mode == "prefix" and not self.args:
            raise ValueError("argv prefix rule must contain at least one argument")
        if any("\x00" in value for value in self.args):
            raise ValueError("argv rules must not contain NUL")
        return self


class HostCommandRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resolved_path: str = Field(min_length=1)
    argv: tuple[HostArgvRule, ...] = Field(min_length=1)
    cwd_roots: tuple[str, ...] = ()
    allow_no_cwd: bool = False
    require_root_owned: bool = True
    allow_group_or_world_writable: bool = False

    @field_validator("resolved_path")
    @classmethod
    def validate_resolved_path(cls, value: str) -> str:
        return _validate_lexical_absolute_path(value, "resolved executable")

    @field_validator("cwd_roots")
    @classmethod
    def validate_cwd_roots(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _validate_lexical_absolute_path(value, "cwd root")
            for value in values
        )

    @model_validator(mode="after")
    def validate_cwd_policy(self) -> "HostCommandRule":
        if not self.cwd_roots and not self.allow_no_cwd:
            raise ValueError(
                "command rule must define cwd_roots or explicitly allow no cwd"
            )
        return self


class HostExecutionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[2] = 2
    allowed_profiles: frozenset[str] = Field(min_length=1)
    commands: dict[str, HostCommandRule] = Field(min_length=1)
    env_allow: frozenset[str] = frozenset()
    max_timeout_seconds: float = Field(gt=0, le=3600)
    max_output_bytes: int = Field(gt=0, le=64 * 1024 * 1024)
    max_stdin_bytes: int = Field(ge=0, le=64 * 1024 * 1024)

    @field_validator("allowed_profiles")
    @classmethod
    def validate_profiles(cls, values: frozenset[str]) -> frozenset[str]:
        if any(not value or value != value.strip() for value in values):
            raise ValueError("allowed profiles must be non-empty and trimmed")
        return values

    @field_validator("commands")
    @classmethod
    def validate_command_keys(
        cls,
        commands: dict[str, HostCommandRule],
    ) -> dict[str, HostCommandRule]:
        for requested_path in commands:
            _validate_lexical_absolute_path(
                requested_path,
                "requested executable",
            )
        return commands

    @field_validator("env_allow")
    @classmethod
    def validate_env_allow(cls, values: frozenset[str]) -> frozenset[str]:
        if values.intersection(_ALWAYS_DENIED_ENV):
            raise ValueError("hard-denied environment variables cannot be allowlisted")
        if any(not value or "=" in value or "\x00" in value for value in values):
            raise ValueError("invalid environment variable name")
        return values


class HostAuthorizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str
    resolved_executable: str | None = None
    resolved_cwd: str | None = None


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: yaml.Loader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise HostPolicyError(f"duplicate host-policy key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _validate_lexical_absolute_path(value: str, label: str) -> str:
    if "\x00" in value:
        raise ValueError(f"{label} must not contain NUL")
    try:
        normalized = normalize_executable(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be absolute") from exc
    if normalized != value:
        raise ValueError(f"{label} must be a canonical lexical path")
    return value


def load_host_policy(
    path: str | Path = DEFAULT_POLICY_PATH,
    *,
    require_root_owner: bool = True,
) -> HostExecutionPolicy:
    policy_path = Path(path)

    if not hasattr(os, "O_NOFOLLOW"):
        raise HostPolicyError("host policy requires O_NOFOLLOW support")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(policy_path, flags)
    except OSError as exc:
        raise HostPolicyError("host policy is unavailable") from exc

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise HostPolicyError("host policy must be a regular file")
        if require_root_owner and info.st_uid != 0:
            raise HostPolicyError("host policy must be owned by root")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise HostPolicyError("host policy must not be group/other writable")
        if info.st_size > MAX_POLICY_BYTES:
            raise HostPolicyError("host policy exceeds maximum size")

        data = bytearray()
        while len(data) <= MAX_POLICY_BYTES:
            remaining = MAX_POLICY_BYTES + 1 - len(data)
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            data.extend(chunk)

        if len(data) > MAX_POLICY_BYTES:
            raise HostPolicyError("host policy exceeds maximum size")
    finally:
        os.close(fd)

    try:
        raw = yaml.load(
            bytes(data).decode("utf-8"),
            Loader=_UniqueKeyLoader,
        )
        if not isinstance(raw, dict):
            raise HostPolicyError("host policy root must be a mapping")
        return HostExecutionPolicy.model_validate(raw)
    except HostPolicyError:
        raise
    except (UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise HostPolicyError("invalid host policy") from exc


def _argv_allowed(
    rules: tuple[HostArgvRule, ...],
    args: tuple[str, ...],
) -> bool:
    for rule in rules:
        if rule.mode == "exact" and args == rule.args:
            return True
        if (
            rule.mode == "prefix"
            and len(args) >= len(rule.args)
            and args[: len(rule.args)] == rule.args
        ):
            return True
    return False


def _deny(reason: str) -> HostAuthorizationResult:
    return HostAuthorizationResult(allowed=False, reason=reason)


def _resolve_executable(
    requested_path: str,
    rule: HostCommandRule,
) -> tuple[str | None, str | None]:
    try:
        expected = Path(rule.resolved_path).resolve(strict=True)
        requested = Path(requested_path).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None, "executable path cannot be resolved"

    # The configured resolved path must itself already name the canonical
    # target. This prevents policy from silently following a mutable symlink.
    if str(expected) != rule.resolved_path:
        return None, "configured resolved executable is not canonical"

    if requested != expected:
        return None, "executable resolved target does not match host policy"

    try:
        info = expected.stat()
    except OSError:
        return None, "resolved executable is unavailable"

    if not stat.S_ISREG(info.st_mode):
        return None, "resolved executable is not a regular file"
    if rule.require_root_owned and info.st_uid != 0:
        return None, "resolved executable is not root-owned"
    if (
        not rule.allow_group_or_world_writable
        and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None, "resolved executable is group/other writable"
    if not os.access(expected, os.X_OK):
        return None, "resolved executable is not executable"

    return str(expected), None


def _resolve_cwd(
    cwd: str | None,
    rule: HostCommandRule,
) -> tuple[str | None, str | None]:
    if cwd is None:
        if rule.allow_no_cwd:
            return None, None
        return None, "working directory is required by host policy"

    try:
        candidate = Path(cwd).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None, "working directory cannot be resolved"

    if not candidate.is_dir():
        return None, "working directory is not a directory"

    for root_text in rule.cwd_roots:
        try:
            root = Path(root_text).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return None, "configured cwd root cannot be resolved"

        if str(root) != root_text:
            return None, "configured cwd root is not canonical"

        try:
            candidate.relative_to(root)
            return str(candidate), None
        except ValueError:
            continue

    return None, "working directory is outside allowed roots"


def authorize_request(
    policy: HostExecutionPolicy,
    envelope: ExecEnvelope,
) -> HostAuthorizationResult:
    if envelope.profile not in policy.allowed_profiles:
        return _deny("profile is not allowed by host policy")

    rule = policy.commands.get(envelope.executable)
    if rule is None:
        return _deny("executable is not allowed by host policy")

    if any("\x00" in arg for arg in envelope.args):
        return _deny("argv contains NUL")
    if envelope.cwd is not None and "\x00" in envelope.cwd:
        return _deny("working directory contains NUL")

    if not _argv_allowed(rule.argv, envelope.args):
        return _deny("argv is not allowed by host policy")

    for name, value in envelope.env.items():
        if "\x00" in name or "\x00" in value:
            return _deny("environment contains NUL")
        if name in _ALWAYS_DENIED_ENV:
            return _deny("environment contains a hard-denied variable")
        if name not in policy.env_allow:
            return _deny("environment variable is not allowlisted")

    if envelope.limits.timeout_seconds > policy.max_timeout_seconds:
        return _deny("requested timeout exceeds host-policy ceiling")

    if envelope.limits.max_output_bytes > policy.max_output_bytes:
        return _deny("requested output limit exceeds host-policy ceiling")

    if envelope.limits.max_stdin_bytes > policy.max_stdin_bytes:
        return _deny("requested stdin limit exceeds host-policy ceiling")

    resolved_executable, error = _resolve_executable(
        envelope.executable,
        rule,
    )
    if error:
        return _deny(error)

    resolved_cwd, error = _resolve_cwd(envelope.cwd, rule)
    if error:
        return _deny(error)

    return HostAuthorizationResult(
        allowed=True,
        reason="host policy allowed request",
        resolved_executable=resolved_executable,
        resolved_cwd=resolved_cwd,
    )
