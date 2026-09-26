from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

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


class HostExecutionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    allowed_profiles: frozenset[str] = Field(min_length=1)
    allowed_executables: frozenset[str] = Field(min_length=1)
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

    @field_validator("allowed_executables")
    @classmethod
    def validate_executables(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if "\x00" in value:
                raise ValueError("allowed executables must not contain NUL")
            try:
                normalized = normalize_executable(value)
            except ValueError as exc:
                raise ValueError("allowed executables must be absolute") from exc
            if normalized != value:
                raise ValueError("allowed executables must be canonical lexical paths")
        return values

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


def authorize_request(
    policy: HostExecutionPolicy,
    envelope: ExecEnvelope,
) -> HostAuthorizationResult:
    if envelope.profile not in policy.allowed_profiles:
        return HostAuthorizationResult(
            allowed=False,
            reason="profile is not allowed by host policy",
        )

    if envelope.executable not in policy.allowed_executables:
        return HostAuthorizationResult(
            allowed=False,
            reason="executable is not allowed by host policy",
        )

    for name in envelope.env:
        if name in _ALWAYS_DENIED_ENV:
            return HostAuthorizationResult(
                allowed=False,
                reason="environment contains a hard-denied variable",
            )
        if name not in policy.env_allow:
            return HostAuthorizationResult(
                allowed=False,
                reason="environment variable is not allowlisted",
            )

    if envelope.limits.timeout_seconds > policy.max_timeout_seconds:
        return HostAuthorizationResult(
            allowed=False,
            reason="requested timeout exceeds host-policy ceiling",
        )

    if envelope.limits.max_output_bytes > policy.max_output_bytes:
        return HostAuthorizationResult(
            allowed=False,
            reason="requested output limit exceeds host-policy ceiling",
        )

    if envelope.limits.max_stdin_bytes > policy.max_stdin_bytes:
        return HostAuthorizationResult(
            allowed=False,
            reason="requested stdin limit exceeds host-policy ceiling",
        )

    return HostAuthorizationResult(allowed=True, reason="host policy allowed request")
