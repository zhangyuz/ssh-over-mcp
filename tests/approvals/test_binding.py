from __future__ import annotations

import hashlib
from math import inf, nan

import pytest
from pydantic import ValidationError

from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.binding import (
    build_approval_binding,
    canonical_binding_bytes,
    fingerprint_argv,
    fingerprint_bytes,
    fingerprint_text,
)
from ssh_over_mcp.approvals.models import ApprovalExecutionFacts
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)


def _principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )


def _request(
    *,
    args: tuple[str, ...] = ("status", "--short"),
    env: dict[str, str] | None = None,
) -> EvaluationRequest:
    return EvaluationRequest(
        profile="developer",
        host="host-a",
        tool="ssh_exec",
        executable="/usr/bin/git",
        args=args,
        cwd="/srv/app/.",
        env=env
        if env is not None
        else {
            "B": "SUPERSECRET-B",
            "A": "SUPERSECRET-A",
        },
        privilege="user",
    )


def _decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.APPROVAL_REQUIRED,
        reason="approval required",
        risk=RiskLevel.HIGH,
        normalized_executable="/usr/bin/git",
        normalized_cwd="/srv/app",
        normalized_path=None,
        approval_required=True,
        policy_version="policy-v7",
    )


def _facts() -> ApprovalExecutionFacts:
    return ApprovalExecutionFacts(
        effective_timeout_seconds=10.0,
        effective_max_output_bytes=4096,
        effective_max_stdin_bytes=65536,
        stdin_length=3,
        stdin_fingerprint=fingerprint_bytes(b"abc"),
        content_length=None,
        content_fingerprint=None,
    )


def test_fingerprint_helpers_use_exact_sha256_format() -> None:
    assert fingerprint_bytes(b"abc") == (
        "sha256:" + hashlib.sha256(b"abc").hexdigest()
    )
    assert fingerprint_text("é") == (
        "sha256:" + hashlib.sha256("é".encode()).hexdigest()
    )


def test_argv_fingerprint_preserves_argument_boundaries() -> None:
    first = fingerprint_argv(("ab", "c"))
    second = fingerprint_argv(("a", "bc"))

    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64
    assert first != second
    assert fingerprint_argv(("ab", "c")) == first


def test_build_binding_uses_trusted_and_normalized_fields() -> None:
    binding = build_approval_binding(
        _principal(),
        _request(),
        _decision(),
        _facts(),
    )

    assert binding.principal_id == "static:developer"
    assert binding.profile == "developer"
    assert binding.host == "host-a"
    assert binding.tool == "ssh_exec"
    assert binding.privilege == "user"
    assert binding.policy_version == "policy-v7"
    assert binding.normalized_executable == "/usr/bin/git"
    assert binding.normalized_cwd == "/srv/app"
    assert binding.normalized_path is None
    assert binding.argv_count == 2
    assert binding.argv_fingerprint == fingerprint_argv(
        ("status", "--short")
    )
    assert tuple(item.name for item in binding.env_fingerprints) == (
        "A",
        "B",
    )
    assert binding.env_fingerprints[0].value_fingerprint == fingerprint_text(
        "SUPERSECRET-A"
    )
    assert binding.stdin_length == 3
    assert binding.stdin_fingerprint == fingerprint_bytes(b"abc")
    assert binding.effective_timeout_seconds == 10.0

    serialized = binding.model_dump_json()
    assert "SUPERSECRET-A" not in serialized
    assert "SUPERSECRET-B" not in serialized
    assert '"status"' not in serialized
    assert '"--short"' not in serialized


def test_environment_insertion_order_does_not_change_binding() -> None:
    first = build_approval_binding(
        _principal(),
        _request(env={"A": "one", "B": "two"}),
        _decision(),
        _facts(),
    )
    second = build_approval_binding(
        _principal(),
        _request(env={"B": "two", "A": "one"}),
        _decision(),
        _facts(),
    )

    assert first == second
    assert canonical_binding_bytes(first) == canonical_binding_bytes(second)


def test_canonical_binding_is_compact_deterministic_utf8_json() -> None:
    binding = build_approval_binding(
        _principal(),
        _request(args=("é",)),
        _decision(),
        _facts(),
    )

    first = canonical_binding_bytes(binding)
    second = canonical_binding_bytes(binding)

    assert first == second
    assert first.startswith(b"{")
    assert b": " not in first
    assert b", " not in first
    assert b"\xc3\xa9" not in first


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "host-b"),
        ("tool", "fs_read"),
        ("privilege", "root"),
        ("policy_version", "policy-v8"),
        ("normalized_executable", "/usr/bin/stat"),
        ("normalized_cwd", "/srv/other"),
        ("normalized_path", "/srv/app/file"),
        ("argv_count", 3),
        ("effective_timeout_seconds", 9.0),
        ("effective_max_output_bytes", 2048),
        ("effective_max_stdin_bytes", 1024),
        ("effective_tool_bytes", 512),
    ],
)
def test_each_material_field_change_changes_canonical_binding(
    field: str,
    value: object,
) -> None:
    binding = build_approval_binding(
        _principal(),
        _request(),
        _decision(),
        _facts(),
    )
    changed = binding.model_copy(update={field: value})

    assert canonical_binding_bytes(changed) != canonical_binding_bytes(
        binding
    )


def test_environment_value_change_changes_binding() -> None:
    first = build_approval_binding(
        _principal(),
        _request(env={"SAFE": "first"}),
        _decision(),
        _facts(),
    )
    second = build_approval_binding(
        _principal(),
        _request(env={"SAFE": "second"}),
        _decision(),
        _facts(),
    )

    assert canonical_binding_bytes(first) != canonical_binding_bytes(second)


def test_stdin_fingerprint_change_changes_binding() -> None:
    first = build_approval_binding(
        _principal(),
        _request(),
        _decision(),
        _facts(),
    )
    second = build_approval_binding(
        _principal(),
        _request(),
        _decision(),
        _facts().model_copy(
            update={
                "stdin_fingerprint": fingerprint_bytes(b"abd"),
            }
        ),
    )

    assert canonical_binding_bytes(first) != canonical_binding_bytes(second)


@pytest.mark.parametrize("value", [nan, inf])
def test_non_finite_execution_limits_are_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        ApprovalExecutionFacts(effective_timeout_seconds=value)


def test_fs_write_content_fingerprint_change_changes_binding() -> None:
    first_facts = _facts().model_copy(
        update={
            "content_length": 4,
            "content_fingerprint": fingerprint_bytes(b"data"),
        }
    )
    second_facts = first_facts.model_copy(
        update={
            "content_fingerprint": fingerprint_bytes(b"date"),
        }
    )

    first = build_approval_binding(
        _principal(),
        _request(),
        _decision(),
        first_facts,
    )
    second = build_approval_binding(
        _principal(),
        _request(),
        _decision(),
        second_facts,
    )

    assert canonical_binding_bytes(first) != canonical_binding_bytes(second)
