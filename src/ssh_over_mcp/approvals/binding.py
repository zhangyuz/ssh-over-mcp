from __future__ import annotations

import hashlib
import json

from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.policy.models import (
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)

from .models import (
    ApprovalBindingInput,
    ApprovalEnvFingerprint,
    ApprovalExecutionFacts,
    ApprovalSafeSummary,
)

_ARGV_FINGERPRINT_PREFIX = b"argv-v1\x00"


def fingerprint_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def fingerprint_text(value: str) -> str:
    return fingerprint_bytes(value.encode("utf-8"))


def fingerprint_argv(argv: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(_ARGV_FINGERPRINT_PREFIX)
    for argument in argv:
        encoded = argument.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return f"sha256:{digest.hexdigest()}"


def build_approval_binding(
    principal: PrincipalContext,
    request: EvaluationRequest,
    decision: PolicyDecision,
    facts: ApprovalExecutionFacts,
) -> ApprovalBindingInput:
    if request.profile != principal.profile:
        raise ValueError("policy request profile does not match principal")

    env_fingerprints = tuple(
        ApprovalEnvFingerprint(
            name=name,
            value_fingerprint=fingerprint_text(value),
        )
        for name, value in sorted(request.env.items())
    )

    return ApprovalBindingInput(
        principal_id=principal.principal_id,
        profile=principal.profile,
        host=request.host,
        tool=request.tool,
        privilege=request.privilege,
        policy_version=decision.policy_version,
        normalized_executable=decision.normalized_executable,
        normalized_cwd=decision.normalized_cwd,
        normalized_path=decision.normalized_path,
        argv_count=len(request.args),
        argv_fingerprint=fingerprint_argv(request.args),
        env_fingerprints=env_fingerprints,
        stdin_length=facts.stdin_length,
        stdin_fingerprint=facts.stdin_fingerprint,
        content_length=facts.content_length,
        content_fingerprint=facts.content_fingerprint,
        effective_timeout_seconds=facts.effective_timeout_seconds,
        effective_max_output_bytes=facts.effective_max_output_bytes,
        effective_max_stdin_bytes=facts.effective_max_stdin_bytes,
        effective_tool_bytes=facts.effective_tool_bytes,
    )


def safe_summary_from_binding(
    binding: ApprovalBindingInput,
    risk: RiskLevel,
) -> ApprovalSafeSummary:
    return ApprovalSafeSummary(
        principal_id=binding.principal_id,
        profile=binding.profile,
        host=binding.host,
        tool=binding.tool,
        privilege=binding.privilege,
        policy_version=binding.policy_version,
        risk=risk,
        normalized_executable=binding.normalized_executable,
        normalized_cwd=binding.normalized_cwd,
        normalized_path=binding.normalized_path,
        argv_count=binding.argv_count,
        argv_fingerprint=binding.argv_fingerprint,
        env_names=tuple(item.name for item in binding.env_fingerprints),
        stdin_length=binding.stdin_length,
        stdin_fingerprint=binding.stdin_fingerprint,
        content_length=binding.content_length,
        content_fingerprint=binding.content_fingerprint,
        effective_timeout_seconds=binding.effective_timeout_seconds,
        effective_max_output_bytes=binding.effective_max_output_bytes,
        effective_max_stdin_bytes=binding.effective_max_stdin_bytes,
        effective_tool_bytes=binding.effective_tool_bytes,
    )


def canonical_binding_bytes(binding: ApprovalBindingInput) -> bytes:
    payload = binding.model_dump(mode="json")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
