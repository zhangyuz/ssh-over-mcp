from __future__ import annotations

from typing import Any

from .models import EvaluationRequest, PolicyDecision


def explain_decision(
    request: EvaluationRequest, decision: PolicyDecision
) -> dict[str, Any]:
    return {
        "request": request.model_dump(mode="json", exclude={"env"}),
        "decision": decision.decision.value,
        "reason": decision.reason,
        "risk": decision.risk.value,
        "matched_allow_rules": list(decision.matched_allow_rules),
        "matched_deny_rules": list(decision.matched_deny_rules),
        "effective_roles": list(decision.effective_roles),
        "capabilities": list(decision.capabilities),
        "normalized": {
            "executable": decision.normalized_executable,
            "cwd": decision.normalized_cwd,
            "path": decision.normalized_path,
        },
        "approval_required": decision.approval_required,
        "policy_version": decision.policy_version,
    }
