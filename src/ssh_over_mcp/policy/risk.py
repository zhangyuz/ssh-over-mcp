from __future__ import annotations

from .models import EvaluationRequest, RiskLevel


def classify_risk(request: EvaluationRequest, capabilities: frozenset[str]) -> RiskLevel:
    if request.privilege != "user":
        return RiskLevel.CRITICAL
    if capabilities.intersection(
        {"shell", "privilege_escalation", "network_administration"}
    ):
        return RiskLevel.CRITICAL
    if capabilities.intersection(
        {"destructive", "container_runtime", "package_manager"}
    ):
        return RiskLevel.HIGH
    if capabilities.intersection(
        {"filesystem_mutation", "process_control", "service_control", "arbitrary_code"}
    ):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
