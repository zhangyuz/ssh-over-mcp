from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import (
    Decision,
    Effect,
    EvaluationRequest,
    PolicyDocument,
    PolicyRule,
    RiskLevel,
)


def test_destructive_command_is_high_risk_and_needs_approval(inventory, policy):
    policy2 = PolicyDocument(
        version=policy.version,
        roles=policy.roles,
        rules=policy.rules
        + (
            PolicyRule(
                id="admin.rm",
                effect=Effect.ALLOW,
                roles=("admin",),
                hosts=("dev01",),
                tools=("ssh_exec",),
                executables=("/usr/bin/rm",),
            ),
        ),
        risk=policy.risk,
    )
    engine = PolicyEngine(inventory=inventory, policy=policy2)
    decision = engine.evaluate(
        EvaluationRequest(
            profile="admin",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/rm",
            args=("-rf", "/tmp/test"),
        )
    )
    assert decision.decision == Decision.APPROVAL_REQUIRED
    assert decision.risk == RiskLevel.HIGH
