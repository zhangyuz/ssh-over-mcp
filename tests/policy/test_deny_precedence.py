from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import (
    Decision,
    Effect,
    EvaluationRequest,
    PolicyDocument,
    PolicyRule,
)


def test_explicit_deny_overrides_allow(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/bin/bash",
        )
    )
    assert decision.decision == Decision.DENY
    assert "deny.shell-capability" in decision.matched_deny_rules


def test_inherited_parent_deny_cannot_be_overridden(inventory, policy):
    policy2 = PolicyDocument(
        version=policy.version,
        roles=policy.roles,
        rules=policy.rules
        + (
            PolicyRule(
                id="observer.bash.deny",
                effect=Effect.DENY,
                roles=("observer",),
                tools=("ssh_exec",),
                executables=("/bin/bash",),
            ),
            PolicyRule(
                id="developer.bash.allow",
                effect=Effect.ALLOW,
                roles=("developer",),
                tools=("ssh_exec",),
                executables=("/bin/bash",),
            ),
        ),
        risk=policy.risk,
    )
    engine2 = PolicyEngine(inventory=inventory, policy=policy2)
    decision = engine2.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/bin/bash",
        )
    )
    assert decision.decision == Decision.DENY
    assert "observer.bash.deny" in decision.matched_deny_rules
    assert "developer.bash.allow" in decision.matched_allow_rules
