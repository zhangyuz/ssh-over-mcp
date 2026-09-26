from ssh_over_mcp.policy.models import Decision, EvaluationRequest


def test_default_deny_when_no_allow_rule_matches(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/curl",
        )
    )
    assert decision.decision == Decision.DENY
    assert "default deny" in decision.reason
