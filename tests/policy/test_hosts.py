from ssh_over_mcp.policy.models import Decision, EvaluationRequest


def test_unknown_host_alias_is_denied(engine):
    decision = engine.evaluate(
        EvaluationRequest(profile="developer", host="10.20.0.10", tool="host_info")
    )
    assert decision.decision == Decision.DENY
    assert "inventory" in decision.reason


def test_host_role_restriction_is_enforced(engine):
    decision = engine.evaluate(
        EvaluationRequest(profile="developer", host="prod01", tool="host_info")
    )
    assert decision.decision == Decision.DENY
    assert "not allowed on target host" in decision.reason
