from ssh_over_mcp.policy.models import Decision, EvaluationRequest


def test_environment_variable_must_be_allowlisted(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/git",
            cwd="/srv/projects/app",
            env={"HOME": "/tmp/fake"},
        )
    )
    assert decision.decision == Decision.DENY
    assert "not allowlisted" in decision.reason


def test_dangerous_loader_environment_is_always_denied(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="admin",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/id",
            env={"LD_PRELOAD": "/tmp/evil.so"},
        )
    )
    assert decision.decision == Decision.DENY
    assert "LD_PRELOAD" in decision.reason


def test_role_specific_env_deny_overrides_allow(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/git",
            cwd="/srv/projects/app",
            env={"AWS_PROFILE": "prod"},
        )
    )
    assert decision.decision == Decision.DENY
    assert "denied" in decision.reason
