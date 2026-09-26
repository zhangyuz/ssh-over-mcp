from ssh_over_mcp.policy.models import Decision, EvaluationRequest, RiskLevel


def test_git_allowed_in_dev_project(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/git",
            args=("status", "--short"),
            cwd="/srv/projects/app",
        )
    )
    assert decision.decision == Decision.ALLOW
    assert decision.normalized_executable == "/usr/bin/git"


def test_executable_is_lexically_normalized_before_policy(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="/usr/bin/../bin/bash",
        )
    )
    assert decision.normalized_executable == "/usr/bin/bash"
    assert decision.decision == Decision.DENY


def test_relative_executable_is_denied(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="dev01",
            tool="ssh_exec",
            executable="git",
        )
    )
    assert decision.decision == Decision.DENY
    assert "absolute path" in decision.reason


def test_raw_shell_is_critical_and_requires_approval_for_admin(engine):
    decision = engine.evaluate(
        EvaluationRequest(profile="admin", host="prod01", tool="ssh_shell")
    )
    assert decision.decision == Decision.APPROVAL_REQUIRED
    assert decision.risk == RiskLevel.CRITICAL
    assert decision.approval_required is True

    approved = engine.evaluate(
        EvaluationRequest(
            profile="admin",
            host="prod01",
            tool="ssh_shell",
            approval_granted=True,
        )
    )
    assert approved.decision == Decision.ALLOW
