from pathlib import Path

from ssh_over_mcp.config.loader import load_config
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import Decision, EvaluationRequest


def test_example_configuration_loads_and_evaluates():
    config_path = Path(__file__).parents[2] / "config" / "policy.example.yaml"
    config = load_config(config_path)
    engine = PolicyEngine(inventory=config.inventory, policy=config.policy)

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
