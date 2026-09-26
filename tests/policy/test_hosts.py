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


def test_child_role_does_not_inherit_host_membership(policy):
    from ssh_over_mcp.inventory.models import Host, Inventory
    from ssh_over_mcp.policy.engine import PolicyEngine

    observer_only = Inventory(
        hosts={
            "observe01": Host(
                address="10.20.0.30",
                ssh_user="mcp-observer",
                credential_ref="secret://ssh/observe01",
                host_key="ssh-ed25519 AAAATEST",
                allowed_roles=frozenset({"observer"}),
            )
        }
    )
    engine = PolicyEngine(inventory=observer_only, policy=policy)

    decision = engine.evaluate(
        EvaluationRequest(
            profile="developer",
            host="observe01",
            tool="host_info",
        )
    )

    assert decision.decision == Decision.DENY
    assert "not allowed on target host" in decision.reason
