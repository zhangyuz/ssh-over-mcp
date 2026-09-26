from ssh_over_mcp.policy.engine import PolicyEngine


def test_policy_hash_is_deterministic(inventory, policy):
    first = PolicyEngine(inventory=inventory, policy=policy).policy_version
    second = PolicyEngine(inventory=inventory, policy=policy).policy_version
    assert first == second
    assert first.startswith("sha256:")
