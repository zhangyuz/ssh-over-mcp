"""Verify proposed OCI and network proof contract is complete, not authorized."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs/superpowers/specs/2026-10-24-mode-a-oci-privilege-and-network-proof-matrix.md"
ADR = ROOT / "docs/decisions/0022-proposed-compose-ssh-privilege-domains.md"
COMPOSE = ROOT / "deploy/compose/compose.dev-ssh.yaml"


def test_oci_role_matrix_contains_every_privilege_and_identity_boundary():
    s = SPEC.read_text()
    for name in (
        "sshd master",
        "SSH login",
        "fixed launcher",
        "trusted host agent",
        "containment manager",
        "workload",
        "typed filesystem",
    ):
        assert name in s
    for keyword in (
        "UID/GID",
        "NoNewPrivs",
        "CAP_SETUID",
        "CAP_SETGID",
        "ambient",
        "inheritable",
        "FD",
        "cgroup v2",
        "SO_PEERCRED",
        "no argv",
        "root-owned",
        "exact digest",
    ):
        assert keyword in s


def test_network_matrix_requires_directional_denial_and_stateful_return():
    s = SPEC.read_text()
    for keyword in (
        "node01",
        "node02",
        "MCP TCP/8000",
        "NEW",
        "ESTABLISHED",
        "host/LAN",
        "spoof",
        "private bridge",
        "origin authentication",
        "fail closed",
    ):
        assert keyword in s
    assert "runtime proof required" in s


def test_unapproved_exception_is_not_applied_to_compose():
    s = COMPOSE.read_text()
    assert s.count('cap_drop: ["ALL"]') == 2
    assert s.count('security_opt: ["no-new-privileges:true"]') == 2
    assert "privileged: true" not in s
    assert "runtime privilege exception not approved" in SPEC.read_text()
    assert "PROPOSED, not accepted" in ADR.read_text()


def test_static_compose_really_shares_private_bridges_both_directions():
    # A graph edge is bidirectional; internal:true does not prove node->MCP deny.
    # This is not an iptables/nftables/packet acceptance test.
    import yaml

    model = yaml.safe_load(COMPOSE.read_text().replace("!override", ""))
    control = set(model["services"]["mcp"]["networks"])
    for node in ("node01", "node02"):
        bridges = set(model["services"][node]["networks"])
        assert bridges == {f"{node}_ssh"}
        assert control & bridges
        assert model["networks"][f"{node}_ssh"]["internal"] is True
    assert "ports" not in model["services"]["node01"]
    assert "ports" not in model["services"]["node02"]
