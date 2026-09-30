from __future__ import annotations

import pytest

from ssh_over_mcp.api.errors import (
    HostNotVisibleError,
    InvalidExplainToolError,
)
from ssh_over_mcp.api.models import (
    PolicyExplainRequest,
    PrincipalContext,
)
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.models import (
    Decision,
    PolicyDecision,
    RiskLevel,
)


def host(
    *,
    suffix: str,
    allowed_roles: frozenset[str] = frozenset(),
) -> Host:
    return Host(
        address=f"10.0.0.{suffix}",
        port=2200 + int(suffix),
        ssh_user=f"secret-user-{suffix}",
        credential_ref=f"secret-credential-{suffix}",
        host_key=f"secret-host-key-{suffix}",
        labels=frozenset({f"secret-label-{suffix}"}),
        allowed_roles=allowed_roles,
    )


@pytest.fixture
def inventory() -> Inventory:
    return Inventory(
        hosts={
            "open-host": host(suffix="1"),
            "developer-host": host(
                suffix="2",
                allowed_roles=frozenset({"developer"}),
            ),
            "ops-only-host": host(
                suffix="3",
                allowed_roles=frozenset({"ops"}),
            ),
        }
    )


@pytest.fixture
def developer() -> PrincipalContext:
    return PrincipalContext(profile="developer")


class RecordingPolicy:
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.requests = []

    def evaluate(self, request):
        self.requests.append(request)
        return self.decision


def policy_decision(
    decision: Decision,
    *,
    risk: RiskLevel = RiskLevel.LOW,
    approval_required: bool = False,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="sensitive internal policy reason",
        risk=risk,
        matched_allow_rules=("secret-allow-rule",),
        matched_deny_rules=("secret-deny-rule",),
        effective_roles=("developer", "secret-parent-role"),
        capabilities=("secret-capability",),
        normalized_executable="/bin/echo",
        normalized_cwd="/srv/app",
        normalized_path="/srv/app/file",
        approval_required=approval_required,
        policy_version="sha256:public-policy-version",
    )


def test_list_hosts_returns_only_visible_aliases_and_empty_public_metadata(
    inventory: Inventory,
    developer: PrincipalContext,
) -> None:
    service = MCPService(
        inventory=inventory,
        policy=RecordingPolicy(policy_decision(Decision.ALLOW)),
    )

    result = service.list_hosts(developer)

    assert [item.alias for item in result.hosts] == [
        "developer-host",
        "open-host",
    ]
    assert all(item.labels == () for item in result.hosts)
    assert all(item.capabilities == () for item in result.hosts)

    serialized = repr(result.model_dump(mode="json"))
    for secret in (
        "10.0.0.",
        "secret-user",
        "secret-credential",
        "secret-host-key",
        "secret-label",
        "allowed_roles",
    ):
        assert secret not in serialized


@pytest.mark.parametrize("alias", ["missing-host", "ops-only-host"])
def test_get_host_hides_unknown_and_role_hidden_aliases(
    inventory: Inventory,
    developer: PrincipalContext,
    alias: str,
) -> None:
    service = MCPService(
        inventory=inventory,
        policy=RecordingPolicy(policy_decision(Decision.ALLOW)),
    )

    with pytest.raises(
        HostNotVisibleError,
        match="host is not visible",
    ):
        service.get_host(developer, alias)


def test_policy_explain_injects_principal_and_returns_sanitized_allow(
    inventory: Inventory,
    developer: PrincipalContext,
) -> None:
    policy = RecordingPolicy(policy_decision(Decision.ALLOW))
    service = MCPService(inventory=inventory, policy=policy)

    result = service.explain_policy(
        developer,
        PolicyExplainRequest(
            host="open-host",
            tool="ssh_exec",
            executable="/bin/echo",
            args=("hello",),
            cwd="/srv/app",
        ),
    )

    assert len(policy.requests) == 1
    assert policy.requests[0].profile == "developer"
    assert result.decision == Decision.ALLOW
    assert result.reason == "allowed by central policy"
    assert result.normalized_executable == "/bin/echo"
    assert result.normalized_cwd == "/srv/app"

    serialized = repr(result.model_dump(mode="json"))
    assert "secret-allow-rule" not in serialized
    assert "secret-deny-rule" not in serialized
    assert "secret-parent-role" not in serialized
    assert "secret-capability" not in serialized


@pytest.mark.parametrize(
    ("decision", "approval_required", "expected_reason"),
    [
        (
            Decision.DENY,
            False,
            "denied by central policy",
        ),
        (
            Decision.APPROVAL_REQUIRED,
            True,
            "approval required by central policy",
        ),
    ],
)
def test_policy_explain_maps_decision_to_stable_public_reason(
    inventory: Inventory,
    developer: PrincipalContext,
    decision: Decision,
    approval_required: bool,
    expected_reason: str,
) -> None:
    service = MCPService(
        inventory=inventory,
        policy=RecordingPolicy(
            policy_decision(
                decision,
                risk=RiskLevel.MEDIUM,
                approval_required=approval_required,
            )
        ),
    )

    result = service.explain_policy(
        developer,
        PolicyExplainRequest(
            host="open-host",
            tool="fs_write",
            path="/srv/app/file",
        ),
    )

    assert result.decision == decision
    assert result.reason == expected_reason
    assert result.approval_required is approval_required


@pytest.mark.parametrize("alias", ["missing-host", "ops-only-host"])
def test_policy_explain_hides_host_before_policy_evaluation(
    inventory: Inventory,
    developer: PrincipalContext,
    alias: str,
) -> None:
    policy = RecordingPolicy(policy_decision(Decision.ALLOW))
    service = MCPService(inventory=inventory, policy=policy)

    with pytest.raises(
        HostNotVisibleError,
        match="host is not visible",
    ):
        service.explain_policy(
            developer,
            PolicyExplainRequest(
                host=alias,
                tool="fs_stat",
                path="/srv/app/file",
            ),
        )

    assert policy.requests == []


def test_policy_explain_rejects_unrecognized_tool_before_evaluation(
    inventory: Inventory,
    developer: PrincipalContext,
) -> None:
    policy = RecordingPolicy(policy_decision(Decision.ALLOW))
    service = MCPService(inventory=inventory, policy=policy)
    request = PolicyExplainRequest.model_construct(
        host="open-host",
        tool="ssh_shell",
    )

    with pytest.raises(
        InvalidExplainToolError,
        match="policy explanation tool is invalid",
    ):
        service.explain_policy(developer, request)

    assert policy.requests == []


def test_policy_explain_result_schema_has_no_internal_policy_fields() -> None:
    from ssh_over_mcp.api.models import PolicyExplainResult

    assert set(PolicyExplainResult.model_fields) == {
        "decision",
        "reason",
        "risk",
        "normalized_executable",
        "normalized_cwd",
        "normalized_path",
        "approval_required",
        "policy_version",
    }
