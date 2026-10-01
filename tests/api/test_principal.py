from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_over_mcp.api.errors import PrincipalConfigurationError
from ssh_over_mcp.api.models import (
    HostSummary,
    PolicyExplainRequest,
    PrincipalContext,
)
from ssh_over_mcp.api.principal import StaticPrincipalProvider
from ssh_over_mcp.policy.models import PolicyDocument, RoleSpec


@pytest.fixture
def policy() -> PolicyDocument:
    return PolicyDocument(
        roles={
            "developer": RoleSpec(),
            "ops": RoleSpec(),
        },
        rules=(),
    )


def test_static_principal_provider_returns_server_owned_profile(
    policy: PolicyDocument,
) -> None:
    provider = StaticPrincipalProvider(
        profile="developer",
        policy=policy,
    )

    assert provider.get_principal() == PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )


def test_principal_context_requires_server_owned_principal_id() -> None:
    with pytest.raises(ValidationError):
        PrincipalContext(profile="developer")


def test_static_principal_provider_rejects_unknown_profile(
    policy: PolicyDocument,
) -> None:
    with pytest.raises(
        PrincipalConfigurationError,
        match="configured principal profile is invalid",
    ):
        StaticPrincipalProvider(
            profile="missing",
            policy=policy,
        )


def test_host_summary_contains_only_public_fields() -> None:
    assert set(HostSummary.model_fields) == {
        "alias",
        "labels",
        "capabilities",
    }


@pytest.mark.parametrize(
    ("model_type", "kwargs"),
    [
        (
            PrincipalContext,
            {
                "profile": "developer",
                "unexpected": "value",
            },
        ),
        (
            HostSummary,
            {
                "alias": "host-a",
                "unexpected": "value",
            },
        ),
        (
            PolicyExplainRequest,
            {
                "host": "host-a",
                "tool": "ssh_exec",
                "unexpected": "value",
            },
        ),
    ],
)
def test_phase4_api_models_reject_extra_fields(
    model_type,
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model_type.model_validate(kwargs)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "executable": "/" + ("x" * 4096),
        },
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "args": tuple("x" for _ in range(257)),
        },
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "args": ("x" * 4097,),
        },
        {
            "host": "host-a",
            "tool": "fs_stat",
            "path": "/" + ("x" * 4096),
        },
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "env": {f"K{index}": "v" for index in range(129)},
        },
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "env": {"K" * 129: "v"},
        },
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "env": {"SAFE": "v" * 8193},
        },
        {
            "host": "host-a",
            "tool": "ssh_exec",
            "privilege": "p" * 65,
        },
    ],
)
def test_policy_explain_request_rejects_oversized_fields(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        PolicyExplainRequest.model_validate(payload)


def test_policy_explain_request_rejects_aggregate_metadata_over_64_kib() -> None:
    with pytest.raises(ValidationError, match="metadata exceeds maximum"):
        PolicyExplainRequest(
            host="host-a",
            tool="ssh_exec",
            args=tuple("x" * 4000 for _ in range(17)),
        )
