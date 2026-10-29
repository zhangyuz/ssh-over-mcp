"""Contract-first tests for future fs_list/fs_search host-side rule checks.

These tests do NOT enable new MCP operations or v5 runtime policy loading.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_over_mcp.host_agent.visibility_policy_v5 import (
    VisibilityPolicyV5,
    VisibilityRules,
    canonical_visibility_path,
)


def _rules(**overrides):
    data = {
        "allow_roots": ("/srv/data/team", "/srv/data/public"),
        "deny_subtrees": ("/srv/data/team/private",),
    }
    data.update(overrides)
    return data


def _policy(**overrides):
    data = {
        "version": 5,
        "host": "node01",
        "profile": "rw-operator",
        "policy_epoch": 17,
        "central_policy_sha256": "a" * 64,
        "enabled": True,
        "operations": {"fs_list": _rules(), "fs_search": _rules()},
    }
    data.update(overrides)
    return data


def test_explicitly_enabled_v5_rules_are_bounded_and_deny_first():
    policy = VisibilityPolicyV5.model_validate(_policy())
    assert policy.visible(operation="fs_list", path="/srv/data/team")
    assert policy.visible(operation="fs_search", path="/srv/data/team/report.txt")
    assert not policy.visible(operation="fs_list", path="/srv/data/team/private")
    assert not policy.visible(operation="fs_search", path="/srv/data/team/private/a")
    assert policy.visible(operation="fs_list", path="/srv/data/team/private2")
    assert not policy.visible(operation="fs_list", path="/srv/data/team2")
    assert not policy.visible(operation="fs_list", path="/etc/hosts")
    assert not policy.visible(operation="fs_delete", path="/srv/data/team")


def test_default_disabled_even_for_valid_rules():
    raw = _policy()
    del raw["enabled"]
    policy = VisibilityPolicyV5.model_validate(raw)
    assert not policy.visible(operation="fs_list", path="/srv/data/team/a")


@pytest.mark.parametrize(
    "bad",
    [
        "relative",
        "//srv/data/team",
        "/srv//data/team",
        "/srv/data/./team",
        "/srv/data/../team",
        "/srv/data/team/",
        "/srv/data/team\\x",
        "/srv/data/te\x00am",
        "/srv/data/te\n",
        "/srv/data/t*",
        "/srv/data/t?",
        "/srv/data/t[0]",
        "/srv/data/\ud800",
        "/" + "a" * 4096,
    ],
)
def test_ambiguous_path_is_rejected_not_normalized(bad):
    with pytest.raises(ValueError):
        canonical_visibility_path(bad)


@pytest.mark.parametrize("bad", [None, 1, True, b"/srv/data", []])
def test_path_must_be_string(bad):
    with pytest.raises(ValueError):
        canonical_visibility_path(bad)


@pytest.mark.parametrize(
    "bad",
    [
        {"allow_roots": (), "deny_subtrees": ()},
        {"allow_roots": ("/srv/data/team", "/srv/data/team"), "deny_subtrees": ()},
        {"allow_roots": ("/srv/data", "/srv/data/team"), "deny_subtrees": ()},
        {"allow_roots": ("/srv/data/team",), "deny_subtrees": ("/srv/data/team",)},
        {"allow_roots": ("/srv/data/team",), "deny_subtrees": ("/srv/data/other",)},
        {
            "allow_roots": ("/srv/data/team",),
            "deny_subtrees": ("/srv/data/team/p", "/srv/data/team/p/a"),
        },
        {
            "allow_roots": ("/srv/data/team/private/x",),
            "deny_subtrees": ("/srv/data/team/private",),
        },
    ],
)
def test_rules_refuse_invalid_and_shadowed_configuration(bad):
    with pytest.raises(ValidationError):
        VisibilityRules.model_validate(bad)


@pytest.mark.parametrize("invalid", [4, 6, "5", None])
def test_policy_requires_explicit_version_5(invalid):
    with pytest.raises(ValidationError):
        VisibilityPolicyV5.model_validate(_policy(version=invalid))


@pytest.mark.parametrize("invalid", [0, -1, True, "17", None])
def test_policy_epoch_requires_strict_positive_integer(invalid):
    with pytest.raises(ValidationError):
        VisibilityPolicyV5.model_validate(_policy(policy_epoch=invalid))


def test_policy_requires_exact_two_visibility_operations():
    raw = _policy(operations={"fs_list": _rules()})
    with pytest.raises(ValidationError):
        VisibilityPolicyV5.model_validate(raw)
    raw = _policy()
    raw["operations"]["fs_delete"] = _rules()
    with pytest.raises(ValidationError):
        VisibilityPolicyV5.model_validate(raw)


def test_policy_rejects_untrusted_metadata_and_additional_keys():
    for key, value in (
        ("central_policy_sha256", "not-a-digest"),
        ("central_policy_sha256", "B" * 64),
        ("host", ""),
        ("profile", ""),
        ("enabled", "true"),
    ):
        with pytest.raises(ValidationError):
            VisibilityPolicyV5.model_validate(_policy(**{key: value}))
    raw = _policy()
    raw["silent_policy_bypass"] = True
    with pytest.raises(ValidationError):
        VisibilityPolicyV5.model_validate(raw)


def test_rule_bounds_are_hard_and_do_not_truncate():
    with pytest.raises(ValidationError):
        VisibilityRules.model_validate(
            _rules(allow_roots=tuple(f"/data/a{i}" for i in range(17)), deny_subtrees=())
        )
    with pytest.raises(ValidationError):
        VisibilityRules.model_validate(
            _rules(deny_subtrees=tuple(f"/srv/data/team/x{i}" for i in range(65)))
        )


def test_list_and_search_can_have_different_visibility_and_no_fallback():
    policy = VisibilityPolicyV5.model_validate(
        _policy(
            operations={
                "fs_list": _rules(allow_roots=("/srv/data/public",), deny_subtrees=()),
                "fs_search": _rules(
                    allow_roots=("/srv/data/team",), deny_subtrees=("/srv/data/team/private",)
                ),
            }
        )
    )
    assert policy.visible(operation="fs_list", path="/srv/data/public/a")
    assert not policy.visible(operation="fs_search", path="/srv/data/public/a")
    assert not policy.visible(operation="fs_list", path="/srv/data/team/a")
    assert policy.visible(operation="fs_search", path="/srv/data/team/a")


def test_unvalidated_rule_objects_cannot_be_used_directly_for_authorization():
    rules = VisibilityRules.model_validate(_rules())
    assert rules.matches("/srv/data/team/a")
    assert not rules.matches("/srv/data/team/private/a")
    # A matching rule does not imply control snapshot authentication, host
    # binding, inode-safe traversal or an actual enabled MCP capability.


@pytest.mark.parametrize("operation", ["fs_list", "fs_search"])
def test_legacy_smcp_v1_does_not_accept_candidate_v5_tools(operation):
    import json

    from ssh_over_mcp.ssh.protocol import ProtocolError, decode_envelope_metadata

    # Even an explicitly enabled v5 syntactic shape is not a valid v1
    # authorizing request. The active private pilot must remain four-tool-only.
    payload = {
        "version": 1,
        "request_id": "request-v5-visibility-000001",
        "profile": "rw-operator",
        "operation": operation,
        "path": "/srv/data/team",
        "page_size": 64,
    }
    with pytest.raises(ProtocolError):
        decode_envelope_metadata(json.dumps(payload).encode("utf-8"))
