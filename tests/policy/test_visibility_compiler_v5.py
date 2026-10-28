"""Test-first candidate central subtree compiler; NOT connected to MCP."""

from __future__ import annotations

import pytest

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import (
    Effect,
    PolicyDocument,
    PolicyRule,
    RiskLevel,
    RiskPolicy,
    RoleSpec,
)
from ssh_over_mcp.policy.visibility_compiler_v5 import (
    VisibilityCompilationDenied,
    compile_visibility_rules,
    reauthorize_list_paths,
)


def _rule(name: str, effect: Effect, *paths: str, **kwargs) -> PolicyRule:
    return PolicyRule(
        id=name,
        effect=effect,
        tools=("fs_list",),
        roles=("operator",),
        paths=tuple(paths),
        **kwargs,
    )


def _engine(*rules: PolicyRule, roles=None, risk=None) -> PolicyEngine:
    policy = PolicyDocument(
        roles=roles or {"operator": RoleSpec(), "viewer": RoleSpec()},
        rules=tuple(rules),
        risk=risk or RiskPolicy(),
    )
    inventory = Inventory(
        hosts={
            "node01": Host(
                address="127.0.0.1",
                ssh_user="fs",
                credential_ref="node01",
                host_key="ssh-ed25519 AAAATEST",
                allowed_roles=frozenset({"operator", "viewer"}),
            )
        }
    )
    return PolicyEngine(inventory=inventory, policy=policy)


def _compile(engine: PolicyEngine, *, root="/srv/data", profile="operator", host="node01"):
    return compile_visibility_rules(
        engine, host=host, profile=profile, operation="fs_list", root=root
    )


def test_compiles_explicit_subtree_allow_and_entry_hiding_deny():
    eng = _engine(
        _rule("allow-root", Effect.ALLOW, "/srv/data"),
        _rule("allow-children", Effect.ALLOW, "/srv/data/**"),
        _rule("deny-private", Effect.DENY, "/srv/data/secrets/**"),
        _rule("deny-etc", Effect.DENY, "/etc/shadow"),
    )
    result = _compile(eng)
    assert result.rules.allow_roots == ("/srv/data",)
    assert result.rules.deny_subtrees == ("/srv/data/secrets",)
    assert result.rules.matches("/srv/data/public.txt")
    assert not result.rules.matches("/srv/data/secrets")
    assert not result.rules.matches("/srv/data/secrets/credentials")
    assert result.policy_sha256 == eng.policy_version.removeprefix("sha256:")


def test_allow_subtree_root_may_be_more_general_than_selected_root():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    result = _compile(eng, root="/srv/data")
    assert result.rules.matches("/srv/data/x/y")


def test_exact_root_allow_does_not_grant_children():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/data"))
    with pytest.raises(VisibilityCompilationDenied):
        _compile(eng)


def test_wildcard_only_descendants_does_not_grant_parent_automatically():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/data/**"))
    with pytest.raises(VisibilityCompilationDenied):
        _compile(eng)


def test_parent_deny_hides_subtree_even_if_root_is_exact_allowed():
    eng = _engine(
        _rule("allow-root", Effect.ALLOW, "/srv/data"),
        _rule("allow-children", Effect.ALLOW, "/srv/data/**"),
        _rule("deny-parent", Effect.DENY, "/srv"),
    )
    with pytest.raises(VisibilityCompilationDenied):
        _compile(eng)


def test_global_deny_blocks_all_and_global_allow_can_be_bounded():
    with pytest.raises(VisibilityCompilationDenied):
        _compile(_engine(_rule("allow", Effect.ALLOW, "/srv/**"), _rule("global", Effect.DENY)))
    result = _compile(_engine(_rule("global-allow", Effect.ALLOW)))
    assert result.rules.allow_roots == ("/srv/data",)
    assert not result.rules.matches("/etc/passwd")


@pytest.mark.parametrize(
    "ambiguous",
    [
        "/srv/data/secret*",
        "/srv/data/**/secret",
        "/srv/**/private/**",
        "/srv/data/private?",
        "/srv/data/private[0-9]",
        "/srv/data/../private/**",
        "/srv/data//private/**",
        "/srv/data/\ud800/**",
    ],
)
def test_central_deny_with_unrepresentable_match_is_refused(ambiguous):
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"), _rule("complex", Effect.DENY, ambiguous))
    with pytest.raises(VisibilityCompilationDenied):
        _compile(eng)


def test_unrepresentable_allow_fails_closed_even_with_broad_allow():
    eng = _engine(
        _rule("allow-broad", Effect.ALLOW, "/srv/**"),
        _rule("allow-unknown", Effect.ALLOW, "/srv/data/private*"),
    )
    with pytest.raises(VisibilityCompilationDenied):
        _compile(eng)


def test_exact_deny_name_conservatively_hides_children_as_well():
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        _rule("deny-exact", Effect.DENY, "/srv/data/secret"),
    )
    compiled = _compile(eng)
    assert compiled.rules.deny_subtrees == ("/srv/data/secret",)
    assert not compiled.rules.matches("/srv/data/secret/subfile")
    assert compiled.rules.matches("/srv/data/secret2")


def test_inherited_role_deny_is_preserved():
    allow = _rule("allow", Effect.ALLOW, "/srv/**")
    inherited_deny = PolicyRule(
        id="viewer-deny",
        effect=Effect.DENY,
        roles=("viewer",),
        tools=("fs_*",),
        paths=("/srv/data/private/**",),
    )
    eng = _engine(
        allow,
        inherited_deny,
        roles={"operator": RoleSpec(inherits=("viewer",)), "viewer": RoleSpec()},
    )
    assert _compile(eng).rules.deny_subtrees == ("/srv/data/private",)


def test_host_specific_deny_that_does_not_match_is_not_applied():
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        _rule("other-host", Effect.DENY, "/srv/data/secret", hosts=("node02",)),
    )
    assert _compile(eng).rules.deny_subtrees == ()


def test_default_deny_on_unknown_host_or_profile():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    for changes in ({"host": "node02"}, {"profile": "viewer"}):
        with pytest.raises(VisibilityCompilationDenied):
            _compile(eng, **changes)


def test_permission_with_approval_requirement_does_not_silently_bypass_approval():
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        risk=RiskPolicy(approval_required=frozenset({RiskLevel.LOW})),
    )
    with pytest.raises(VisibilityCompilationDenied):
        _compile(eng)


def test_shadowed_nested_deny_roots_are_collapsed_safely():
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        _rule("deny-one", Effect.DENY, "/srv/data/private/**"),
        _rule("deny-two", Effect.DENY, "/srv/data/private/child/**"),
    )
    assert _compile(eng).rules.deny_subtrees == ("/srv/data/private",)


def test_unbounded_denies_are_refused_without_truncation():
    rules = [_rule("allow", Effect.ALLOW, "/srv/**")]
    rules.extend(_rule(f"deny-{i}", Effect.DENY, f"/srv/data/secret{i}/**") for i in range(65))
    with pytest.raises(VisibilityCompilationDenied):
        _compile(_engine(*rules))


@pytest.mark.parametrize("path", ["/srv/data/../data", "//srv/data", "/srv/data/", "srv/data", "/"])
def test_requested_root_must_be_strict_canonical_and_bounded(path):
    with pytest.raises(VisibilityCompilationDenied):
        _compile(_engine(_rule("allow", Effect.ALLOW, "/srv/**")), root=path)


def test_deny_glob_prefix_also_catches_child_entry_of_recursive_pattern():
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        _rule("deny", Effect.DENY, "/srv/data/private/**"),
    )
    compiled = _compile(eng)
    assert not compiled.rules.matches("/srv/data/private")
    assert not compiled.rules.matches("/srv/data/private/visible")


def test_empty_policy_refuses():
    with pytest.raises(VisibilityCompilationDenied):
        _compile(_engine())


def _recheck(engine, paths, *, root="/srv/data", policy_sha256=None, active=None, max_entries=64):
    return reauthorize_list_paths(
        engine,
        host="node01",
        profile="operator",
        root=root,
        response_policy_sha256=policy_sha256 or engine.policy_version.removeprefix("sha256:"),
        result_paths=paths,
        max_entries=max_entries,
        is_epoch_active=active or (lambda: True),
    )


def test_reauthorization_accepts_only_valid_direct_children_in_byte_order():
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        _rule("deny", Effect.DENY, "/srv/data/private/**"),
    )
    assert _recheck(eng, ("/srv/data/a", "/srv/data/z")) == (
        "/srv/data/a",
        "/srv/data/z",
    )
    assert _recheck(eng, ()) == ()


@pytest.mark.parametrize(
    "invalid",
    [
        ("/srv/data/private",),
        ("/srv/data/private/a",),
        ("/srv/data/./a",),
        ("/srv/data/a/../b",),
        ("/srv/data/sub/child",),
        ("/srv/data/a", "/srv/data/a"),
        ("/srv/data/z", "/srv/data/a"),
        ("/srv/data/a", "/srv/data/a\ud800"),
        ("/srv/datab",),
        ("/etc/passwd",),
    ],
)
def test_reauthorization_rejects_any_bad_or_denied_remote_path(invalid):
    eng = _engine(
        _rule("allow", Effect.ALLOW, "/srv/**"),
        _rule("deny", Effect.DENY, "/srv/data/private/**"),
    )
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, invalid)


def test_reauthorization_rejects_stale_policy_digest_without_releasing_results():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a",), policy_sha256="f" * 64)


def test_reauthorization_checks_each_result_with_the_live_central_engine():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    original = eng.evaluate
    observed = []

    def tracked(req):
        observed.append(req.path)
        return original(req)

    eng.evaluate = tracked
    assert _recheck(eng, ("/srv/data/a", "/srv/data/b")) == ("/srv/data/a", "/srv/data/b")
    assert "/srv/data/a" in observed and "/srv/data/b" in observed


def test_reauthorization_fails_on_revocation_mid_result_and_after_loop():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    times = iter((True, True, False))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a", "/srv/data/b"), active=lambda: next(times))
    times = iter((True, True, False))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a",), active=lambda: next(times))


def test_reauthorization_rejects_unavailable_epoch_check():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a",), active=lambda: None)


def test_reauthorization_rejects_more_than_hard_budget_even_if_all_visible():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    paths = (f"/srv/data/{i:03d}" for i in range(65))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, paths, max_entries=64)


@pytest.mark.parametrize("bound", [0, 65, True, "64", 1.5])
def test_reauthorization_does_not_accept_invalid_page_budget(bound):
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a",), max_entries=bound)


def test_reauthorization_requires_central_subtree_authorization_not_just_root():
    eng = _engine(_rule("only-root", Effect.ALLOW, "/srv/data"))
    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a",))


def test_reauthorization_denies_on_callback_exception():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))

    def unavailable():
        raise OSError("epoch database offline")

    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, ("/srv/data/a",), active=unavailable)


def test_reauthorization_does_not_inspect_indefinitely_large_stream():
    eng = _engine(_rule("allow", Effect.ALLOW, "/srv/**"))
    calls = []

    def unbounded_stream():
        for i in range(1000):
            calls.append(i)
            yield f"/srv/data/file{i:04d}"

    with pytest.raises(VisibilityCompilationDenied):
        _recheck(eng, unbounded_stream(), max_entries=3)
    assert len(calls) <= 4
