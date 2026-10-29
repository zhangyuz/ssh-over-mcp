"""INACTIVE candidate compiler for exact central fs_list/fs_search subtree rules.

The live central PolicyEngine uses fnmatchcase on *one requested path*.
That is not a sufficient authorization for returning child metadata.
This compiler conservatively supports only absolute literal patterns and
single terminal '/**' subtree patterns. Unknown patterns fail closed, not
best-effort filtered. Output is a lexical rule set, NOT signed authority,
and is never called by the live MCP/SSH runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ssh_over_mcp.host_agent.visibility_policy_v5 import (
    VisibilityRules,
    _within,
    canonical_visibility_path,
)

from .commands import classify_executable
from .engine import PolicyEngine
from .matcher import rule_matches
from .models import Decision, Effect, EvaluationRequest, PolicyRule


class VisibilityCompilationDenied(ValueError):
    """Central policy cannot be safely represented for per-node traversal."""


@dataclass(frozen=True, slots=True)
class CompiledVisibilityRules:
    rules: VisibilityRules
    policy_sha256: str


def _pattern_root(pattern: str) -> tuple[str, bool]:
    """Only literal node or literal-root slash-double-star is representable."""

    if not isinstance(pattern, str):
        raise VisibilityCompilationDenied("unrepresentable central filesystem rule")
    recursive = pattern.endswith("/**")
    try:
        root = canonical_visibility_path(pattern[:-3] if recursive else pattern)
    except ValueError as exc:
        raise VisibilityCompilationDenied("unrepresentable central filesystem rule") from exc
    if root == "/":
        raise VisibilityCompilationDenied("unbounded central visibility pattern")
    return root, recursive


def _nonpath_rule_matches(
    engine: PolicyEngine, rule: PolicyRule, request: EvaluationRequest
) -> bool:
    host = engine.inventory.hosts[request.host]
    roles = engine._effective_roles(request.profile)
    # A pure model copy strips ONLY the path selector: the host, role,
    # capabilities, user privilege and all other selectors remain unchanged.
    # No glob evaluation of the untrusted path is used for compilation.
    return rule_matches(
        rule.model_copy(update={"paths": ()}),
        request=request,
        host=host,
        effective_roles=roles,
        capabilities=classify_executable(None, request.tool),
        executable=None,
        cwd=None,
        path=request.path,
    )


def compile_visibility_rules(
    engine: PolicyEngine,
    *,
    host: str,
    profile: str,
    operation: Literal["fs_list", "fs_search"],
    root: str,
) -> CompiledVisibilityRules:
    """Compile a conservative, root-bounded effective central subtree policy.

    This is NOT enough to issue a signed visibility grant. Live integration
    must separately authenticate host SSH-key identity, principal, epoch,
    request, policy signer and revocation state, then recheck output against
    the current central PolicyEngine before returning it to a client.
    """

    if operation not in {"fs_list", "fs_search"}:
        raise VisibilityCompilationDenied("unsupported visibility operation")
    try:
        root = canonical_visibility_path(root)
        if root == "/":
            raise ValueError("root-wide listing is not supported")
        request = EvaluationRequest(host=host, profile=profile, tool=operation, path=root)
    except (ValueError, TypeError) as exc:
        raise VisibilityCompilationDenied("invalid visibility request") from exc

    # The exact request must already be ALLOW; an approval-required decision
    # is not consent and must not bypass the separate Ledger approval gate.
    if engine.evaluate(request).decision != Decision.ALLOW:
        raise VisibilityCompilationDenied("central policy denied listing root")

    broadly_allowed = False
    denied_roots: set[str] = set()
    for rule in engine.policy.rules:
        if not _nonpath_rule_matches(engine, rule, request):
            continue

        if not rule.paths:
            if rule.effect == Effect.DENY:
                raise VisibilityCompilationDenied("central policy denies subtree")
            broadly_allowed = True
            continue

        for pattern in rule.paths:
            rule_root, recursive = _pattern_root(pattern)
            if rule.effect == Effect.ALLOW:
                if recursive and _within(root, rule_root):
                    broadly_allowed = True
                continue

            # Interpret exact-path denies as denying that node and descendants.
            # This is more restrictive than the legacy one-path fnmatchcase,
            # deliberately avoiding any authorization below a denied parent.
            if _within(root, rule_root):
                raise VisibilityCompilationDenied("central ancestor denied")
            if _within(rule_root, root):
                denied_roots.add(rule_root)

    if not broadly_allowed:
        raise VisibilityCompilationDenied(
            "central policy does not allow the entire requested subtree"
        )

    # Redundant descendants are safely hidden by a single parent deny.
    collapsed = tuple(
        candidate
        for candidate in sorted(denied_roots, key=lambda p: (len(p), p.encode("utf-8")))
        if not any(
            _within(candidate, ancestor) and candidate != ancestor for ancestor in denied_roots
        )
    )
    try:
        compiled = VisibilityRules(allow_roots=(root,), deny_subtrees=collapsed)
    except ValueError as exc:
        raise VisibilityCompilationDenied("central visibility rules exceed bounds") from exc

    if not engine.policy_version.startswith("sha256:"):
        raise VisibilityCompilationDenied("central policy digest is unavailable")
    return CompiledVisibilityRules(
        rules=compiled,
        policy_sha256=engine.policy_version.removeprefix("sha256:"),
    )


def reauthorize_list_paths(
    engine: PolicyEngine,
    *,
    host: str,
    profile: str,
    root: str,
    response_policy_sha256: str,
    result_paths,
    max_entries: int,
    is_epoch_active,
) -> tuple[str, ...]:
    """Fail-closed central reauthorization of remote list *paths*.

    This only validates path disclosure, not remote metadata authenticity or
    snapshot/response signatures. It is intentionally inactive and MUST NOT
    replace pre-traversal host-side authorization or revocation synchronization.
    """

    if type(max_entries) is not int or not 1 <= max_entries <= 64 or not callable(is_epoch_active):
        raise VisibilityCompilationDenied("central listing verification unavailable")

    def require_active() -> None:
        try:
            if is_epoch_active() is True:
                return
        except Exception as exc:
            raise VisibilityCompilationDenied("central listing verification unavailable") from exc
        raise VisibilityCompilationDenied("central listing verification unavailable")

    require_active()
    compiled = compile_visibility_rules(
        engine, host=host, profile=profile, operation="fs_list", root=root
    )
    if type(response_policy_sha256) is not str or response_policy_sha256 != compiled.policy_sha256:
        raise VisibilityCompilationDenied("central listing policy changed")

    # A remote host cannot pre-authorize a returned path merely by claiming
    # a root or an epoch: centrally re-evaluate every direct child.
    previous_name: bytes | None = None
    visible: list[str] = []
    prefix = root + "/"
    try:
        for path in result_paths:
            if len(visible) >= max_entries:
                raise VisibilityCompilationDenied("central listing result exceeds bound")
            require_active()
            canonical_visibility_path(path)
            if not path.startswith(prefix) or not path[len(prefix) :] or "/" in path[len(prefix) :]:
                raise VisibilityCompilationDenied("invalid central listing child")
            name_bytes = path[len(prefix) :].encode("utf-8", errors="strict")
            if previous_name is not None and name_bytes <= previous_name:
                raise VisibilityCompilationDenied("invalid central listing ordering")
            previous_name = name_bytes
            if not compiled.rules.matches(path):
                raise VisibilityCompilationDenied("central listing child denied")
            child = EvaluationRequest(host=host, profile=profile, tool="fs_list", path=path)
            if engine.evaluate(child).decision != Decision.ALLOW:
                raise VisibilityCompilationDenied("central listing child denied")
            visible.append(path)
        require_active()
    except VisibilityCompilationDenied:
        raise
    except Exception as exc:
        raise VisibilityCompilationDenied("central listing verification unavailable") from exc

    return tuple(visible)
