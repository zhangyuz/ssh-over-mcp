from __future__ import annotations

import fnmatch
import hashlib
import json

from ssh_over_mcp.inventory.models import Inventory

from .commands import classify_executable, normalize_executable
from .matcher import rule_matches
from .models import (
    Decision,
    Effect,
    EvaluationRequest,
    PolicyDecision,
    PolicyDocument,
)
from .paths import PathPolicyError, normalize_remote_path
from .risk import classify_risk


_ALWAYS_DENIED_ENV = (
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
)


class PolicyEngine:
    def __init__(self, *, inventory: Inventory, policy: PolicyDocument) -> None:
        self.inventory = inventory
        self.policy = policy
        self._validate_role_graph()
        self.policy_version = self._hash_policy()

    def _hash_policy(self) -> str:
        payload = self.policy.model_dump(mode="json")
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _validate_role_graph(self) -> None:
        roles = self.policy.roles
        for name, spec in roles.items():
            for parent in spec.inherits:
                if parent not in roles:
                    raise ValueError(f"role {name!r} inherits unknown role {parent!r}")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                raise ValueError(f"role inheritance cycle includes {name!r}")
            visiting.add(name)
            for parent in roles[name].inherits:
                visit(parent)
            visiting.remove(name)
            visited.add(name)

        for name in roles:
            visit(name)

    def _effective_roles(self, profile: str) -> frozenset[str]:
        if profile not in self.policy.roles:
            return frozenset()
        result: set[str] = set()

        def add(name: str) -> None:
            if name in result:
                return
            result.add(name)
            for parent in self.policy.roles[name].inherits:
                add(parent)

        add(profile)
        return frozenset(result)

    def _environment_failure(
        self, request: EvaluationRequest, roles: frozenset[str]
    ) -> str | None:
        if not request.env:
            return None

        allowed_patterns: list[str] = []
        denied_patterns: list[str] = list(_ALWAYS_DENIED_ENV)
        for role in roles:
            spec = self.policy.roles[role]
            allowed_patterns.extend(spec.env_allow)
            denied_patterns.extend(spec.env_deny)

        for name in request.env:
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in denied_patterns):
                return f"environment variable is denied: {name}"
            if not any(fnmatch.fnmatchcase(name, pattern) for pattern in allowed_patterns):
                return f"environment variable is not allowlisted: {name}"
        return None

    def evaluate(self, request: EvaluationRequest) -> PolicyDecision:
        roles = self._effective_roles(request.profile)
        if not roles:
            return self._deny("unknown profile", request)

        host = self.inventory.hosts.get(request.host)
        if host is None:
            return self._deny("host is not present in server-side inventory", request, roles)

        if host.allowed_roles and not roles.intersection(host.allowed_roles):
            return self._deny("profile is not allowed on target host", request, roles)

        try:
            executable = (
                normalize_executable(request.executable)
                if request.executable is not None
                else None
            )
            cwd = normalize_remote_path(request.cwd) if request.cwd else None
            path = normalize_remote_path(request.path) if request.path else None
        except (ValueError, PathPolicyError) as exc:
            return self._deny(str(exc), request, roles)

        capabilities = classify_executable(executable, request.tool)

        if request.tool == "ssh_shell" and not any(
            self.policy.roles[role].shell for role in roles
        ):
            return self._deny(
                "raw shell is not permitted for profile",
                request, roles, capabilities, executable, cwd, path,
            )

        if request.privilege != "user" and not any(
            self.policy.roles[role].sudo for role in roles
        ):
            return self._deny(
                "requested privilege is not permitted for profile",
                request, roles, capabilities, executable, cwd, path,
            )

        env_failure = self._environment_failure(request, roles)
        if env_failure:
            return self._deny(
                env_failure, request, roles, capabilities, executable, cwd, path,
            )

        matched = [
            rule
            for rule in self.policy.rules
            if rule_matches(
                rule,
                request=request,
                host=host,
                effective_roles=roles,
                capabilities=capabilities,
                executable=executable,
                cwd=cwd,
                path=path,
            )
        ]
        denied = tuple(rule.id for rule in matched if rule.effect == Effect.DENY)
        allowed = tuple(rule.id for rule in matched if rule.effect == Effect.ALLOW)
        risk = classify_risk(request, capabilities)

        if denied:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="explicit deny rule matched",
                risk=risk,
                matched_allow_rules=allowed,
                matched_deny_rules=denied,
                effective_roles=tuple(sorted(roles)),
                capabilities=tuple(sorted(capabilities)),
                normalized_executable=executable,
                normalized_cwd=cwd,
                normalized_path=path,
                approval_required=False,
                policy_version=self.policy_version,
            )

        if not allowed:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="no allow rule matched (default deny)",
                risk=risk,
                matched_allow_rules=(),
                matched_deny_rules=(),
                effective_roles=tuple(sorted(roles)),
                capabilities=tuple(sorted(capabilities)),
                normalized_executable=executable,
                normalized_cwd=cwd,
                normalized_path=path,
                approval_required=False,
                policy_version=self.policy_version,
            )

        approval_required = risk in self.policy.risk.approval_required
        if approval_required and not request.approval_granted:
            return PolicyDecision(
                decision=Decision.APPROVAL_REQUIRED,
                reason=f"{risk.value} risk operation requires approval",
                risk=risk,
                matched_allow_rules=allowed,
                matched_deny_rules=(),
                effective_roles=tuple(sorted(roles)),
                capabilities=tuple(sorted(capabilities)),
                normalized_executable=executable,
                normalized_cwd=cwd,
                normalized_path=path,
                approval_required=True,
                policy_version=self.policy_version,
            )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason="explicit allow rule matched",
            risk=risk,
            matched_allow_rules=allowed,
            matched_deny_rules=(),
            effective_roles=tuple(sorted(roles)),
            capabilities=tuple(sorted(capabilities)),
            normalized_executable=executable,
            normalized_cwd=cwd,
            normalized_path=path,
            approval_required=False,
            policy_version=self.policy_version,
        )

    def _deny(
        self,
        reason: str,
        request: EvaluationRequest,
        roles: frozenset[str] = frozenset(),
        capabilities: frozenset[str] = frozenset(),
        executable: str | None = None,
        cwd: str | None = None,
        path: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=reason,
            risk=classify_risk(request, capabilities),
            effective_roles=tuple(sorted(roles)),
            capabilities=tuple(sorted(capabilities)),
            normalized_executable=executable,
            normalized_cwd=cwd,
            normalized_path=path,
            approval_required=False,
            policy_version=self.policy_version,
        )
