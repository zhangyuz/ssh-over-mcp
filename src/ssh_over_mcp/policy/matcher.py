from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from ssh_over_mcp.inventory.models import Host

from .models import EvaluationRequest, PolicyRule


def _any_match(value: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _argv_prefix_matches(args: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    if not prefix:
        return True
    if len(args) < len(prefix):
        return False
    return all(fnmatch.fnmatchcase(value, pattern) for value, pattern in zip(args, prefix))


def rule_matches(
    rule: PolicyRule,
    *,
    request: EvaluationRequest,
    host: Host,
    effective_roles: frozenset[str],
    capabilities: frozenset[str],
    executable: str | None,
    cwd: str | None,
    path: str | None,
) -> bool:
    if rule.roles and not effective_roles.intersection(rule.roles):
        return False
    if rule.hosts and not _any_match(request.host, rule.hosts):
        return False
    if rule.host_labels and not set(rule.host_labels).issubset(host.labels):
        return False
    if rule.tools and not _any_match(request.tool, rule.tools):
        return False
    if rule.executables and (
        executable is None or not _any_match(executable, rule.executables)
    ):
        return False
    if rule.capabilities and not capabilities.intersection(rule.capabilities):
        return False
    if not _argv_prefix_matches(request.args, rule.argv_prefix):
        return False
    if rule.cwd and (cwd is None or not _any_match(cwd, rule.cwd)):
        return False
    if rule.paths and (path is None or not _any_match(path, rule.paths)):
        return False
    return not rule.privileges or _any_match(request.privilege, rule.privileges)
