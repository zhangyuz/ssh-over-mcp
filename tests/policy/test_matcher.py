import pytest

from ssh_over_mcp.inventory.models import Host
from ssh_over_mcp.policy.matcher import rule_matches
from ssh_over_mcp.policy.models import Effect, EvaluationRequest, PolicyRule

HOST = Host(
    address="10.0.0.1",
    ssh_user="mcp",
    credential_ref="secret://test",
    host_key="ssh-ed25519 AAAATEST",
    labels=frozenset({"linux"}),
    allowed_roles=frozenset({"developer"}),
)


def _matches(
    rule: PolicyRule,
    *,
    executable: str | None = None,
    cwd: str | None = None,
    path: str | None = None,
    privilege: str = "user",
) -> bool:
    request = EvaluationRequest(
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        privilege=privilege,
    )
    return rule_matches(
        rule,
        request=request,
        host=HOST,
        effective_roles=frozenset({"developer"}),
        capabilities=frozenset(),
        executable=executable,
        cwd=cwd,
        path=path,
    )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("executables", None, False),
        ("executables", "/usr/bin/git", True),
        ("executables", "/usr/bin/python3", False),
        ("cwd", None, False),
        ("cwd", "/srv/projects/app", True),
        ("cwd", "/tmp", False),
        ("paths", None, False),
        ("paths", "/var/log/app.log", True),
        ("paths", "/etc/shadow", False),
    ],
)
def test_optional_pathlike_rule_constraints_require_present_matching_value(
    field: str,
    value: str | None,
    expected: bool,
):
    kwargs = {
        "id": f"test.{field}",
        "effect": Effect.ALLOW,
        field: (
            "/usr/bin/git"
            if field == "executables"
            else "/srv/projects/**"
            if field == "cwd"
            else "/var/log/**"
        ,),
    }
    rule = PolicyRule(**kwargs)
    call_kwargs = {
        "executable": None,
        "cwd": None,
        "path": None,
    }
    target = {
        "executables": "executable",
        "cwd": "cwd",
        "paths": "path",
    }[field]
    call_kwargs[target] = value

    assert _matches(rule, **call_kwargs) is expected


@pytest.mark.parametrize(
    ("privilege", "expected"),
    [
        ("root", True),
        ("user", False),
    ],
)
def test_privilege_constraint_matches_only_allowed_privilege(
    privilege: str,
    expected: bool,
):
    rule = PolicyRule(
        id="test.privilege",
        effect=Effect.ALLOW,
        privileges=("root",),
    )

    assert _matches(rule, privilege=privilege) is expected
