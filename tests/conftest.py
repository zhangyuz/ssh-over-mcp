import pytest

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import Effect, PolicyDocument, PolicyRule, RoleSpec


@pytest.fixture
def inventory() -> Inventory:
    return Inventory(
        hosts={
            "dev01": Host(
                address="10.20.0.10",
                ssh_user="mcp-developer",
                credential_ref="secret://ssh/dev01",
                host_key="ssh-ed25519 AAAATESTDEV",
                labels=frozenset({"linux", "dev"}),
                allowed_roles=frozenset({"observer", "developer", "admin"}),
            ),
            "prod01": Host(
                address="10.20.0.20",
                ssh_user="mcp-operator",
                credential_ref="secret://ssh/prod01",
                host_key="ssh-ed25519 AAAATESTPROD",
                labels=frozenset({"linux", "production"}),
                allowed_roles=frozenset({"operator", "admin"}),
            ),
        }
    )


@pytest.fixture
def policy() -> PolicyDocument:
    return PolicyDocument(
        roles={
            "observer": RoleSpec(env_allow=("LANG", "LC_*")),
            "developer": RoleSpec(
                inherits=("observer",),
                env_allow=("CI",),
                env_deny=("AWS_*",),
            ),
            "operator": RoleSpec(env_allow=("LANG",)),
            "admin": RoleSpec(
                env_allow=("LANG", "LC_*", "CI", "TERM"),
                shell=True,
                sudo=True,
            ),
        },
        rules=(
            PolicyRule(
                id="observer.discovery",
                effect=Effect.ALLOW,
                roles=("observer",),
                tools=("hosts_list", "host_info"),
            ),
            PolicyRule(
                id="observer.fs-read",
                effect=Effect.ALLOW,
                roles=("observer",),
                tools=("fs_read",),
                paths=("/srv/projects/**", "/var/log/**"),
            ),
            PolicyRule(
                id="observer.inspect-exec",
                effect=Effect.ALLOW,
                roles=("observer",),
                tools=("ssh_exec",),
                executables=("/usr/bin/ls", "/usr/bin/stat", "/usr/bin/df"),
            ),
            PolicyRule(
                id="developer.git",
                effect=Effect.ALLOW,
                roles=("developer",),
                hosts=("dev*",),
                tools=("ssh_exec",),
                executables=("/usr/bin/git",),
                cwd=("/srv/projects/**",),
            ),
            PolicyRule(
                id="deny.shell-capability",
                effect=Effect.DENY,
                roles=("observer", "developer", "operator"),
                capabilities=("shell",),
            ),
            PolicyRule(
                id="deny.shadow",
                effect=Effect.DENY,
                roles=("observer", "developer", "operator", "admin"),
                tools=("fs_*",),
                paths=("/etc/shadow", "/root/**"),
            ),
            PolicyRule(
                id="operator.service",
                effect=Effect.ALLOW,
                roles=("operator",),
                hosts=("prod*",),
                tools=("service_action",),
            ),
            PolicyRule(
                id="admin.shell",
                effect=Effect.ALLOW,
                roles=("admin",),
                tools=("ssh_shell",),
            ),
            PolicyRule(
                id="admin.sudo",
                effect=Effect.ALLOW,
                roles=("admin",),
                tools=("ssh_exec",),
                privileges=("root",),
            ),
        ),
    )


@pytest.fixture
def engine(inventory: Inventory, policy: PolicyDocument) -> PolicyEngine:
    return PolicyEngine(inventory=inventory, policy=policy)
