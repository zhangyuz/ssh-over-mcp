"""Offline operator-facing Compose configuration shape/security refusal tests.

These are synthetic config structures, not evidence of running Docker Engines.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "ops/mvp/compose_config_preflight.py"
PIN = "registry.example.test/som@sha256:" + "a" * 64


def service(**updates):
    value = {
        "image": PIN,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
    }
    value.update(updates)
    return value


def reviewed_control_service(role, **updates):
    """Fixture mirrors the existing control-plane Compose UID/entrypoint pins."""
    props = {
        "ledger-init": {
            "user": "0:0",
            "entrypoint": ["ssh-over-mcp-ledger-init"],
        },
        "ledger": {
            "user": "10002:10002",
            "entrypoint": ["ssh-over-mcp-ledger"],
            "group_add": ["10003", "10005"],
        },
        "mcp": {
            "user": "10001:10003",
            "entrypoint": ["ssh-over-mcp-server"],
        },
        "approvalctl": {
            "user": "10004:10005",
            "entrypoint": ["ssh-over-mcp-approvalctl"],
        },
        "cloudflared": {
            "user": "65532:65532",
            "command": ["tunnel", "run", "--token-file", "/run/secrets/cloudflare-tunnel-token"],
        },
    }
    if role in ("ledger", "ledger-init"):
        props[role]["environment"] = {
            "SSH_OVER_MCP_LEDGER_DB_PATH": "/var/lib/ssh-over-mcp/ledger/ledger.db",
            "SSH_OVER_MCP_LEDGER_HMAC_KEY_PATH": "/var/lib/ssh-over-mcp/ledger/ledger.key",
            "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
            "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
            "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": "/run/ssh-over-mcp-exec/ledger/ledger.sock",
            "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_GID": "10003",
            "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_MODE": "0660",
            "SSH_OVER_MCP_LEDGER_EXEC_PEER_UID": "10001",
            "SSH_OVER_MCP_LEDGER_EXEC_PEER_GID": "10003",
            "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": "/run/ssh-over-mcp-admin/ledger/ledger.sock",
            "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_GID": "10005",
            "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_MODE": "0660",
            "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID": "10004",
            "SSH_OVER_MCP_LEDGER_ADMIN_PEER_GID": "10005",
        }
    elif role == "mcp":
        props[role]["environment"] = {
            "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
            "SSH_OVER_MCP_CREDENTIAL_MAP": "/etc/ssh-over-mcp/credentials.yaml",
            "SSH_OVER_MCP_PROFILE": "rw-operator",
            "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": "/run/ssh-over-mcp-exec/ledger/ledger.sock",
            "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
            "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
            "SSH_OVER_MCP_BIND_HOST": "0.0.0.0",
            "SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE": "/run/secrets/origin-bearer",
        }
    elif role == "approvalctl":
        props[role]["environment"] = {
            "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": "/run/ssh-over-mcp-admin/ledger/ledger.sock",
            "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
            "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
        }
    value = service(**props[role])
    value.update(updates)
    return value


def control(mode):
    networks = {"origin_internal": {"internal": True}}
    if mode == "dev-e2e":
        networks.update({"node01_ssh": {"internal": True}, "node02_ssh": {"internal": True}})
        mcp_nets = ["origin_internal", "node01_ssh", "node02_ssh"]
    else:
        networks["private_ssh_egress"] = {}
        mcp_nets = ["origin_internal", "private_ssh_egress"]
    services = {
        "ledger-init": reviewed_control_service(
            network_mode="none", cap_add=["CHOWN", "DAC_OVERRIDE"], role="ledger-init"
        ),
        "ledger": reviewed_control_service(role="ledger", network_mode="none"),
        "mcp": reviewed_control_service(role="mcp", networks=mcp_nets),
    }
    if mode == "dev-e2e":
        for alias in ("node01", "node02"):
            services[alias] = service(
                networks=[alias + "_ssh"],
                volumes=[
                    {"type": "volume", "source": alias + "-data", "target": "/srv/data"},
                    {"type": "volume", "source": alias + "-keys", "target": "/etc/ssh/hostkeys"},
                ],
            )
    return {"services": services, "networks": networks}


def host():
    return {
        "services": {
            "ssh-target": service(
                networks=["ssh_private"],
                volumes=[
                    {"type": "volume", "source": "ssh-data", "target": "/srv/data"},
                    {"type": "volume", "source": "ssh-keys", "target": "/etc/ssh/hostkeys"},
                ],
            ),
        },
        "networks": {"ssh_private": {"internal": True}},
    }


def invoke(tmp_path, mode="dev-e2e", control_doc=None, node01_doc=None, node02_doc=None):
    control_doc = control(mode) if control_doc is None else control_doc
    p = tmp_path / "control.json"
    p.write_text(json.dumps(control_doc))
    args = [sys.executable, str(CLI), "--mode", mode, "--control-json", str(p)]
    if mode == "multi-host":
        for alias, value in (("node01", node01_doc), ("node02", node02_doc)):
            node = tmp_path / (alias + ".json")
            node.write_text(json.dumps(host() if value is None else value))
            args.extend(["--" + alias + "-json", str(node)])
    return subprocess.run(args, capture_output=True, text=True, check=False, timeout=6)


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_offline_good_shape_is_not_deployment_authorization(tmp_path, mode):
    result = invoke(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == mode
    assert report["static_compose_shape_valid"] is True
    assert report["deployment_ready"] is False
    assert report["image_trust_verified"] is False
    assert report["network_acl_verified"] is False
    assert report["runtime_verified"] is False
    assert report["host_identity_verified"] is False
    assert report["target_count"] == 2


@pytest.mark.parametrize(
    "defect",
    [
        "mutable_image",
        "privileged",
        "host_network",
        "host_pid",
        "published_ssh",
        "docker_socket",
        "cgroup_bind",
        "shared_target_volume",
        "target_lateral_network",
        "missing_mcp_target_net",
        "extra_service",
        "missing_read_only",
        "add_admin_socket",
        "capability",
        "missing_nnp",
        "target_no_hostkeys",
    ],
)
def test_mode_a_refuses_unsafe_config_without_source_reflection(tmp_path, defect):
    doc = control("dev-e2e")
    services = doc["services"]
    if defect == "mutable_image":
        services["node01"]["image"] = "repo:latest"
    elif defect == "privileged":
        services["node02"]["privileged"] = True
    elif defect == "host_network":
        services["node01"]["network_mode"] = "host"
    elif defect == "host_pid":
        services["mcp"]["pid"] = "host"
    elif defect == "published_ssh":
        services["node01"]["ports"] = [{"target": 22, "published": "22"}]
    elif defect == "docker_socket":
        services["node01"]["volumes"].append(
            {
                "type": "bind",
                "source": "/var/run/docker.sock",
                "target": "/var/run/docker.sock",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
        )
    elif defect == "cgroup_bind":
        services["node01"]["volumes"].append(
            {
                "type": "bind",
                "source": "/sys/fs/cgroup",
                "target": "/sys/fs/cgroup",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
        )
    elif defect == "shared_target_volume":
        services["node02"]["volumes"][0]["source"] = "node01-data"
    elif defect == "target_lateral_network":
        services["node01"]["networks"].append("node02_ssh")
    elif defect == "missing_mcp_target_net":
        services["mcp"]["networks"].remove("node01_ssh")
    elif defect == "extra_service":
        services["sidecar"] = service()
    elif defect == "missing_read_only":
        services["node01"]["read_only"] = False
    elif defect == "add_admin_socket":
        services["node01"]["volumes"].append(
            {"type": "volume", "source": "ledger-admin", "target": "/run/ssh-over-mcp-admin"}
        )
    elif defect == "capability":
        services["node01"]["cap_add"] = ["SYS_ADMIN"]
    elif defect == "missing_nnp":
        services["node01"]["security_opt"] = []
    elif defect == "target_no_hostkeys":
        services["node01"]["volumes"].pop()
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert "preflight refused:" in result.stderr
    assert "registry.example.test" not in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize(
    "defect",
    [
        "target_privileged",
        "target_own_host_network",
        "target_published_port",
        "control_extra_ssh_service",
        "missing_target_volume",
    ],
)
def test_mode_b_refuses_dangerous_per_host_projects(tmp_path, defect):
    c = control("multi-host")
    h = host()
    if defect == "target_privileged":
        h["services"]["ssh-target"]["privileged"] = True
    elif defect == "target_own_host_network":
        h["services"]["ssh-target"]["network_mode"] = "host"
    elif defect == "target_published_port":
        h["services"]["ssh-target"]["ports"] = ["0.0.0.0:22:22"]
    elif defect == "control_extra_ssh_service":
        c["services"]["ssh-target"] = service()
    elif defect == "missing_target_volume":
        h["services"]["ssh-target"]["volumes"].pop()
    result = invoke(tmp_path, "multi-host", control_doc=c, node02_doc=h)
    assert result.returncode != 0
    assert result.stdout == ""


def test_missing_multi_host_project_and_suspicious_input_rejected(tmp_path):
    p = tmp_path / "control.json"
    p.write_text(json.dumps(control("multi-host")))
    args = [sys.executable, str(CLI), "--mode", "multi-host", "--control-json", str(p)]
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode != 0

    link = tmp_path / "link.json"
    link.symlink_to(p)
    args = [sys.executable, str(CLI), "--mode", "dev-e2e", "--control-json", str(link)]
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode != 0
    assert result.stdout == ""

    p.write_text('{"services":{},"services":{}}')
    args[-1] = str(p)
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode != 0

    p.write_bytes(b" " * (16 * 1024 + 1))
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode != 0


def test_current_repo_compose_is_not_silently_claimed_hardened():
    source = (ROOT / "deploy/compose/compose.yaml").read_text()
    assert "ssh-over-mcp:phase6b" in source
    assert "ssh_egress: {}" in source


def test_mode_a_allows_read_only_control_config_bind_and_project_named_volumes(tmp_path):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": "/operator-owned/config.yaml",
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
    ]
    for alias in ("node01", "node02"):
        for mount in doc["services"][alias]["volumes"]:
            mount["source"] = "som_" + mount["source"]
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode == 0, response.stderr


def test_mode_a_refuses_mcp_access_to_target_volume(tmp_path):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {"type": "volume", "source": "node01-data", "target": "/unsafe-data"},
    ]
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode != 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("cap_add", [["SYS_ADMIN"]]),
        ("networks", [["node01_ssh"]]),
    ],
)
def test_adversarial_nested_types_do_not_echo_or_traceback(tmp_path, field, value):
    doc = control("dev-e2e")
    doc["services"]["node01"][field] = value
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode != 0
    assert "Traceback" not in response.stderr
    assert "registry.example.test" not in response.stderr


def test_cloudflared_cannot_join_an_ssh_target_network(tmp_path):
    doc = control("dev-e2e")
    doc["services"]["cloudflared"] = reviewed_control_service(
        "cloudflared", networks=["origin_internal", "node01_ssh"]
    )
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0


@pytest.mark.parametrize(
    "source",
    [
        "/",
        "/private/../var/run/docker.sock",
        "/etc/../sys/fs/cgroup",
        "/tmp/./config",
    ],
)
def test_control_ro_bind_rejects_unsafe_or_noncanonical_host_source(tmp_path, source):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode != 0


def test_target_mount_denies_dot_path_alias(tmp_path):
    doc = control("dev-e2e")
    doc["services"]["node01"]["volumes"][0]["target"] = "/srv/../srv/data"
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode != 0


def test_mode_b_refuses_project_prefixed_admin_volume(tmp_path):
    h = host()
    h["services"]["ssh-target"]["volumes"][0]["source"] = "other_ledger-admin"
    response = invoke(tmp_path, "multi-host", node01_doc=h)
    assert response.returncode != 0


@pytest.mark.parametrize(
    "defect",
    [
        "seccomp_unconfined",
        "duplicate_resolved_network_name",
        "duplicate_resolved_volume_name",
        "external_target_volume",
    ],
)
def test_known_compose_name_alias_and_hardening_bypasses_refused(tmp_path, defect):
    doc = control("dev-e2e")
    if defect == "seccomp_unconfined":
        doc["services"]["node01"]["security_opt"].append("seccomp:unconfined")
    elif defect == "duplicate_resolved_network_name":
        doc["networks"]["node01_ssh"]["name"] = "same-shared-bridge"
        doc["networks"]["node02_ssh"]["name"] = "same-shared-bridge"
    elif defect == "duplicate_resolved_volume_name":
        doc["volumes"] = {
            "node01-data": {"name": "som-shared-target-data"},
            "node02-data": {"name": "som-shared-target-data"},
        }
    elif defect == "external_target_volume":
        doc["volumes"] = {"node01-data": {"external": True}}
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode != 0
    assert response.stdout == ""


@pytest.mark.parametrize("source", ["/var", "/var/run", "/run", "/sys"])
def test_read_only_bind_ancestor_of_docker_socket_is_denied(tmp_path, source):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    response = invoke(tmp_path, control_doc=doc)
    assert response.returncode != 0
    assert response.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_accepts_rendered_compose_null_network_attachments(tmp_path, mode):
    doc = control(mode)
    doc["services"]["mcp"]["networks"] = {name: None for name in doc["services"]["mcp"]["networks"]}
    if mode == "dev-e2e":
        for alias in ("node01", "node02"):
            doc["services"][alias]["networks"] = {alias + "_ssh": None}
        result = invoke(tmp_path, mode, control_doc=doc)
    else:
        h = host()
        h["services"]["ssh-target"]["networks"] = {"ssh_private": None}
        result = invoke(tmp_path, mode, control_doc=doc, node01_doc=h, node02_doc=h)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize("source", ["/var//run/docker.sock", "/var/run//docker.sock"])
def test_duplicate_separator_bind_source_cannot_hide_socket(tmp_path, source):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_resolved_target_volume_cannot_alias_ledger_admin(tmp_path, mode):
    if mode == "dev-e2e":
        doc = control(mode)
        doc["volumes"] = {"node01-data": {"name": "other_ledger-admin"}}
        result = invoke(tmp_path, mode, control_doc=doc)
    else:
        target = host()
        target["volumes"] = {"ssh-data": {"name": "other_ledger-admin"}}
        result = invoke(tmp_path, mode, node01_doc=target)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "source",
    [
        "/run/user",
        "/run/user/1000",
        "/run/user/1000/docker.sock",
    ],
)
def test_rootless_docker_runtime_mount_refused(tmp_path, source):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/daemon-api",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize(
    "defect",
    [
        "mcp_ledger_admin",
        "mcp_ledger_data",
        "mcp_resolved_ledger_admin",
        "approvalctl_ledger_exec",
        "cloudflared_ledger_data",
        "mcp_exec_not_readonly",
    ],
)
def test_control_volume_role_boundaries_refuse_conflicts(tmp_path, defect):
    doc = control("dev-e2e")
    role = "mcp"
    source = "ledger-admin"
    ro = True
    if defect == "mcp_ledger_data":
        source = "ledger-data"
    elif defect == "mcp_resolved_ledger_admin":
        source = "custom-data"
        doc["volumes"] = {source: {"name": "external_ledger-admin"}}
    elif defect == "approvalctl_ledger_exec":
        role = "approvalctl"
        doc["services"][role] = reviewed_control_service(role, network_mode="none")
        source = "ledger-exec"
    elif defect == "cloudflared_ledger_data":
        role = "cloudflared"
        doc["services"][role] = reviewed_control_service(role, networks=["origin_internal"])
        source = "ledger-data"
    elif defect == "mcp_exec_not_readonly":
        source = "ledger-exec"
        ro = False
    doc["services"][role]["volumes"] = [
        {"type": "volume", "source": source, "target": "/run/ssh-over-mcp-exec", "read_only": ro}
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


def test_control_volume_role_allows_legitimate_mcp_ledger_approvalctl_mounts(tmp_path):
    doc = control("dev-e2e")
    mapping = {
        "ledger-init": [
            ("ledger-data", "/var/lib/ssh-over-mcp", False),
            ("ledger-exec", "/run/ssh-over-mcp-exec", False),
            ("ledger-admin", "/run/ssh-over-mcp-admin", False),
        ],
        "ledger": [
            ("ledger-data", "/var/lib/ssh-over-mcp", False),
            ("ledger-exec", "/run/ssh-over-mcp-exec", False),
            ("ledger-admin", "/run/ssh-over-mcp-admin", False),
        ],
        "mcp": [("ledger-exec", "/run/ssh-over-mcp-exec", True)],
        "approvalctl": [("ledger-admin", "/run/ssh-over-mcp-admin", True)],
    }
    doc["services"]["approvalctl"] = reviewed_control_service("approvalctl", network_mode="none")
    doc["volumes"] = {
        name: {"name": "som_" + name} for name in ("ledger-data", "ledger-exec", "ledger-admin")
    }
    for role, mounts in mapping.items():
        doc["services"][role]["volumes"] = [
            {"type": "volume", "source": source, "target": target, "read_only": read_only}
            for source, target, read_only in mounts
        ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize("driver", ["host", "none", "overlay", "plugin.example/magic"])
def test_non_bridge_network_drivers_refused(tmp_path, driver):
    doc = control("dev-e2e")
    doc["networks"]["node01_ssh"]["driver"] = driver
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("target", ["/", "/run", "/run/ssh-over-mcp-admin"])
def test_mcp_readonly_bind_cannot_cover_ledger_runtime_targets(tmp_path, target):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": "/operator-owned/notes",
            "target": target,
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize(
    "source",
    [
        "/run/containerd/containerd.sock",
        "/run/containerd",
        "/run/podman/podman.sock",
        "/var/run/podman",
        "/var/run/crio/crio.sock",
        "/var/lib/docker/volumes/som_ledger-admin/_data",
        "/var/lib/docker",
        "/var/lib/containers/storage/volumes/som_ledger-data/_data",
        "/var/lib/containerd",
    ],
)
def test_management_runtime_and_volume_backend_bind_sources_refused(tmp_path, source):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "options",
    [
        {"selinux": "Z"},
        {"selinux": "z"},
        {"propagation": "rshared"},
        {"create_host_path": True},
        {"create_host_path": False, "selinux": "Z"},
    ],
)
def test_read_only_bind_host_metadata_changes_refused(tmp_path, options):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": "/operator-owned/config.yaml",
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": options,
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


def test_allowed_read_only_bind_option_has_no_host_mutation(tmp_path):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": "/operator-owned/config.yaml",
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize("target", ["/host-admin", "/etc", "/run/secrets/cloudflare-tunnel-token"])
def test_mcp_bind_requires_known_control_input_target(tmp_path, target):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": "/operator-owned/config.yaml",
            "target": target,
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


def test_expected_read_only_secret_mounts_are_not_refusal_only(tmp_path):
    doc = control("dev-e2e")
    doc["networks"]["cloudflare_egress"] = {}
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": "/operator-owned/secrets/ssh",
            "target": "/run/secrets/ssh",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
        {
            "type": "bind",
            "source": "/operator-owned/secrets/origin",
            "target": "/run/secrets/origin-bearer",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
    ]
    doc["services"]["cloudflared"] = reviewed_control_service(
        "cloudflared",
        networks=["origin_internal", "cloudflare_egress"],
        volumes=[
            {
                "type": "bind",
                "source": "/operator-owned/secrets/cloudflare",
                "target": "/run/secrets/cloudflare-tunnel-token",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
        ],
    )
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize(
    "mode,role",
    [
        ("dev-e2e", "ledger-init"),
        ("dev-e2e", "ledger"),
        ("dev-e2e", "mcp"),
        ("dev-e2e", "node01"),
        ("dev-e2e", "node02"),
        ("multi-host", "ledger-init"),
        ("multi-host", "ledger"),
        ("multi-host", "mcp"),
        ("multi-host", "ssh-target"),
    ],
)
def test_required_service_cannot_hide_behind_compose_profile(tmp_path, mode, role):
    doc = control(mode)
    if role == "ssh-target":
        target = host()
        target["services"]["ssh-target"]["profiles"] = ["disabled"]
        result = invoke(tmp_path, "multi-host", control_doc=doc, node01_doc=target)
    else:
        doc["services"][role]["profiles"] = ["disabled"]
        result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""
    assert "preflight refused:" in result.stderr


@pytest.mark.parametrize(
    "mode,role,field,value",
    [
        ("dev-e2e", "mcp", "user", "0:0"),
        ("dev-e2e", "ledger", "user", "0:0"),
        ("dev-e2e", "ledger-init", "user", "10001:10001"),
        ("multi-host", "mcp", "user", "0:0"),
        ("multi-host", "ssh-target", "user", "0:0"),
        ("dev-e2e", "node01", "user", "0:0"),
        ("dev-e2e", "node02", "group_add", ["0"]),
        ("dev-e2e", "mcp", "group_add", ["0"]),
        ("dev-e2e", "ledger", "group_add", ["0"]),
        ("multi-host", "ssh-target", "group_add", ["0"]),
        ("dev-e2e", "node01", "entrypoint", ["/bin/sh", "-c", "sleep infinity"]),
        ("multi-host", "ssh-target", "entrypoint", ["/bin/sh", "-c", "sleep infinity"]),
        ("dev-e2e", "mcp", "entrypoint", ["/bin/sh"]),
        ("dev-e2e", "mcp", "command", ["sh", "-c", "id"]),
        ("dev-e2e", "node01", "command", ["sh", "-c", "true"]),
        ("multi-host", "ssh-target", "command", ["/usr/sbin/sshd", "-D"]),
        ("dev-e2e", "mcp", "working_dir", "/tmp"),
    ],
)
def test_executable_and_identity_overrides_are_not_unchecked(
    tmp_path,
    mode,
    role,
    field,
    value,
):
    doc = control(mode)
    if role == "ssh-target":
        target = host()
        target["services"]["ssh-target"][field] = value
        result = invoke(tmp_path, mode, control_doc=doc, node02_doc=target)
    else:
        doc["services"][role][field] = value
        result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("profiles", ["disabled", [1], [""], None, {"disabled": True}])
def test_invalid_optional_service_profile_syntax_is_refused(tmp_path, profiles):
    doc = control("dev-e2e")
    doc["services"]["approvalctl"] = reviewed_control_service(
        "approvalctl",
        network_mode="none",
        profiles=profiles,
    )
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


def test_optional_reviewed_profiles_are_accepted_but_not_deployment_proof(tmp_path):
    doc = control("dev-e2e")
    doc["services"]["approvalctl"] = reviewed_control_service(
        "approvalctl",
        network_mode="none",
        profiles=["admin"],
    )
    doc["networks"]["cloudflare_egress"] = {}
    doc["services"]["cloudflared"] = reviewed_control_service(
        "cloudflared",
        networks=["origin_internal", "cloudflare_egress"],
        profiles=["cloudflare"],
    )
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize(
    "role,field,value",
    [
        ("ledger-init", "user", None),
        ("ledger-init", "entrypoint", ["ssh-over-mcp-server"]),
        ("ledger-init", "cap_add", ["SYS_ADMIN"]),
        ("ledger", "user", None),
        ("ledger", "entrypoint", None),
        ("ledger", "group_add", ["10003"]),
        ("mcp", "user", None),
        ("mcp", "entrypoint", None),
        ("mcp", "entrypoint", ["ssh-over-mcp-ledger"]),
    ],
)
def test_control_requires_exact_reviewed_uid_and_start_contract(tmp_path, role, field, value):
    doc = control("dev-e2e")
    doc["services"][role][field] = value
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "role,profiles",
    [
        ("mcp", ["debug"]),
        ("node01", ["node01"]),
        ("node02", [123]),
        ("ledger-init", "admin"),
        ("ledger", {"admin": True}),
        ("mcp", None),
    ],
)
def test_mode_a_mandatory_profiles_refuse_invalid_values(tmp_path, role, profiles):
    doc = control("dev-e2e")
    doc["services"][role]["profiles"] = profiles
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "field,value",
    [
        ("entrypoint", ["/bin/sh"]),
        ("command", ["sleep", "infinity"]),
        ("user", "10001:10001"),
        ("group_add", ["10001"]),
        ("profiles", ["disabled"]),
    ],
)
def test_mode_b_ssh_target_bootstrap_needs_separate_approval(tmp_path, field, value):
    h = host()
    h["services"]["ssh-target"][field] = value
    result = invoke(tmp_path, "multi-host", node01_doc=h)
    assert result.returncode != 0
    assert result.stdout == ""


def test_required_services_may_have_explicit_empty_profiles(tmp_path):
    doc = control("dev-e2e")
    for role in ("ledger-init", "ledger", "mcp", "node01", "node02"):
        doc["services"][role]["profiles"] = []
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_swapped_ledger_socket_environment_identity_is_refused(tmp_path, mode):
    doc = control(mode)
    for role in ("ledger-init", "ledger"):
        doc["services"][role]["environment"] = {
            "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": "/run/ssh-over-mcp-admin/ledger/ledger.sock",
            "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": "/run/ssh-over-mcp-exec/ledger/ledger.sock",
            "SSH_OVER_MCP_LEDGER_EXEC_PEER_UID": "10004",
            "SSH_OVER_MCP_LEDGER_EXEC_PEER_GID": "10005",
            "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID": "10001",
            "SSH_OVER_MCP_LEDGER_ADMIN_PEER_GID": "10003",
        }
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_arbitrary_mcp_healthcheck_shell_refused(tmp_path, mode):
    doc = control(mode)
    doc["services"]["mcp"]["healthcheck"] = {
        "test": ["CMD-SHELL", "id"],
        "interval": "1s",
    }
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize("role", ["mcp", "ledger", "ledger-init"])
def test_loader_override_environment_cannot_execute_unreviewed_code(tmp_path, role):
    doc = control("dev-e2e")
    doc["services"][role]["environment"] = {"LD_PRELOAD": "/tmp/custom.so"}
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize(
    "role,field,value",
    [
        ("mcp", "tmpfs", ["/proc:rw,exec,mode=1777"]),
        ("node01", "tmpfs", ["/etc/ssh/hostkeys:mode=0777"]),
        (
            "mcp",
            "logging",
            {"driver": "syslog", "options": {"syslog-address": "tcp://outside.invalid:514"}},
        ),
    ],
)
def test_unreviewed_auxiliary_exec_mount_and_log_controls_refused(
    tmp_path,
    role,
    field,
    value,
):
    doc = control("dev-e2e")
    doc["services"][role][field] = value
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_reviewed_mcp_readiness_healthcheck_stays_accepted(tmp_path, mode):
    doc = control(mode)
    doc["services"]["mcp"]["healthcheck"] = {
        "test": [
            "CMD",
            "python",
            "-c",
            "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/readyz',timeout=2).read()",
        ],
        "interval": "5s",
        "timeout": "3s",
        "retries": 12,
        "start_period": "2s",
    }
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize(
    "mode,role,key,wrong_value",
    [
        ("dev-e2e", "ledger", "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID", "10001"),
        ("multi-host", "ledger-init", "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_GID", "10005"),
        (
            "dev-e2e",
            "mcp",
            "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH",
            "/run/ssh-over-mcp-admin/ledger/ledger.sock",
        ),
        ("multi-host", "mcp", "SSH_OVER_MCP_PROFILE", "unreviewed-shell-profile"),
    ],
)
def test_security_relevant_environment_bindings_are_immutable(
    tmp_path,
    mode,
    role,
    key,
    wrong_value,
):
    doc = control(mode)
    doc["services"][role]["environment"][key] = wrong_value
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


def test_reviewed_control_uid_entrypoint_and_socket_pins_match_repo_compose_source():
    """Prevent our static contract drifting from the actual current control stack."""
    import yaml

    actual = yaml.safe_load((ROOT / "deploy/compose/compose.yaml").read_text())["services"]
    for role in ("ledger-init", "ledger", "mcp", "approvalctl", "cloudflared"):
        expected = reviewed_control_service(role)
        assert actual[role]["user"] == expected["user"]
        if "entrypoint" in expected:
            assert actual[role]["entrypoint"] == expected["entrypoint"]
        if "command" in expected:
            assert actual[role]["command"] == expected["command"]
        if "group_add" in expected:
            assert actual[role]["group_add"] == expected["group_add"]
        if "environment" in expected:
            for key, value in expected["environment"].items():
                if key == "SSH_OVER_MCP_PROFILE":
                    # The real operator supplies the MVP profile at render time.
                    assert actual[role]["environment"][key].startswith("${SSH_OVER_MCP_PROFILE:")
                    continue
                assert actual[role]["environment"][key] == value


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
@pytest.mark.parametrize("bind_option", [None, {}, {"create_host_path": True}])
def test_readonly_operator_bind_requires_explicit_no_host_creation(
    tmp_path,
    mode,
    bind_option,
):
    doc = control(mode)
    mount = {
        "type": "bind",
        "source": "/operator-owned/missing-config.yaml",
        "target": "/etc/ssh-over-mcp/config.yaml",
        "read_only": True,
    }
    if bind_option is not None:
        mount["bind"] = bind_option
    doc["services"]["mcp"]["volumes"] = [mount]
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


def test_cloudflared_bind_requires_explicit_no_host_creation(tmp_path):
    doc = control("dev-e2e")
    doc["networks"]["cloudflare_egress"] = {}
    doc["services"]["cloudflared"] = reviewed_control_service(
        "cloudflared",
        networks=["origin_internal", "cloudflare_egress"],
        volumes=[
            {
                "type": "bind",
                "source": "/operator-owned/cloudflare-token",
                "target": "/run/secrets/cloudflare-tunnel-token",
                "read_only": True,
            }
        ],
    )
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode != 0 and result.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
@pytest.mark.parametrize(
    "source",
    [
        "/run/docker/containerd",
        "/run/docker/containerd/containerd.sock",
        "/var/run/docker/containerd/containerd.sock",
        "/run/docker",
        "/var/run/docker",
        "/home/operator/.local/share/docker/volumes/som_ledger-data/_data",
        "/home/operator/.local/share/docker",
        "/home/operator/.local/share/containers/storage",
        "/home/operator/.local/share/containerd",
        "/home/operator/.local/share/podman",
        "/root/.local/share/docker/volumes/ledger-data/_data",
        "/home/operator",
    ],
)
def test_managed_runtime_paths_and_rootless_storage_refused(tmp_path, mode, source):
    doc = control(mode)
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/run/secrets/ssh",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "source",
    [
        "/home/operator/config.yaml",
        "/home/operator/app/credentials.yaml",
        "/srv/som/operator-owned/config.yaml",
    ],
)
def test_regular_non_sensitive_home_config_bind_not_blanket_denied(tmp_path, source):
    doc = control("dev-e2e")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, control_doc=doc)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False


@pytest.mark.parametrize(
    "source",
    [
        "/home/operator/.local",
        "/home/operator/.local/share",
        "/root/.local",
        "/srv/users/custom/.local/share/docker/volumes/admin/_data",
    ],
)
def test_rootless_storage_enclosing_paths_and_custom_home_refused(tmp_path, source):
    doc = control("multi-host")
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/etc/ssh-over-mcp/config.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, "multi-host", control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_rendered_compose_empty_ipam_defaults_accepted_in_both_modes(tmp_path, mode):
    """Compose 5.5 emits ipam: {} for regular bridge networks after config render."""
    doc = control(mode)
    for config in doc["networks"].values():
        config["ipam"] = {}
    if mode == "dev-e2e":
        result = invoke(tmp_path, mode, control_doc=doc)
    else:
        node = host()
        for config in node["networks"].values():
            config["ipam"] = {}
        result = invoke(tmp_path, mode, control_doc=doc, node01_doc=node, node02_doc=node)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["static_compose_shape_valid"] is True
    assert report["deployment_ready"] is False
    assert report["network_acl_verified"] is False


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
@pytest.mark.parametrize(
    "ipam",
    [
        None,
        [],
        {"config": [{"subnet": "10.0.0.0/8"}]},
        {"driver": "default"},
        {"options": {"unsafe": "value"}},
        {"config": []},
    ],
)
def test_rendered_compose_nonempty_or_malformed_ipam_is_refused(tmp_path, mode, ipam):
    doc = control(mode)
    doc["networks"]["origin_internal"]["ipam"] = ipam
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "preflight refused:" in result.stderr


def test_mode_b_target_rendered_custom_ipam_refused(tmp_path):
    node = host()
    node["networks"]["ssh_private"]["ipam"] = {"config": [{"subnet": "10.12.0.0/16"}]}
    result = invoke(tmp_path, "multi-host", node02_doc=node)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
@pytest.mark.parametrize(
    "source",
    [
        "/home",
        "/home/",
        "/root",
        "/root/",
        "/home/operator/",
        "/home/operator/.local/",
        "/root/.local/",
        "/home/operator/.local/share/",
    ],
)
def test_rootless_storage_ancestor_with_trailing_slash_cannot_escape_refusal(
    tmp_path,
    mode,
    source,
):
    doc = control(mode)
    doc["services"]["mcp"]["volumes"] = [
        {
            "type": "bind",
            "source": source,
            "target": "/run/secrets/ssh",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    result = invoke(tmp_path, mode, control_doc=doc)
    assert result.returncode != 0
    assert result.stdout == ""
