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


def control(mode):
    networks = {"origin_internal": {"internal": True}}
    if mode == "dev-e2e":
        networks.update({"node01_ssh": {"internal": True}, "node02_ssh": {"internal": True}})
        mcp_nets = ["origin_internal", "node01_ssh", "node02_ssh"]
    else:
        networks["private_ssh_egress"] = {}
        mcp_nets = ["origin_internal", "private_ssh_egress"]
    services = {
        "ledger-init": service(network_mode="none", cap_add=["CHOWN", "DAC_OVERRIDE"]),
        "ledger": service(network_mode="none"),
        "mcp": service(networks=mcp_nets),
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
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
        )
    elif defect == "cgroup_bind":
        services["node01"]["volumes"].append(
            {"type": "bind", "source": "/sys/fs/cgroup", "target": "/sys/fs/cgroup"}
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
            "target": "/etc/som/config.yaml",
            "read_only": True,
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
    doc["services"]["cloudflared"] = service(networks=["origin_internal", "node01_ssh"])
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
        {"type": "bind", "source": source, "target": "/etc/som/config.yaml", "read_only": True}
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
        {"type": "bind", "source": source, "target": "/host-view", "read_only": True}
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
        {"type": "bind", "source": source, "target": "/host-view", "read_only": True}
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
