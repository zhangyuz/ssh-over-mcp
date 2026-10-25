"""Read-only Mode A VM plan validation tests; never authorize boot."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ops.mvp.mode_a_vm_offline_preflight import Refused, check_document, main, read_yaml

_IMAGE = (
    "https://cloud-images.ubuntu.com/releases/resolute/release/"
    "ubuntu-26.04-server-cloudimg-amd64.img"
)
_DIGEST = "sha256:5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5"


def candidate() -> dict:
    return {
        "minimumLimaVersion": "2.0.0",
        "images": [{"location": _IMAGE, "arch": "x86_64", "variant": "server", "digest": _DIGEST}],
        "param": {"internal_netplanOptional": "true"},
        "mounts": None,
        "cpus": 2,
        "memory": "4GiB",
        "vmType": "vz",
        "arch": "x86_64",
        "containerd": {"user": False, "system": False},
        "disk": "16GiB",
        "plain": True,
    }


def test_candidate_is_never_boot_authorized():
    assert check_document(candidate()) == {
        "schema": "som-mode-a-vm-offline-preflight-v1",
        "static_vm_shape_valid": True,
        "host_lan_isolation_verified": False,
        "docker_runtime_verified": False,
        "vm_execution_authorized": False,
        "deployment_ready": False,
        "network_gate": "UNVERIFIED_DEFAULT_USERMODE_EGRESS",
    }


@pytest.mark.parametrize(
    "name,value",
    [
        ("mounts", [{"location": "~", "writable": False}]),
        ("networks", [{"vzNAT": True}]),
        ("portForwards", [{"guestPort": 8000, "hostPort": 8000, "static": True}]),
        ("provision", [{"mode": "system", "script": "exit 0"}]),
        ("propagateProxyEnv", True),
        ("ssh", {"localPort": 22}),
        ("plain", False),
        ("plain", 1),
        ("vmType", "qemu"),
        ("cpus", 32),
        ("memory", "64GiB"),
        ("disk", "1TiB"),
        ("containerd", {"system": True, "user": False}),
    ],
)
def test_widened_vm_config_refused(name, value):
    item = candidate()
    item[name] = value
    with pytest.raises(Refused):
        check_document(item)


@pytest.mark.parametrize(
    "field,value",
    [
        ("digest", "sha256:" + "a" * 64),
        ("location", "https://example.invalid/base.img"),
    ],
)
def test_untrusted_image_source_refused(field, value):
    item = candidate()
    item["images"][0][field] = value
    with pytest.raises(Refused):
        check_document(item)


def test_read_once_refuses_duplicates_symlinks_and_excess(tmp_path):
    p = tmp_path / "vm.yaml"
    p.write_text("cpus: 2\ncpus: 16\n")
    with pytest.raises(Refused):
        read_yaml(p)
    p.write_text(yaml.safe_dump(candidate()))
    alias = tmp_path / "alias.yaml"
    alias.symlink_to(p)
    with pytest.raises(Refused):
        read_yaml(alias)
    p.write_text("x" * 16385)
    with pytest.raises(Refused):
        read_yaml(p)


def test_cli_static_success_and_non_leaking_refusal(tmp_path, capsys):
    p = tmp_path / "vm.yaml"
    p.write_text(yaml.safe_dump(candidate()))
    assert main(["--config", str(p)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["vm_execution_authorized"] is False
    assert output["host_lan_isolation_verified"] is False
    p.write_text(yaml.safe_dump({**candidate(), "networks": [{"vzNAT": True}]}))
    assert main(["--config", str(p)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(p) not in captured.err


def test_vm_operator_runbook_does_not_instruct_start():
    p = Path(__file__).resolve().parents[2] / "docs/runbooks/mvp-mode-a-vm-offline-gate.md"
    s = p.read_text()
    assert "limactl start" not in s
    assert "host_lan_isolation_verified" in s
    assert "2.2" in s


def test_containerd_boolean_fields_must_not_accept_integer_zero():
    item = candidate()
    item["containerd"] = {"user": 0, "system": 0}
    with pytest.raises(Refused):
        check_document(item)
