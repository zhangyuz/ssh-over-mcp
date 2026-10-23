from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "ops" / "mvp" / "topology_preflight.py"


def _pin(label: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(label.encode()).digest()).decode().rstrip(
        "="
    )


IMAGE = "registry.example.test/ssh@sha256:" + "a" * 64


def topology(mode: str = "dev-e2e") -> dict:
    return {
        "schema": "som-mvp-compose-topology-v1",
        "mode": mode,
        "control": {"engine": "control01" if mode == "multi-host" else "lab01", "image": IMAGE},
        "targets": [
            {
                "alias": alias,
                "engine": host if mode == "multi-host" else "lab01",
                "image": IMAGE,
                "host_key_pin": _pin(alias),
            }
            for alias, host in (("node01", "ssh-host01"), ("node02", "ssh-host02"))
        ],
    }


def invoke(tmp_path: Path, data: object, *, raw: str | None = None) -> subprocess.CompletedProcess:
    p = tmp_path / "deployment.json"
    p.write_text(json.dumps(data) if raw is None else raw, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(CLI), "--topology-json", str(p)],
        check=False,
        text=True,
        capture_output=True,
        timeout=10,
    )


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_operator_can_validate_two_distinct_ssh_targets_without_claiming_runtime(mode, tmp_path):
    result = invoke(tmp_path, topology(mode))
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report == {
        "schema": "som-mvp-compose-topology-preflight-v1",
        "mode": mode,
        "target_count": 2,
        "target_aliases": ["node01", "node02"],
        "static_structure_valid": True,
        "deployment_ready": False,
        "network_verified": False,
        "runtime_verified": False,
        "trust_verified": False,
        "live_e2e_verified": False,
    }


@pytest.mark.parametrize(
    "change",
    [
        lambda x: x["targets"][1].update(alias="node01"),
        lambda x: x["targets"].pop(),
        lambda x: x["targets"][0].update(image="ssh-over-mcp:latest"),
        lambda x: x["targets"][0].update(host_key_pin="no-host-key"),
        lambda x: x["targets"][1].update(engine="ssh-host01"),
        lambda x: x["control"].update(engine="ssh-host01"),
        lambda x: x.update(private_key="TOP_SECRET_7Z"),
    ],
)
def test_multihost_wrong_trust_shape_or_engine_refused_without_reflection(tmp_path, change):
    data = topology("multi-host")
    change(data)
    result = invoke(tmp_path, data)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "TOP_SECRET_7Z" not in result.stderr
    assert "deployment.json" not in result.stderr
    assert "refused" in result.stderr


def test_single_engine_mode_refuses_remote_target_engine(tmp_path):
    data = topology()
    data["targets"][1]["engine"] = "remote02"
    result = invoke(tmp_path, data)
    assert result.returncode == 2
    assert result.stdout == ""


def test_duplicate_object_fields_nan_and_trailing_payload_refused(tmp_path):
    for raw in ('{"schema":"a","schema":"b"}', '{"x":NaN}', "{}garbage"):
        result = invoke(tmp_path, {}, raw=raw)
        assert result.returncode == 2
        assert result.stdout == ""


def test_bounded_input_does_not_echo_untrusted_bytes(tmp_path):
    result = invoke(tmp_path, {}, raw='"SECRET_SENTINEL"' + "!" * 20000)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "SECRET_SENTINEL" not in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no fifo on this platform")
def test_fifo_is_rejected_without_blocking(tmp_path):
    path = tmp_path / "pipe.json"
    os.mkfifo(path)
    result = subprocess.run(
        [sys.executable, str(CLI), "--topology-json", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert result.returncode == 2
    assert result.stdout == ""


def test_symlink_refused_without_reading_target(tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text("TOP_SECRET_VALUE")
    link = tmp_path / "link.json"
    link.symlink_to(secret)
    result = subprocess.run(
        [sys.executable, str(CLI), "--topology-json", str(link)],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "TOP_SECRET_VALUE" not in result.stderr


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_unknown_schema_and_unknown_extra_control_key_fail_closed(tmp_path, mode):
    data = topology(mode)
    data["schema"] = "unexpected-new-schema"
    assert invoke(tmp_path, data).returncode == 2
    data = topology(mode)
    data["control"]["private_key"] = "DO_NOT_REFLECT_ME"
    result = invoke(tmp_path, data)
    assert result.returncode == 2
    assert "DO_NOT_REFLECT_ME" not in result.stderr


def test_duplicate_host_key_pins_are_rejected(tmp_path):
    data = topology("multi-host")
    data["targets"][1]["host_key_pin"] = data["targets"][0]["host_key_pin"]
    assert invoke(tmp_path, data).returncode == 2


def test_fake_engine_labels_are_not_treated_as_identity_or_network_attestation(tmp_path):
    data = topology("multi-host")
    data["control"]["engine"] = "invented-engine-id"
    report = json.loads(invoke(tmp_path, data).stdout)
    assert report["static_structure_valid"] is True
    assert report["deployment_ready"] is False
    assert report["runtime_verified"] is False
    assert report["network_verified"] is False


@pytest.mark.parametrize(
    "image_name",
    [
        "repo///sub",
        "repo/../target",
        "repo/.",
        "repo/-test",
        "registry.-bad.test/target",
        "repo/a___b",
        "repo:a",
        "repo/target:latest",
        "localhost:0/target",
        "localhost:65536/target",
        "[2001:db8:::1]:5000/target",
        "repo/" + "x" * 255,
    ],
)
def test_malformed_oci_repository_name_refused(tmp_path, image_name):
    data = topology("multi-host")
    data["control"]["image"] = image_name + "@sha256:" + "a" * 64
    result = invoke(tmp_path, data)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "IMAGE_DIGEST_REQUIRED" in result.stderr


@pytest.mark.parametrize(
    "image_name",
    [
        "registry.example.test:5000/team/app",
        "localhost:5000/my_image",
        "[2001:db8::1]:5000/team/app",
        "ghcr.io/org/my__image",
    ],
)
def test_valid_oci_registry_references_with_digest_accepted(tmp_path, image_name):
    data = topology("multi-host")
    data["control"]["image"] = image_name + "@sha256:" + "a" * 64
    result = invoke(tmp_path, data)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deployment_ready"] is False
