"""Operator-facing cross-artifact declaration consistency, never host attestation."""

import copy
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "ops/mvp/bundle_preflight.py"
# Reuse independently tested accepted fixture shapes, not their validation code.
COMPOSE = runpy.run_path(str(ROOT / "tests/ops/test_mvp_compose_config_preflight.py"))
TOPOLOGY = runpy.run_path(str(ROOT / "tests/ops/test_mvp_topology_preflight.py"))
CONTROL_IMAGE = "registry.example.test/ctrl@sha256:" + "a" * 64
TARGET_IMAGES = {
    "node01": "registry.example.test/ssh@sha256:" + "b" * 64,
    "node02": "registry.example.test/ssh@sha256:" + "c" * 64,
}


def bundle(mode="dev-e2e"):
    manifest = copy.deepcopy(TOPOLOGY["topology"](mode))
    manifest["control"]["image"] = CONTROL_IMAGE
    for node in manifest["targets"]:
        node["image"] = TARGET_IMAGES[node["alias"]]
    control = COMPOSE["control"](mode)
    for role in ("ledger-init", "ledger", "mcp"):
        control["services"][role]["image"] = CONTROL_IMAGE
    hosts = {}
    if mode == "dev-e2e":
        for alias, image in TARGET_IMAGES.items():
            control["services"][alias]["image"] = image
    else:
        for alias, image in TARGET_IMAGES.items():
            target = COMPOSE["host"]()
            target["services"]["ssh-target"]["image"] = image
            hosts[alias] = target
    return manifest, control, hosts


def invoke(tmp_path, mode="dev-e2e", *, manifest=None, control=None, hosts=None, files=None):
    native_manifest, native_control, native_hosts = bundle(mode)
    manifest = native_manifest if manifest is None else manifest
    control = native_control if control is None else control
    hosts = native_hosts if hosts is None else hosts
    files = files or {}
    paths = {}
    for key, data in (("topology", manifest), ("control", control), *hosts.items()):
        p = tmp_path / (key + ".json")
        p.write_text(json.dumps(data))
        paths[key] = p
    paths.update(files)
    args = [
        sys.executable,
        str(CLI),
        "--topology-json",
        str(paths["topology"]),
        "--control-json",
        str(paths["control"]),
    ]
    for alias in ("node01", "node02"):
        if alias in paths:
            args.extend(["--" + alias + "-json", str(paths[alias])])
    return subprocess.run(args, capture_output=True, text=True, check=False, timeout=8)


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_consistent_both_modes_reports_static_only(mode, tmp_path):
    res = invoke(tmp_path, mode)
    assert res.returncode == 0, res.stderr
    assert res.stderr == ""
    assert json.loads(res.stdout) == {
        "schema": "som-mvp-compose-bundle-preflight-v1",
        "mode": mode,
        "target_count": 2,
        "static_artifacts_consistent": True,
        "topology_shape_valid": True,
        "compose_shape_valid": True,
        "image_declarations_match": True,
        "deployment_ready": False,
        "image_trust_verified": False,
        "host_identity_verified": False,
        "network_acl_verified": False,
        "runtime_verified": False,
        "live_e2e_verified": False,
    }


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
@pytest.mark.parametrize("role", ["ledger-init", "ledger", "mcp"])
def test_control_role_digest_mismatch_refused(mode, role, tmp_path):
    manifest, control, hosts = bundle(mode)
    control["services"][role]["image"] = TARGET_IMAGES["node01"]
    res = invoke(tmp_path, mode, manifest=manifest, control=control, hosts=hosts)
    assert res.returncode != 0 and res.stdout == ""
    assert "IMAGE_DECLARATION_MISMATCH" in res.stderr
    assert TARGET_IMAGES["node01"] not in res.stderr


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
@pytest.mark.parametrize("alias", ["node01", "node02"])
def test_ssh_target_digest_mismatch_refused(mode, alias, tmp_path):
    manifest, control, hosts = bundle(mode)
    if mode == "dev-e2e":
        control["services"][alias]["image"] = CONTROL_IMAGE
    else:
        hosts[alias]["services"]["ssh-target"]["image"] = CONTROL_IMAGE
    res = invoke(tmp_path, mode, manifest=manifest, control=control, hosts=hosts)
    assert res.returncode != 0 and "IMAGE_DECLARATION_MISMATCH" in res.stderr
    assert res.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_swapped_distinct_ssh_images_refused(mode, tmp_path):
    manifest, control, hosts = bundle(mode)
    if mode == "dev-e2e":
        control["services"]["node01"]["image"], control["services"]["node02"]["image"] = (
            control["services"]["node02"]["image"],
            control["services"]["node01"]["image"],
        )
    else:
        hosts["node01"], hosts["node02"] = hosts["node02"], hosts["node01"]
    res = invoke(tmp_path, mode, manifest=manifest, control=control, hosts=hosts)
    assert res.returncode == 2 and res.stdout == ""


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_wrong_topology_pin_or_engine_is_not_reinterpreted_as_trust(mode, tmp_path):
    manifest, control, hosts = bundle(mode)
    manifest["targets"][0]["host_key_pin"] = "untrusted-key"
    res = invoke(tmp_path, mode, manifest=manifest, control=control, hosts=hosts)
    assert res.returncode == 2 and res.stdout == ""
    assert "HOST_KEY_PIN_REQUIRED" in res.stderr


@pytest.mark.parametrize("mode", ["dev-e2e", "multi-host"])
def test_original_compose_hardening_remains_authoritative(mode, tmp_path):
    manifest, control, hosts = bundle(mode)
    control["services"]["mcp"]["user"] = "0:0"
    res = invoke(tmp_path, mode, manifest=manifest, control=control, hosts=hosts)
    assert res.returncode == 2 and res.stdout == ""
    assert "UNREVIEWED_SERVICE_IDENTITY" in res.stderr


def test_mode_a_refuses_mode_b_extra_files(tmp_path):
    path = tmp_path / "extra.json"
    path.write_text(json.dumps(COMPOSE["host"]()))
    res = invoke(tmp_path, "dev-e2e", files={"node01": path})
    assert res.returncode == 2 and res.stdout == ""


@pytest.mark.parametrize("which", ["node01", "node02"])
def test_mode_b_refuses_missing_host_document(tmp_path, which):
    _, _, hosts = bundle("multi-host")
    hosts.pop(which)
    res = invoke(tmp_path, "multi-host", hosts=hosts)
    assert res.returncode == 2 and res.stdout == ""


@pytest.mark.parametrize(
    "pair", [("topology", "control"), ("control", "node01"), ("node01", "node02")]
)
def test_mode_b_cannot_reuse_same_path_as_distinct_project_input(tmp_path, pair):
    _, control, _ = bundle("multi-host")
    res = invoke(tmp_path, "multi-host")
    assert res.returncode == 0, res.stderr
    base = tmp_path / (pair[0] + ".json")
    # The pair's second input is replaced in CLI with the first path, not content.
    files = {pair[1]: base}
    res = invoke(tmp_path, "multi-host", control=control, files=files)
    assert res.returncode == 2 and res.stdout == ""


def test_rejects_duplicate_json_keys_and_does_not_echo_secrets(tmp_path):
    topology, control, hosts = bundle("multi-host")
    res = invoke(tmp_path, "multi-host", manifest=topology, control=control, hosts=hosts)
    assert res.returncode == 0, res.stderr
    p = tmp_path / "malformed-topology.json"
    p.write_text('{"schema":"som-mvp-compose-topology-v1", "schema":"SECRET-DENY"}')
    res = invoke(tmp_path, "multi-host", files={"topology": p})
    assert res.returncode == 2 and res.stdout == ""
    assert "SECRET-DENY" not in res.stderr


def test_symlinked_input_refused_without_reading_secret(tmp_path):
    secret = tmp_path / "SECRET.txt"
    secret.write_text("TOP_SECRET_SENTINEL")
    link = tmp_path / "hidden.json"
    link.symlink_to(secret)
    res = invoke(tmp_path, "dev-e2e", files={"topology": link})
    assert res.returncode == 2 and res.stdout == ""
    assert "TOP_SECRET_SENTINEL" not in res.stderr


def test_large_input_refused_without_reflection(tmp_path):
    extra = tmp_path / "large.json"
    extra.write_text('"TOP_SECRET_SENTINEL"' + "a" * 20000)
    res = invoke(tmp_path, "dev-e2e", files={"control": extra})
    assert res.returncode == 2 and res.stdout == ""
    assert "TOP_SECRET_SENTINEL" not in res.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO not available")
def test_fifo_is_refused_without_waiting(tmp_path):
    pipe = tmp_path / "request.pipe"
    os.mkfifo(pipe)
    res = invoke(tmp_path, "dev-e2e", files={"control": pipe})
    assert res.returncode == 2 and res.stdout == ""


def test_no_unreviewed_optional_control_service_image_mismatch(tmp_path):
    manifest, control, hosts = bundle("dev-e2e")
    control["services"]["approvalctl"] = COMPOSE["reviewed_control_service"](
        "approvalctl", network_mode="none"
    )
    control["services"]["approvalctl"]["image"] = TARGET_IMAGES["node02"]
    res = invoke(tmp_path, "dev-e2e", manifest=manifest, control=control, hosts=hosts)
    assert res.returncode == 2 and res.stdout == ""


def test_mode_b_same_digest_for_both_targets_is_not_proof_of_distinct_engines(tmp_path):
    manifest, control, hosts = bundle("multi-host")
    manifest["targets"][1]["image"] = TARGET_IMAGES["node01"]
    hosts["node02"]["services"]["ssh-target"]["image"] = TARGET_IMAGES["node01"]
    res = invoke(tmp_path, "multi-host", manifest=manifest, control=control, hosts=hosts)
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout)["host_identity_verified"] is False


@pytest.mark.parametrize("alias", ["node01", "node02"])
def test_mode_a_supplied_null_extra_document_is_not_missing_input(tmp_path, alias):
    path = tmp_path / "explicit-null.json"
    path.write_text("null")
    res = invoke(tmp_path, "dev-e2e", files={alias: path})
    assert res.returncode == 2 and res.stdout == ""
    assert "INVALID_MODE_FILES" in res.stderr


@pytest.mark.parametrize("alias", ["node01", "node02"])
def test_mode_b_null_target_document_is_invalid_shape_not_missing(tmp_path, alias):
    path = tmp_path / "explicit-null.json"
    path.write_text("null")
    res = invoke(tmp_path, "multi-host", files={alias: path})
    assert res.returncode == 2 and res.stdout == ""
    assert "preflight refused:" in res.stderr
