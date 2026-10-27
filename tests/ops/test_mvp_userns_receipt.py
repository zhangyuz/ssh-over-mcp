"""Offline-only checks for CI's signed test userns image-identity mapping."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ops/mvp/mode_a_userns_image_receipt.py"
EXPECTED = "sha256:" + "a" * 64
IMPORTED = "sha256:" + "b" * 64


def _invoke(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), EXPECTED, IMPORTED, "100000", "100000"],
        cwd=tmp_path,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_EVENT_NAME": "pull_request",
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_identity_receipt_binds_archive_and_exact_import_and_remains_test_only(tmp_path):
    proof = tmp_path / "proof"
    proof.mkdir()
    archive = proof / "som342-openssh-fs.docker.tar.gz"
    archive.write_bytes(b"isolated-test-only-archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (proof / "OFFLINE_IMAGE_SHA256SUMS").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    (proof / "PROVENANCE.txt").write_text(
        "PR_SOURCE_SHA="
        + "c" * 40
        + "\n"
        + "TEST_MERGE_SHA="
        + "d" * 40
        + "\n"
        + f"FS_NATIVE_REVIEW_IMAGE_ID={EXPECTED}\n",
        encoding="ascii",
    )
    result = _invoke(tmp_path)
    assert result.returncode == 0, result.stderr
    receipt = json.loads((proof / "REMAPPED_IMAGE_TEST_RECEIPT.json").read_text())
    assert receipt["source_archive_sha256"] == digest
    assert receipt["source_image_id"] == EXPECTED
    assert receipt["remapped_runtime_image_id"] == IMPORTED
    assert receipt["import_rewrote_image_id"] is True
    assert receipt["remapped_host_root_uid"] == 100000
    assert receipt["central_mcp_ledger_two_node_ci_passed"] is True
    assert receipt["entrypoint"].endswith("ssh-over-mcp-image-hold")
    assert receipt["production_signed_runtime_id"] is False
    assert receipt["production_deployed"] is False

    # Untrusted archive bytes cannot keep a valid linked receipt.
    (proof / "REMAPPED_IMAGE_TEST_RECEIPT.json").unlink()
    archive.write_bytes(b"changed-archive")
    bad = _invoke(tmp_path)
    assert bad.returncode != 0
    assert not (proof / "REMAPPED_IMAGE_TEST_RECEIPT.json").exists()


def test_ci_workflow_attests_both_archive_and_post_remap_identity():
    import yaml

    job = yaml.safe_load((ROOT / ".github/workflows/mvp-342-oci-source-build.yml").read_text())[
        "jobs"
    ]["build-source"]
    steps = {x.get("id"): x for x in job["steps"] if x.get("id")}
    assert steps["attest_remap_receipt"]["with"]["subject-path"] == (
        "proof/REMAPPED_IMAGE_TEST_RECEIPT.json"
    )
    assert steps["attest_archive"]["with"]["subject-path"].endswith(".tar.gz")
    assert "steps.attest_remap_receipt.outcome == 'success'" in job["steps"][-1]["if"]
    shell = (ROOT / "ops/mvp/mode_a_hosted_userns_verify.sh").read_text()
    assert "python3 ops/mvp/mode_a_hosted_oci_fs_smoke.py" in shell
    assert "python3 ops/mvp/mode_a_userns_image_receipt.py" in shell
