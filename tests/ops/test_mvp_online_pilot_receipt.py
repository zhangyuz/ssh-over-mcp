"""Small pure tests of signed-receipt input invariants; no Docker needed."""

import hashlib

import pytest

from ops.mvp.mode_a_online_pilot_receipt import IMAGE, make_receipt


def test_receipt_hash_binds_runnable_archive_and_both_image_ids(tmp_path):
    expected, actual = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    body = b"synthetic CI-only archive, not an image"
    archive = tmp_path / IMAGE
    archive.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    (tmp_path / "ONLINE_PILOT_IMAGE_SHA256SUMS").write_text(f"{digest}  {IMAGE}\n")
    lines = [
        "PR_SOURCE_SHA=" + "c" * 40,
        "TEST_MERGE_SHA=" + "d" * 40,
        f"ONLINE_PILOT_SOURCE_IMAGE_ID={expected}",
        f"ONLINE_PILOT_REMAPPED_IMAGE_ID={actual}",
        f"ONLINE_PILOT_ARCHIVE_SHA256={digest}",
        "ONLINE_PILOT_RELOAD_DEFAULT_SSHD_FS_PASSED=true",
        "ONLINE_PILOT_RELOAD_DUAL_MCP_LEDGER=true",
        "ONLINE_PILOT_REMAPPED_DUAL_MCP_LEDGER=true",
        "ONLINE_PILOT_TEST_ARCHIVE_ONLY=true",
        "PRODUCTION_RELEASE_AUTHORIZED=false",
    ]
    provenance = tmp_path / "PROVENANCE.txt"
    provenance.write_text("\n".join(lines) + "\n")
    result = make_receipt(tmp_path, expected, actual, 165536, 165536)
    assert result["source_archive_sha256"] == digest
    assert result["remapped_runtime_image_id"] == actual
    assert result["import_rewrote_image_id"] is True
    assert result["entrypoint"] == "/usr/sbin/sshd"
    assert result["command"] == ["-D", "-e"]
    assert result["remapped_default_start_and_typed_fs_passed"] is True
    assert result["remapped_default_start_two_node_mcp_ledger_passed"] is True
    assert result["production_signed_runtime_id"] is False
    assert result["production_deployed"] is False

    archive.write_bytes(b"tampered")
    with pytest.raises(AssertionError):
        make_receipt(tmp_path, expected, actual, 165536, 165536)
    archive.write_bytes(body)
    provenance.write_text("\n".join(lines[:-1] + ["PRODUCTION_RELEASE_AUTHORIZED=true"]) + "\n")
    with pytest.raises(AssertionError):
        make_receipt(tmp_path, expected, actual, 165536, 165536)
