"""Create a bounded, test-only provenance link to the post-userns image ID.

This records observed Docker import identity after the *actual* hosted two-node
MCP/Ledger test. It does not authorize or sign a production runtime image.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_ARCHIVE = 512 * 1024 * 1024
_ARCHIVE_NAME = "som342-openssh-fs.docker.tar.gz"
_HOLD = "/usr/local/libexec/ssh-over-mcp-image-hold"


def _receipt(proof: Path, expected: str, actual: str, uid: int, gid: int) -> dict:
    assert _ID.fullmatch(expected) and _ID.fullmatch(actual)
    assert 65536 <= uid < 2**31 and 65536 <= gid < 2**31
    manifest = (proof / "PROVENANCE.txt").read_text(encoding="ascii")
    fields: dict[str, str] = {}
    for name in ("PR_SOURCE_SHA", "TEST_MERGE_SHA", "FS_NATIVE_REVIEW_IMAGE_ID"):
        matches = [
            s.removeprefix(name + "=") for s in manifest.splitlines() if s.startswith(name + "=")
        ]
        assert len(matches) == 1, f"invalid evidence field: {name}"
        fields[name] = matches[0]
    assert _SHA.fullmatch(fields["PR_SOURCE_SHA"])
    assert _SHA.fullmatch(fields["TEST_MERGE_SHA"])
    assert fields["FS_NATIVE_REVIEW_IMAGE_ID"] == expected
    archive = proof / _ARCHIVE_NAME
    assert archive.is_file() and not archive.is_symlink()
    assert 0 < archive.stat().st_size <= _MAX_ARCHIVE
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    checksums = (proof / "OFFLINE_IMAGE_SHA256SUMS").read_text(encoding="ascii").splitlines()
    assert checksums == [f"{digest}  {_ARCHIVE_NAME}"], "archive manifest mismatch"
    return {
        "schema": "som342-userns-test-only-v1",
        "pr_source_sha": fields["PR_SOURCE_SHA"],
        "test_merge_sha": fields["TEST_MERGE_SHA"],
        "source_archive_sha256": digest,
        "source_image_id": expected,
        "remapped_runtime_image_id": actual,
        "import_rewrote_image_id": actual != expected,
        "remapped_host_root_uid": uid,
        "remapped_host_root_gid": gid,
        "entrypoint": _HOLD,
        "central_mcp_ledger_two_node_ci_passed": True,
        "production_signed_runtime_id": False,
        "production_deployed": False,
    }


def main() -> None:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert len(sys.argv) == 5
    expected, actual, uid, gid = sys.argv[1:]
    proof = Path("proof")
    receipt = _receipt(proof, expected, actual, int(uid), int(gid))
    output = proof / "REMAPPED_IMAGE_TEST_RECEIPT.json"
    assert not output.exists()
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("USERNS_IMAGE_ID_SOURCE_ARCHIVE_CHAIN_RECORDED_TEST_ONLY=true", flush=True)


if __name__ == "__main__":
    main()
