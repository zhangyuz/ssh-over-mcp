"""CI-only signed-receipt subject for independently imported runnable SSH image.

No image is signed or authorized for production by this receipt. Only
source/merge identity, tested archive hash and observed userns import ID.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

IMAGE = "som342-online-pilot-review.docker.tar.gz"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


def make_receipt(proof: Path, expected: str, actual: str, uid: int, gid: int) -> dict:
    assert _ID.fullmatch(expected) and _ID.fullmatch(actual)
    assert 65536 <= uid < 2**31 and 65536 <= gid < 2**31
    items = (proof / "PROVENANCE.txt").read_text(encoding="ascii").splitlines()

    def field(name: str) -> str:
        vals = [line[len(name) + 1 :] for line in items if line.startswith(name + "=")]
        assert len(vals) == 1, name
        return vals[0]

    source = field("PR_SOURCE_SHA")
    merge = field("TEST_MERGE_SHA")
    assert _SHA.fullmatch(source) and _SHA.fullmatch(merge)
    assert field("ONLINE_PILOT_SOURCE_IMAGE_ID") == expected
    assert field("ONLINE_PILOT_REMAPPED_IMAGE_ID") == actual
    assert field("ONLINE_PILOT_RELOAD_DEFAULT_SSHD_FS_PASSED") == "true"
    archive = proof / IMAGE
    assert archive.is_file() and not archive.is_symlink()
    assert 0 < archive.stat().st_size < 512 * 1024 * 1024
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    checksums = (proof / "ONLINE_PILOT_IMAGE_SHA256SUMS").read_text(encoding="ascii").splitlines()
    assert checksums == [f"{digest}  {IMAGE}"]
    assert field("ONLINE_PILOT_ARCHIVE_SHA256") == digest
    assert field("ONLINE_PILOT_TEST_ARCHIVE_ONLY") == "true"
    assert field("PRODUCTION_RELEASE_AUTHORIZED") == "false"
    return {
        "schema": "som342-online-pilot-remapped-ci-only-v1",
        "pr_source_sha": source,
        "test_merge_sha": merge,
        "source_archive_sha256": digest,
        "source_image_id": expected,
        "remapped_runtime_image_id": actual,
        "import_rewrote_image_id": actual != expected,
        "remapped_host_root_uid": uid,
        "remapped_host_root_gid": gid,
        "entrypoint": "/usr/sbin/sshd",
        "command": ["-D", "-e"],
        "remapped_default_start_and_typed_fs_passed": True,
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
    receipt = make_receipt(proof, expected, actual, int(uid), int(gid))
    output = proof / "ONLINE_PILOT_REMAPPED_TEST_RECEIPT.json"
    assert not output.exists()
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("ONLINE_PILOT_REMAPPED_IMPORT_RECEIPT_CI_ONLY_PASS", flush=True)


if __name__ == "__main__":
    main()
