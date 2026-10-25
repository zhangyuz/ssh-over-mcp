"""C5 review-only package candidate snapshot, never an install lock."""

import json
from pathlib import Path

DATA = (
    Path(__file__).resolve().parents[2]
    / "deploy/ssh-target/ubuntu-2604-amd64-metadata-candidates.json"
)

FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"


def test_candidate_snapshot_has_three_independently_signed_pockets():
    obj = json.loads(DATA.read_text())
    assert obj["schema"] == "som-ubuntu-2604-c5-candidate-v1"
    assert obj["platform"] == "linux/amd64"
    assert obj["pinned_archive_fingerprint"] == FINGERPRINT
    assert set(obj["pockets"]) == {"resolute", "resolute-updates", "resolute-security"}
    assert obj["package_archive_bytes_verified"] is False
    assert obj["dependency_closure_verified"] is False
    assert obj["build_or_install_authorized"] is False
    for pocket, value in obj["pockets"].items():
        assert value["pocket"] == pocket
        assert value["signed_release_verified"] is True
        assert value["index_hash_verified"] is True
        assert value["trusted_key_fingerprint"] == FINGERPRINT
        assert len(value["inrelease_sha256"]) == 64
        assert len(value["packages_xz_sha256"]) == 64
        for pkg in value["packages"].values():
            assert len(pkg["deb_sha256"]) == 64
            assert pkg["filename"].startswith("pool/main/")


def test_package_version_recommendations_are_not_fabricated_or_build_authority():
    obj = json.loads(DATA.read_text())
    candidates = obj["candidate_selection"]
    assert set(candidates) == {
        "openssh-server",
        "openssh-client",
        "sudo",
        "python3",
        "python3-minimal",
        "ca-certificates",
        "libc6",
        "libssl3t64",
        "libpam0g",
        "openssl",
    }
    assert candidates["openssh-server"]["version"] == "1:10.2p1-2ubuntu3.8"
    assert candidates["sudo"]["version"] == "1.9.17p2-1ubuntu3.2"
    assert candidates["python3"]["version"] == "3.14.3-0ubuntu2"
    assert candidates["python3"]["pocket"] == "resolute"
    for name, pkg in candidates.items():
        assert pkg == {
            "pocket": pkg["pocket"],
            **obj["pockets"][pkg["pocket"]]["packages"][name],
        }
