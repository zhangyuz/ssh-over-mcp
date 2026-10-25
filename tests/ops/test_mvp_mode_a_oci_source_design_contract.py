"""Offline source provenance and key-design guardrails (not a deploy test)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/superpowers/specs/2026-10-24-mode-a-ssh-source-and-offline-transfer.md"
PROPOSAL = ROOT / "deploy/ssh-target/Dockerfile.proposed"
OVERLAY = ROOT / "deploy/compose/compose.dev-ssh.yaml"
BASE = ROOT / "deploy/compose/compose.yaml"
INDEX_DIGEST = "sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944"
PLATFORM_DIGEST = "sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a"


def test_candidate_base_is_pinned_but_project_image_unbuildable():
    dockerfile = PROPOSAL.read_text()
    instructions = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert instructions[0] == (
        "FROM --platform=linux/amd64 docker.io/library/ubuntu@" + PLATFORM_DIGEST
    )
    assert len(instructions) == 2
    assert instructions[1].startswith("RUN ")
    assert "exit 78" in instructions[1]
    assert "Dockerfile.proposed" not in OVERLAY.read_text()
    assert "Dockerfile.proposed" not in BASE.read_text()


def test_offline_source_evidence_does_not_claim_any_signature_or_blob():
    spec = SOURCE.read_text()
    assert INDEX_DIGEST in spec
    assert PLATFORM_DIGEST in spec
    assert "d5b48b3b44d98cf4a7f5fcf570c5a2acfdf7b723" in spec
    for phrase in (
        "publisher_signature_verified=false",
        "image_use_authorized=false",
        "deployment_ready=false",
        "no blob/config/layer content",
        "InRelease",
        "SHA256",
        "SPDX/CycloneDX",
        "offline",
        "revocation",
        "separate B/C/runtime authorization",
    ):
        assert phrase.lower() in spec.lower()


def test_ssh_key_lifecycle_is_independent_across_nodes():
    spec = SOURCE.read_text()
    for word in (
        "node01",
        "node02",
        "ED25519",
        "0600",
        "0700",
        "known-hosts",
        "Strict",
        "host key",
        "rotation",
        "revoke",
        "destroy",
        "no key bytes",
        "stopped",
        "unsigned",
    ):
        assert word.lower() in spec.lower()
