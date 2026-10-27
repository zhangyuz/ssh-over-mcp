"""Reviewable, non-admitted SSH image source contract.

Static and tamper tests. These do NOT constitute image provenance, A01–A03
or approval of any OCI capabilities.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deploy/ssh-target"
CANDIDATE = SOURCE / "Dockerfile.review-candidate"
HOLD = SOURCE / "entrypoint.review-hold"
SUDOERS = SOURCE / "sudoers.review-candidate"
CONTRACT = SOURCE / "image-build-candidate.md"
PROPOSED = SOURCE / "Dockerfile.proposed"
COMPOSE = ROOT / "deploy/compose/compose.dev-ssh.yaml"

PINNED_BASE = (
    "docker.io/library/ubuntu@sha256:"
    "42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a"
)


def _verify(text: str, hold: str, sudoers: str) -> None:
    assert text.count("FROM ") == 1
    assert f"FROM --platform=linux/amd64 {PINNED_BASE}" in text
    assert "apt-get update" in text
    assert "apt-get" in text and "--no-install-recommends" in text
    assert "openssh-server=" in text and "python3-venv=" in text
    assert "requirements/runtime.lock" in text and "--require-hashes" in text
    assert "--no-index" in text and "--only-binary=:all:" in text
    assert "sha256sum" in text and "dpkg-query" in text
    assert "cp -a /var/lib/apt/lists/*_InRelease" in text
    assert "cp -a /var/lib/apt/lists/*_Packages*" in text
    assert "signed-apt-lists-sha256.txt" in text
    assert "ubuntu-archive-keyring.gpg" in text
    candidates = json.loads((SOURCE / "ubuntu-2604-amd64-metadata-candidates.json").read_text())
    for name in ("openssh-server", "sudo", "python3", "ca-certificates"):
        pin = f"{name}={candidates['candidate_selection'][name]['version']}"
        assert text.count(pin) == 2
    # The candidate venv package must fail closed if the matching apt version
    # is no longer present; unlike the four pins above this is not C5-verified.
    assert text.count("python3-venv=3.14.3-0ubuntu2") == 2
    assert "COPY deploy/ssh-target/sshd_config.review-candidate" in text
    assert "COPY deploy/ssh-target/host-policy.review-candidate.yaml" in text
    assert "chown 2202:3202 /srv/data" in text
    assert "chmod 0700 /srv/data" in text
    assert "COPY deploy/ssh-target/sudoers.review-candidate" in text
    assert "COPY deploy/ssh-target/entrypoint.review-hold" in text
    assert "COPY ops/mvp/ssh-over-mcp-oci-launcher.py" in text
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in text
    assert "COPY src" in text
    assert "ssh-keygen" not in text and "COPY authorized_keys" not in text
    assert "privileged: true" not in text and "docker.sock" not in text
    assert "chmod 0440 /etc/sudoers.d/som-e2e" in text
    assert "exec /usr/sbin/sshd" not in text
    assert "exit 78" in hold and "sshd" not in hold
    assert sudoers.strip() == (
        "Defaults:ssh-over-mcp-e2e-host !requiretty\n"
        'Defaults:ssh-over-mcp-e2e-host env_keep += "SSH_ORIGINAL_COMMAND"\n'
        "ssh-over-mcp-e2e-host ALL=(root) NOPASSWD: "
        "/usr/bin/python3 -I -S "
        "/usr/local/libexec/ssh-over-mcp-oci-launcher.py"
    )


def test_review_image_candidate_records_hashed_inputs_and_stays_non_admitted() -> None:
    _verify(CANDIDATE.read_text(), HOLD.read_text(), SUDOERS.read_text())
    assert "exit 78" in PROPOSED.read_text()
    compose = COMPOSE.read_text()
    assert "Dockerfile.review-candidate" not in compose
    assert "entrypoint:" not in compose
    assert 'cap_drop: ["ALL"]' in compose
    assert "no-new-privileges:true" in compose
    assert "not an oci authorization" in CONTRACT.read_text().lower()


@pytest.mark.parametrize(
    "insecure",
    [
        ("FROM --platform=linux/amd64 " + PINNED_BASE, "FROM ubuntu:latest"),
        ("--require-hashes", "--disable-pip-version-check"),
        ("openssh-server=1:10.2p1-2ubuntu3.8", "openssh-server"),
        ("cp -a /var/lib/apt/lists/*_InRelease", "true # skip provenance"),
        ("--only-binary=:all:", "--no-cache-dir"),
        (
            'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]',
            'ENTRYPOINT ["/usr/sbin/sshd"]',
        ),
        ("COPY deploy/ssh-target/entrypoint.review-hold", "# COPY hold removed"),
    ],
)
def test_candidate_tampering_cannot_silently_admit_sshd(insecure: tuple[str, str]) -> None:
    a, b = insecure
    original = CANDIDATE.read_text()
    assert a in original
    with pytest.raises(AssertionError):
        _verify(original.replace(a, b), HOLD.read_text(), SUDOERS.read_text())


def test_existing_managed_host_launcher_is_not_represented_as_oci_compatible() -> None:
    contract = CONTRACT.read_text()
    assert "SUDO_UID" in contract and "2201" in contract and "2202" in contract
    assert "source cgroup" in contract.lower()
    assert "not an oci authorization" in contract.lower()
    # Existing managed host launcher expects login UID 2202 while proposed OCI
    # login UID is 2201; never silently modify the accepted native launcher.
    launcher = (ROOT / "ops/live-e2e/ssh-over-mcp-host-agent-launcher.py").read_text()
    assert 'env.get("SUDO_UID") != str(HOST_AGENT_UID)' in launcher
