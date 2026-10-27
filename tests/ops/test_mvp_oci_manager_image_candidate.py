"""Standalone nonadmitted OCI manager image contract and import viability.

Source-only checks do not prove registry provenance, Linux OCI isolation,
manager peer mappings, cgroup PID lifetime, or the real image build.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy/ssh-target"
MANAGER = DEPLOY / "Dockerfile.manager-review-candidate"
SSH = DEPLOY / "Dockerfile.review-candidate"
HOLD = DEPLOY / "entrypoint.manager-review-hold"
BASE = (
    "docker.io/library/ubuntu@sha256:"
    "42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a"
)


def verify_candidate(source: str, hold: str) -> None:
    assert source.count("FROM ") == 1
    assert f"FROM --platform=linux/amd64 {BASE}" in source
    assert source.count("apt-get update") == 1
    assert "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" in source
    assert "cp -a /var/lib/apt/lists/*_InRelease" in source
    assert "cp -a /var/lib/apt/lists/*_Packages*" in source
    assert "signed-apt-lists-sha256.txt" in source
    assert "apt-deb-sha256.txt" in source and "apt-installed.tsv" in source
    assert "--download-only install --no-install-recommends" in source
    assert "python3=3.14.3-0ubuntu2" in source
    assert source.count("python3=3.14.3-0ubuntu2") == 2
    assert "python3-venv=" not in source
    assert source.count("ca-certificates=20260816ubuntu0.26.04.1") == 2
    assert "requirements/runtime.lock" not in source
    assert "pip install" not in source and "pip download" not in source
    assert "SITE_PACKAGES" not in source
    assert "COPY src /opt/ssh-over-mcp-e2e/workspace/src" in source
    assert "COPY ops/mvp/ssh-over-mcp-oci-manager.py" in source
    assert "COPY deploy/ssh-target/entrypoint.manager-review-hold" in source
    assert "groupadd -g 3299 som-manager-client" in source
    assert "groupadd -g 3204 som-manager" in source
    assert "useradd -u 2204 -g 3204 -G 3299" in source
    assert "USER som-manager" in source
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-manager-hold"]' in source
    assert "exit 78" in hold
    assert "COPY authorized_keys" not in source
    assert "COPY deploy/ssh-target/sudoers.review-candidate" not in source
    assert "COPY deploy/ssh-target/sshd_config.review-candidate" not in source
    assert "COPY ops/mvp/ssh-over-mcp-oci-launcher.py" not in source
    assert "openssh-server=" not in source and "sudo=" not in source
    assert "EXPOSE 22" not in source
    assert "docker.sock" not in source
    assert "privileged: true" not in source
    assert 'ENTRYPOINT ["/usr/sbin/sshd"]' not in source
    assert 'ENTRYPOINT ["/usr/bin/python3" ' not in source


def test_separate_manager_candidate_has_verified_inputs_and_hard_hold():
    source = MANAGER.read_text()
    verify_candidate(source, HOLD.read_text())
    assert f"FROM --platform=linux/amd64 {BASE}" in SSH.read_text()
    assert "entrypoint.manager-review-hold" not in SSH.read_text()
    assert (
        "Dockerfile.manager-review-candidate"
        not in (ROOT / "deploy/compose/compose.dev-ssh.yaml").read_text()
    )
    assert "exit 78" in (DEPLOY / "Dockerfile.proposed").read_text()
    versions = json.loads((DEPLOY / "ubuntu-2604-amd64-metadata-candidates.json").read_text())[
        "candidate_selection"
    ]
    for name in ("python3", "ca-certificates"):
        assert f"{name}={versions[name]['version']}" in source


@pytest.mark.parametrize(
    "before,after",
    [
        (f"FROM --platform=linux/amd64 {BASE}", "FROM ubuntu:latest"),
        ("python3=3.14.3-0ubuntu2", "python3"),
        ("cp -a /var/lib/apt/lists/*_InRelease", "echo skip-signature-record"),
        (
            'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-manager-hold"]',
            'ENTRYPOINT ["/usr/bin/python3", "-I", "-S", "/usr/local/libexec/ssh-over-mcp-oci-manager.py"]',
        ),
        ("USER som-manager", "USER root"),
    ],
)
def test_tamper_does_not_silently_unlock_manager(before: str, after: str):
    original = MANAGER.read_text()
    assert before in original
    with pytest.raises(AssertionError):
        verify_candidate(original.replace(before, after), HOLD.read_text())


def test_manager_isolated_python_import_requires_no_third_party():
    """The fixed manager + OCI root admission really import under -I -S."""
    program = (
        "import sys;"
        f"sys.path.insert(0,{str(ROOT / 'src')!r});"
        "from ssh_over_mcp.host_agent.oci_manager_runtime import serve_oci_source_manager;"
        "from ssh_over_mcp.host_agent.oci_launcher_admission import OciLauncherDomain;"
        "assert 'pydantic' not in sys.modules;"
        "assert 'yaml' not in sys.modules;"
        "assert 'mcp' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
