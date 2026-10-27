"""One-shot signed Ubuntu APT media must stay on disposable hosted builders."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/mvp-mode-a-one-shot-engine-media.yml"


def test_consumed_native_media_job_is_disabled_and_tightly_bound():
    source = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request" in workflow[True]  # YAML 1.1 parses 'on' as True
    job = workflow["jobs"]["engine-media"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert "github.event.pull_request.number == 342" in job["if"]
    assert "feat/mvp-mode-a-compose-overlay-oct24" in job["if"]
    assert "&& false" in job["if"]
    assert "one-off-20261026-native-apt" in source
    assert "workflow_dispatch" not in source
    assert "self-hosted" not in source
    assert "persist-credentials: false" in source


def test_apt_runs_with_native_hosted_sandbox_not_partial_container_capabilities():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "sudo apt-get update" in source
    assert "--download-only" in source
    assert "Dir::State::status=/dev/null" in source
    assert "Dir::Etc::sourceparts=-" in source
    assert 'Dir::State::lists="$lists"' in source
    assert "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" in source
    assert "--no-install-recommends" in source
    assert "docker.io containerd runc iptables iproute2 ca-certificates" in source
    assert "sha256sum" in source
    assert "max_bytes" in source
    assert "upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in source
    for forbidden in [
        "docker run",
        "docker pull",
        "--cap-add",
        "--privileged",
        "APT::Get::AllowUnauthenticated",
        "allow-unauthenticated",
        "allow-insecure-repositories",
        "Trusted: yes",
        "qemu-system",
        "Dockerfile.proposed",
        "sudo docker",
    ]:
        assert forbidden not in source


def test_artifacts_remain_non_executable_until_separate_runtime_review():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "SSH_IMAGE_BUILT=false" in source
    assert "GUEST_EXECUTED=false" in source
    assert "ENGINE_OFFLINE_INSTALL_PROVEN=false" in source
    assert "SOURCE_SHA=" in source
    assert "(cd media && sha256sum" in source
    assert "sha256sum -c SHA256SUMS" in source
    assert "PACKAGE_ORIGIN=ubuntu-26.04-signed-apt" in source
    assert "retention-days: 3" in source

    # Never archive root-owned APT lock, partial dirs, or build internals.
    workflow = yaml.safe_load(source)
    upload = workflow["jobs"]["engine-media"]["steps"][-1]["with"]["path"]
    assert set(upload.splitlines()) == {
        "media/*.deb",
        "media/SHA256SUMS",
        "media/PROVENANCE.txt",
        "media/architecture.txt",
        "media/engine-package-versions.txt",
        "media/ubuntu-archive-keyring.sha256",
    }


def test_regular_pr_hosted_oci_records_read_only_apt_preflight_for_no_nic_guest():
    """Locate failed one-shot condition without reauthorizing package downloads."""
    source = (ROOT / ".github/workflows/mvp-342-oci-source-build.yml").read_text()
    assert "python3 ops/mvp/mode_a_hosted_apt_probe.py" in source
    assert "Read-only Ubuntu Engine APT provenance diagnostics" in source
    script = ROOT / "ops/mvp/mode_a_hosted_apt_probe.py"
    content = script.read_text()
    assert "ENGINE_APT_PREFLIGHT_" in content
    assert "OFFLINE_ENGINE_MEDIA_BUILD_AUTHORIZED=false" in content
    for forbidden in ("apt-get update", "apt-get install", "sudo ", "subprocess", "socket"):
        assert forbidden not in content


def test_offline_apt_probe_distinguishes_signer_mismatch_without_apt_mutations():
    from ops.mvp.mode_a_hosted_apt_probe import checks

    release = ["ID=ubuntu", 'VERSION_ID="26.04"']
    source = [
        "URIs: http://archive.ubuntu.com/ubuntu",
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg",
    ]
    good = checks(release, source, True, machine="x86_64", uid=1001)
    assert all(good.values())
    missing_signer = checks(release, source[:-1], True, machine="x86_64", uid=1001)
    assert missing_signer["KEYRING_SIGNER"] is False
    assert missing_signer["UBUNTU_REPOSITORY"] is True
    assert checks(release, source, True, machine="x86_64", uid=0)["NON_ROOT"] is False


def test_os_release_symlink_platform_parser_is_used_for_hosted_probe(monkeypatch, capsys):
    from ops.mvp import mode_a_hosted_apt_probe as probe

    monkeypatch.setattr(
        probe.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "26.04"}
    )
    monkeypatch.setattr(probe.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(probe.os, "getuid", lambda: 1001)
    monkeypatch.setattr(probe.os, "access", lambda *_: True)
    monkeypatch.setattr(
        probe,
        "_bounded_lines",
        lambda _: [
            "URIs: mirror+file:/etc/apt/mirrors",
            "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg",
        ],
    )
    monkeypatch.setattr(
        probe,
        "_KEYRING",
        type("Keyring", (), {"is_file": lambda self: True, "is_symlink": lambda self: False})(),
    )
    probe.main()
    lines = capsys.readouterr().out.splitlines()
    assert "ENGINE_APT_PREFLIGHT_UBUNTU_2604=true" in lines
    assert "ENGINE_APT_URI_CLASS=UBUNTU_MIRROR_LIST" in lines
    assert "ENGINE_APT_PREFLIGHT_UBUNTU_REPOSITORY=false" in lines
    assert "OFFLINE_ENGINE_MEDIA_BUILD_AUTHORIZED=false" in lines
