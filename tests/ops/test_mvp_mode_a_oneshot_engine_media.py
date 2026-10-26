"""One-off test-only Engine media builder must never run on persistent hosts."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/mvp-mode-a-one-shot-engine-media.yml"


def test_builder_job_is_specific_to_approved_packet_and_disposable_runner():
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert parsed["permissions"] == {"contents": "read"}
    job = parsed["jobs"]["engine-media"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert "github.event.pull_request.number == 342" in job["if"]
    assert "feat/mvp-mode-a-compose-overlay-oct24" in job["if"]
    # Operator resumed a separately reviewed, one-time APT-capability correction.
    # This activation must be followed by immediate fail-closed disablement.
    assert "&& false" not in job["if"]
    assert "one-off-20261026-capfix" in WORKFLOW.read_text(encoding="utf-8")
    assert "synchronize" in WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch" not in WORKFLOW.read_text(encoding="utf-8")
    assert "self-hosted" not in WORKFLOW.read_text(encoding="utf-8")
    assert "one-off-20261026" in WORKFLOW.read_text(encoding="utf-8")


def test_engine_media_builder_is_bounded_and_not_a_runnable_ssh_image():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a" in source
    assert "apt-get" in source
    # APT's authenticated _apt downloader must be able to change UID/GID
    # and own partial directories; no broader privilege is needed here.
    assert "--cap-drop=ALL" in source
    assert "--cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN" in source
    assert "--security-opt no-new-privileges" in source
    for forbidden_cap in ("SYS_ADMIN", "DAC_OVERRIDE", "SYS_PTRACE", "NET_ADMIN"):
        assert f"--cap-add={forbidden_cap}" not in source
    assert "sha256sum" in source
    assert "docker.io" in source
    assert "max_bytes" in source
    assert "upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in source
    for forbidden in [
        "QEMU",
        "qemu-system",
        "Dockerfile.proposed",
        "privileged: true",
        "sudo docker",
    ]:
        assert forbidden not in source
