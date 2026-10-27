"""Running-image pilot proof must stay distinct from signed STOP78 test media."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_runnable_image_is_built_from_reviewed_source_not_exported_test_archive() -> None:
    source = (ROOT / "ops/mvp/build_online_pilot_review_image.py").read_text()
    assert "from mode_a_hosted_native_review import stage" in source
    assert "FROM som-mvp-fs-privsep:local" in source
    assert 'ENTRYPOINT ["/usr/sbin/sshd"]' in source
    assert 'CMD ["-D","-e"]' in source
    assert 'GITHUB_EVENT_NAME") == "pull_request"' in source
    assert '"--network",' in source and '"none",' in source
    assert "docker load" not in source
    assert "docker push" not in source


def test_runnable_image_default_start_is_proved_with_actual_ssh_and_fs() -> None:
    proof = (ROOT / "ops/mvp/mode_a_hosted_runnable_image_probe.py").read_text()
    smoke = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    assert "use_default_entrypoint=True" in proof
    assert "check_node(" in proof
    assert "HOSTED_ONLINE_PILOT_DEFAULT_SSHD_FS_PASS" in proof
    assert '"--rm"' in smoke and '"--read-only"' in smoke
    assert "if use_default_entrypoint:" in smoke
    assert 'image == "som-mvp-fs-online-pilot-review:local"' in smoke
    assert '"--entrypoint"' in smoke
    assert "docker image rm" not in proof
    assert "docker compose" not in proof


def test_runnable_ci_candidate_never_promoted_as_release_image() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/mvp-342-oci-source-build.yml").read_text())
    steps = workflow["jobs"]["build-source"]["steps"]
    names = [x["name"] for x in steps]
    source_index = next(
        i for i, x in enumerate(steps) if x["name"].startswith("Bake exact no-sudo")
    )
    candidate_index = next(
        i for i, x in enumerate(steps) if x["name"].startswith("Build distinct runnable")
    )
    proof_index = next(i for i, x in enumerate(steps) if x["name"].startswith("Prove default"))
    export_index = next(i for i, x in enumerate(steps) if x["name"].startswith("Export hash-bound"))
    assert source_index < candidate_index < proof_index < export_index
    assert "python3 ops/mvp/build_online_pilot_review_image.py" in steps[candidate_index]["run"]
    assert "python3 ops/mvp/mode_a_hosted_runnable_image_probe.py" in steps[proof_index]["run"]
    export = steps[export_index]["run"]
    assert "docker save som-mvp-fs-native-review:local" in export
    assert "online-pilot-review" not in export
    upload = steps[-1]
    assert upload["with"]["path"] == "proof/*"
    assert not any(
        "docker push" in str(step.get("run", "")) or "docker compose up" in str(step.get("run", ""))
        for step in steps
    )
    assert "ENTRYPOINT" not in names
