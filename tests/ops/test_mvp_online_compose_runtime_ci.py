"""Disposable real Compose startup is isolated from production rollout."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_hosted_compose_startup_is_actual_and_disposable() -> None:
    script = (ROOT / "ops/mvp/mode_a_hosted_online_compose_startup.py").read_text()
    assert 'os.getenv("GITHUB_ACTIONS") == "true"' in script
    assert 'os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"' in script
    assert 'os.getenv("GITHUB_EVENT_NAME") == "pull_request"' in script
    assert '"--project-name"' in script
    assert '"--wait"' in script
    assert '"up",' in script and '"-d",' in script
    assert '"down", "--volumes", "--remove-orphans"' in script or (
        '"down",' in script and '"--volumes",' in script and '"--remove-orphans",' in script
    )
    assert "docker build" not in script
    assert '"docker", "build"' in script
    assert '"Dockerfile"' in script
    assert '"linux/amd64", "linux/x86_64"' in script
    assert "entrypoint: !reset null" in script
    assert "command: !reset null" in script
    assert "mvp-fs-review" in script
    assert "no-production-keys" in script
    assert "MODE_A_COMPOSE_ALL_FIVE_SERVICES_HEALTHY_CI_ONLY_PASS" in script
    assert "docker push" not in script


def test_real_hosted_workflow_runs_compose_after_default_boot_before_export() -> None:
    wf = yaml.safe_load((ROOT / ".github/workflows/mvp-342-oci-source-build.yml").read_text())
    steps = wf["jobs"]["build-source"]["steps"]
    names = [x["name"] for x in steps]
    previous = next(i for i, n in enumerate(names) if n.startswith("Prove default runnable"))
    startup = next(i for i, n in enumerate(names) if n.startswith("Bring up full Compose"))
    export = next(i for i, n in enumerate(names) if n.startswith("Export runnable"))
    assert previous < startup < export
    assert "python3 ops/mvp/mode_a_hosted_online_compose_startup.py" in steps[startup]["run"]
    assert "MODE_A_COMPOSE_ALL_FIVE_SERVICES_HEALTHY_CI_ONLY_PASS" in steps[startup]["run"]
    assert "docker compose up" not in steps[startup]["run"]
    assert "DOCKER_CONFIG" in steps[startup]["run"]
