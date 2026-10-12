from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "supervise-mac-x86-runner.sh"
LABEL = "com.ssh-over-mcp.mac-x86-runner"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def _fake_host_env(tmp_path: Path) -> tuple[dict[str, str], Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state = tmp_path / "runner.state"
    deploy_log = tmp_path / "deploy.log"
    deploy_count = tmp_path / "deploy.count"
    launchctl_log = tmp_path / "launchctl.log"

    _write_executable(
        fake_bin / "uname",
        """
        #!/usr/bin/env bash
        case "${1:-}" in
          -s) echo Darwin ;;
          -m) echo x86_64 ;;
          *) echo Darwin ;;
        esac
        """,
    )
    _write_executable(
        fake_bin / "gh",
        """
        #!/usr/bin/env bash
        if [[ "${1:-}" == "auth" && "${2:-}" == "status" ]]; then
          exit 0
        fi
        exit 1
        """,
    )
    _write_executable(
        fake_bin / "docker",
        """
        #!/usr/bin/env bash
        case "${1:-}" in
          info)
            exit 0
            ;;
          image)
            [[ "${2:-}" == "inspect" ]] && exit 0
            ;;
          inspect)
            if [[ "${2:-}" == "--format" ]]; then
              [[ -f "${FAKE_DOCKER_STATE}" ]] || exit 1
              echo exited
              exit 0
            fi
            [[ -f "${FAKE_DOCKER_STATE}" ]]
            exit $?
            ;;
          rm)
            rm -f "${FAKE_DOCKER_STATE}"
            exit 0
            ;;
        esac
        exit 1
        """,
    )
    _write_executable(
        fake_bin / "launchctl",
        """
        #!/usr/bin/env bash
        printf '%s\n' "$*" >> "${FAKE_LAUNCHCTL_LOG}"
        exit 0
        """,
    )

    fake_deploy = tmp_path / "fake-deploy.sh"
    _write_executable(
        fake_deploy,
        """
        #!/usr/bin/env bash
        [[ -z "${RUNNER_TOKEN:-}" ]] || exit 23
        printf '%s\n' "$*" >> "${FAKE_DEPLOY_LOG}"
        if [[ -n "${FAKE_DEPLOY_IDENTITIES:-}" ]]; then
          printf '%s|%s|%s|%s\n' "${RUNNER_NAME:-}" "${RUNNER_CONTAINER_NAME:-}" \
            "${RUNNER_CPUS:-}" "${RUNNER_MEMORY:-}" >> "${FAKE_DEPLOY_IDENTITIES}"
        fi

        count=0
        if [[ -f "${FAKE_DEPLOY_COUNT}" ]]; then
          count="$(cat "${FAKE_DEPLOY_COUNT}")"
        fi
        count=$((count + 1))
        printf '%s\n' "${count}" > "${FAKE_DEPLOY_COUNT}"
        touch "${FAKE_DOCKER_STATE}"

        if [[ "${FAKE_STOP_AFTER_DEPLOYS:-0}" -gt 0 ]] \
          && [[ "${count}" -ge "${FAKE_STOP_AFTER_DEPLOYS}" ]]; then
          kill -TERM "$PPID"
        fi
        """,
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "HOME": str(tmp_path / "home"),
            "RUNNER_DEPLOY_SCRIPT": str(fake_deploy),
            "RUNNER_SUPERVISOR_POLL_SECONDS": "0",
            "RUNNER_SUPERVISOR_REPLACEMENT_DELAY_SECONDS": "0",
            "FAKE_DOCKER_STATE": str(state),
            "FAKE_DEPLOY_LOG": str(deploy_log),
            "FAKE_DEPLOY_COUNT": str(deploy_count),
            "FAKE_LAUNCHCTL_LOG": str(launchctl_log),
        }
    )
    return env, deploy_log, launchctl_log


def test_once_mode_replaces_one_ephemeral_runner_without_reusing_a_token(
    tmp_path: Path,
) -> None:
    env, deploy_log, _ = _fake_host_env(tmp_path)

    result = subprocess.run(
        ["bash", str(SCRIPT), "once"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert deploy_log.read_text(encoding="utf-8").strip() == "up --no-build"


def test_run_mode_replaces_retired_runner_automatically(tmp_path: Path) -> None:
    env, deploy_log, _ = _fake_host_env(tmp_path)
    env["FAKE_STOP_AFTER_DEPLOYS"] = "2"

    result = subprocess.run(
        ["bash", str(SCRIPT), "run"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr
    assert deploy_log.read_text(encoding="utf-8").splitlines() == [
        "up --no-build",
        "up --no-build",
    ]


def test_supervisor_rejects_a_preseeded_registration_token(tmp_path: Path) -> None:
    env, deploy_log, _ = _fake_host_env(tmp_path)
    env["RUNNER_TOKEN"] = "stale-one-time-token"

    result = subprocess.run(
        ["bash", str(SCRIPT), "once"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "RUNNER_TOKEN" in result.stderr
    assert not deploy_log.exists()


def test_install_creates_keepalive_launchd_user_agent(tmp_path: Path) -> None:
    env, _, launchctl_log = _fake_host_env(tmp_path)

    result = subprocess.run(
        ["bash", str(SCRIPT), "install"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    plist = Path(env["HOME"]) / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    rendered = plist.read_text(encoding="utf-8")
    assert "<key>RunAtLoad</key>" in rendered
    assert "<key>KeepAlive</key>" in rendered
    assert str(SCRIPT) in rendered
    assert "RUNNER_TOKEN" not in rendered
    launchctl_calls = launchctl_log.read_text(encoding="utf-8")
    assert "bootstrap" in launchctl_calls
    assert "kickstart" in launchctl_calls


def test_secondary_once_has_distinct_ephemeral_runner_identity_and_quota(tmp_path: Path) -> None:
    env, deploy_log, _ = _fake_host_env(tmp_path)
    identities = tmp_path / "identities.log"
    env.update({"RUNNER_SUPERVISOR_SLOT": "secondary", "FAKE_DEPLOY_IDENTITIES": str(identities)})

    result = subprocess.run(
        ["bash", str(SCRIPT), "once"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert deploy_log.read_text(encoding="utf-8").strip() == "up --no-build"
    assert identities.read_text(encoding="utf-8").strip() == (
        "ssh-over-mcp-mac-x86-b|ssh-over-mcp-runner-mac-x86-b|3|4g"
    )


def test_secondary_launchd_service_does_not_replace_primary(tmp_path: Path) -> None:
    env, _, launchctl_log = _fake_host_env(tmp_path)
    secondary = env | {"RUNNER_SUPERVISOR_SLOT": "secondary"}

    primary_result = subprocess.run(
        ["bash", str(SCRIPT), "install"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    secondary_result = subprocess.run(
        ["bash", str(SCRIPT), "install"],
        cwd=ROOT,
        env=secondary,
        capture_output=True,
        text=True,
        check=False,
    )

    assert primary_result.returncode == 0, primary_result.stderr
    assert secondary_result.returncode == 0, secondary_result.stderr
    directory = Path(env["HOME"]) / "Library" / "LaunchAgents"
    original = (directory / f"{LABEL}.plist").read_text(encoding="utf-8")
    second = (directory / f"{LABEL}-b.plist").read_text(encoding="utf-8")
    assert "<string>primary</string>" in original
    assert "<string>secondary</string>" in second
    assert "<string>ssh-over-mcp-mac-x86-b</string>" in second
    assert "<string>ssh-over-mcp-runner-mac-x86-b</string>" in second
    assert "<string>3</string>" in second
    assert "<string>4g</string>" in second
    assert "RUNNER_TOKEN" not in original + second
    assert f"{LABEL}-b" not in original
    assert len(launchctl_log.read_text(encoding="utf-8").splitlines()) == 6


def test_secondary_cannot_reuse_primary_identity_or_receive_unsafe_quota(tmp_path: Path) -> None:
    env, deploy_log, _ = _fake_host_env(tmp_path)
    bad_configurations = [
        {"RUNNER_SUPERVISOR_SLOT": "third"},
        {"RUNNER_SUPERVISOR_SLOT": "secondary", "RUNNER_NAME": "ssh-over-mcp-mac-x86"},
        {
            "RUNNER_SUPERVISOR_SLOT": "secondary",
            "RUNNER_CONTAINER_NAME": "ssh-over-mcp-runner-mac-x86",
        },
        {"RUNNER_SUPERVISOR_SLOT": "secondary", "RUNNER_CPUS": "9"},
        {"RUNNER_SUPERVISOR_SLOT": "secondary", "RUNNER_MEMORY": "6g"},
        {"RUNNER_SUPERVISOR_SLOT": "secondary", "RUNNER_MEMORY": "4g</string><key>Bad</key>"},
        {"RUNNER_SUPERVISOR_SLOT": "secondary", "RUNNER_NAME": "bad<XML"},
        {"RUNNER_SUPERVISOR_SLOT": "secondary", "RUNNER_CONTAINER_NAME": "bad name"},
    ]
    for overrides in bad_configurations:
        result = subprocess.run(
            ["bash", str(SCRIPT), "once"],
            cwd=ROOT,
            env=env | overrides,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2, (overrides, result.stdout, result.stderr)
    assert not deploy_log.exists()
