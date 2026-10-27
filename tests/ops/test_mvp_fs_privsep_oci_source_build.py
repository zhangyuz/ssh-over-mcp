"""Guards for the dormant OpenSSH FS-only OCI source build path."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKER = ROOT / "deploy/ssh-target/Dockerfile.fs-privsep-review-candidate"
WORKFLOW = ROOT / ".github/workflows/mvp-342-oci-source-build.yml"
HOLD = 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]'


def test_privsep_image_is_derived_from_pinned_fs_source_and_hard_stopped():
    base = (ROOT / "deploy/ssh-target/Dockerfile.fs-only-review-candidate").read_text()
    source = DOCKER.read_text()
    assert "docker.io/library/ubuntu@sha256:" in base
    assert "ARG SOM_FS_SOURCE_IMAGE" in source
    assert "FROM ${SOM_FS_SOURCE_IMAGE}" in source
    assert "sudo=1.9.17p2-1ubuntu3.2" in source
    assert "sudo-common=1.2ubuntu" in source
    assert "test -x /usr/bin/setpriv" in source
    assert "privsep-signed-apt-lists" in source
    assert "openssh-fs-privsep-deb-sha256.txt" in source
    assert "apt-installed-final.tsv" in source
    assert "install --download-only" in source
    assert "visudo -c -f /etc/sudoers.d/ssh-over-mcp-fs" in source
    assert "COPY deploy/ssh-target/sshd_config.fs-privsep-review-candidate" in source
    assert "COPY deploy/ssh-target/sudoers.fs-privsep-review-candidate" in source
    assert "USER 0:0" in source
    assert HOLD in base and HOLD in source
    assert "ssh-keygen" not in source


def test_hosted_image_builder_never_starts_or_exports_running_ssh():
    job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["build-source"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["timeout-minutes"] <= 28
    assert "pull_request.number == 342" in job["if"]
    steps = job["steps"]
    assert steps[1]["with"]["persist-credentials"] is False
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "docker build" in commands
    assert "docker image inspect" in commands
    assert "RUNTIME_STARTED=false" in commands
    assert "mode_a_hosted_oci_fs_smoke.py" in commands
    assert "HOSTED_OCI_FS_TWO_NODE_SMOKE_PASSED=true" in commands
    assert "PRIVATE_USERNS_PROVEN=false" in commands
    assert "GUEST_VERIFIED=false" in commands
    assert "docker save som-mvp-fs-privsep:local | gzip -n -1" in commands
    assert "OFFLINE_IMAGE_SHA256SUMS" in commands
    assert "gzip -t proof/som342-openssh-fs.docker.tar.gz" in commands
    assert "docker load" in commands
    assert "ARCHIVE_LOAD_TEST_PASSED=true" in commands
    assert "REMAPPED_IMAGE_ADMISSION_REACHED=true" in (ROOT / "ops/mvp/mode_a_hosted_userns_verify.sh").read_text()
    assert "steps.oci_smoke.outcome == 'success'" in job["steps"][-1]["if"]
    assert "steps.export_archive.outcome == 'success'" in job["steps"][-1]["if"]
    assert "OFFLINE_TRANSFER_TEST_ONLY=true" in commands
    assert "SIGNED_IMAGE=false" in commands
    assert "mode_a_hosted_userns_verify.sh" in commands
    assert "HOSTED_DEDICATED_USERNS_REMAP_TEST_PASSED=true" in commands
    assert "TRUSTED_NO_NIC_GUEST_USERNS_PROVEN=false" in commands
    assert job["steps"][-1]["with"]["retention-days"] <= 3
    assert job["steps"][-1]["with"]["compression-level"] == 0
    assert not any(
        forbidden in commands
        for forbidden in ("docker run ", "docker compose", "--privileged", "sudo docker")
    )


def test_disposable_oci_two_node_smoke_has_only_loopback_and_minimal_ssh_caps():
    smoke = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    assert 'os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"' in smoke
    assert 'os.getenv("GITHUB_EVENT_NAME") == "pull_request"' in smoke
    assert '"--network"' in smoke and '"none"' in smoke
    assert '"--cap-drop"' in smoke and '"ALL"' in smoke
    assert 'SSH_CAPS = ("SETUID", "SETGID", "SETPCAP", "SYS_CHROOT")' in smoke
    assert '"--read-only"' in smoke
    assert '"/srv/data:rw,noexec,nosuid,nodev,uid=2201,gid=3201,mode=0700' in smoke
    assert "MODE_A_OPENSSH_OCI_TWO_NODE_FS_ONLY_HOSTED_PASS" in smoke
    assert "foreign_known.read_bytes()" in smoke
    assert "Host key verification failed" in smoke
    assert "oci_node_{i}_cross" in smoke
    assert "USERNS_PRIVATE_PROVEN=false" in smoke
    assert 'run(["docker", "rm", "-f", name]' in smoke
    assert '"--read-only"' in smoke
    assert '"docker"' in smoke and '"exec"' in smoke and '"-i"' in smoke
    assert "str(keys), str(auth), str(authorized)" in smoke
    assert "SOM342_REMAPPED_ROOT_UID" in smoke
    assert 'hostconfig["UsernsMode"] != "host"' in smoke
    assert "OpenSSH StrictModes" in smoke
    assert '"docker", "cp"' not in smoke
    assert "docker compose" not in smoke
    assert "--privileged" not in smoke


def test_ephemeral_userns_engine_does_not_change_host_daemon():
    body = (ROOT / "ops/mvp/mode_a_hosted_userns_verify.sh").read_text()
    assert "RUNNER_ENVIRONMENT:-" in body and "github-hosted" in body
    assert "GITHUB_EVENT_NAME:-" in body and "pull_request" in body
    assert "--userns-remap=default" in body
    assert '--data-root "$scratch/data"' in body
    assert '--host "unix://$scratch/docker.sock"' in body
    assert "--bridge=none --iptables=false --ip-forward=false --ip-masq=false" in body
    assert "SOM342_REMAPPED_ROOT_UID" in body
    assert 'mktemp -d /tmp/som342-userns-XXXXXX' in body
    assert 'chmod 0711 "$scratch"' in body
    assert 'chmod 0711 "$scratch/data"' in body
    assert 'chmod 0777 "$scratch"' not in body
    assert "SOM342_REMAPPED_ROOT_GID" in body
    assert "python3 ops/mvp/mode_a_hosted_oci_fs_smoke.py" in body
    assert "sha256sum -c OFFLINE_IMAGE_SHA256SUMS" in body
    assert "DEDICATED_USERNS_REMAP_OCI_TWO_NODE_FS_PASS" in body
    assert 'sudo -n rm -rf -- "$scratch"' in body
    for forbidden in (
        "systemctl",
        "/etc/docker/daemon.json",
        "docker compose",
        "docker context",
        "--privileged",
        "--userns=host",
    ):
        assert forbidden not in body
