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
    assert "docker save som-mvp-fs-native-review:local | gzip -n -1" in commands
    assert "FS_NATIVE_REVIEW_IMAGE_ID=" in commands
    assert "NATIVE_NOSUDO_CODE_BAKED=true" in commands
    assert "python3 ops/mvp/build_native_review_image.py" in commands
    assert "OFFLINE_IMAGE_SHA256SUMS" in commands
    assert "gzip -t proof/som342-openssh-fs.docker.tar.gz" in commands
    assert "docker load" in commands
    assert "ARCHIVE_LOAD_TEST_PASSED=true" in commands
    assert (
        "REMAPPED_IMAGE_ADMISSION_REACHED=true"
        in (ROOT / "ops/mvp/mode_a_hosted_userns_verify.sh").read_text()
    )
    assert "steps.oci_smoke.outcome == 'success'" in job["steps"][-1]["if"]
    assert "steps.export_archive.outcome == 'success'" in job["steps"][-1]["if"]
    assert "steps.userns_proof.outcome == 'success'" in job["steps"][-1]["if"]
    assert "steps.attest_archive.outcome == 'success'" in job["steps"][-1]["if"]
    perms = yaml.safe_load(WORKFLOW.read_text())["permissions"]
    assert perms == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
        "artifact-metadata": "write",
    }
    attest = [step for step in steps if step.get("id") == "attest_archive"]
    assert len(attest) == 1
    assert attest[0]["uses"] == "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    assert attest[0]["with"]["subject-path"] == "proof/som342-openssh-fs.docker.tar.gz"
    assert "TEST_ARCHIVE_GITHUB_PROVENANCE_ATTESTED=true" in commands
    assert "SIGNED_RUNTIME_ID=false" in commands

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
    node = smoke.split("def start_node(", 1)[1].split("\ndef ", 1)[0]
    assert '"--security-opt"' in node and '"no-new-privileges:true"' in node
    assert 'hostconfig["SecurityOpt"] == ["no-new-privileges:true"]' in node
    assert '"--read-only"' in smoke
    assert '"/srv/data:rw,noexec,nosuid,nodev,uid=2201,gid=3201,mode=0700' in smoke
    assert "MODE_A_OPENSSH_OCI_TWO_NODE_FS_ONLY_HOSTED_PASS" in smoke
    assert "mode_a_hosted_project_transport_smoke.py" in smoke
    assert "PROJECT_ASYNCSSH_TRANSPORT_TYPED_FS_NODE_" in smoke
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
    assert '"/proc/self/uid_map"' in smoke and '"/proc/self/gid_map"' in smoke
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
    assert "mktemp -d /tmp/som342-userns-XXXXXX" in body
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


def test_hosted_project_transport_uses_real_project_ssh_code_not_shell():
    source = (ROOT / "ops/mvp/mode_a_hosted_project_transport_smoke.py").read_text()
    assert "SSHConnectionManager(" in source
    assert "StaticCredentialProvider(" in source
    assert "StructuredSSHTransport(connections=manager)" in source
    assert "FsReadEnvelope(" in source
    assert "FsStatEnvelope(" in source
    assert "FsWriteEnvelope(" in source
    assert "encode_request(envelope, data)" in source
    assert "result.exit_status == expected_status" in source
    assert "host_key=f" in source
    assert "await manager.close()" in source
    assert "PROJECT_ASYNCSSH_TRANSPORT_TYPED_FS_NODE_" in source
    assert "subprocess" not in source


def test_hosted_central_mcp_ledger_two_node_control_is_real_and_test_only():
    smoke = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    script = (ROOT / "ops/mvp/mode_a_hosted_control_ledger_smoke.py").read_text()
    assert '"docker", "network", "create", "--internal"' in smoke
    assert '"docker", "network", "rm", network' in smoke
    assert "HOSTED_TWO_NODE_CROSS_NETWORK_SSH_DENIED_PASS" in smoke
    assert "HOSTED_CONTROL_TO_TWO_ISOLATED_SSH_NODES_PASS" in smoke
    assert "NODE_TO_NODE_TCP_DENIAL_PROVEN=true" in smoke
    assert '"docker", "network", "connect", node_networks[1], control' in smoke
    assert "s.connect_ex((sys.argv[1],2222))" in smoke
    assert "NETWORK_DIRECTIONAL_ACL_PROVEN=false" in smoke
    assert "prove_central_mcp_ledger(work, running, networks)" in smoke
    assert '"--cap-drop"' in smoke and '"no-new-privileges:true"' in smoke
    assert "CENTRAL_MCP_LEDGER_TWO_OPENSSH_NODES_TEST_ONLY_PASS" in smoke
    for token in (
        "build_application(",
        "SecurityLedgerService.create(",
        "Client(transport)",
        '("fs_mkdir",',
        '"fs_write",',
        'client.call_tool("approval_status"',
        '"consumed"',
        '"pending"',
        '"ssh_over_mcp.approvals.cli"',
        "CENTRAL_MCP_LEDGER_TWO_OPENSSH_NODES_TEST_ONLY_PASS",
    ):
        assert token in script
    assert "docker" not in script
    assert 'client.call_tool("ssh_exec"' not in script


def test_openssh_fs_account_home_exists_but_is_root_owned_and_immutable():
    source = (ROOT / "deploy/ssh-target/Dockerfile.fs-only-review-candidate").read_text()
    assert "useradd -u 2201 -g 3201 --no-create-home -d /opt/ssh-over-mcp-e2e/empty-home" in source
    assert "chown 0:0 /opt/ssh-over-mcp-e2e/empty-home" in source
    assert "chmod 0555 /opt/ssh-over-mcp-e2e/empty-home" in source
    assert "-d /nonexistent -s /bin/sh ssh-over-mcp-e2e-host" not in source


def test_hosted_native_login_no_sudo_is_feasibility_only_not_release():
    native = (ROOT / "ops/mvp/mode_a_native_login_probe.py").read_text()
    oci = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    assert "from mode_a_native_login_probe import check as check_native_login" in oci
    assert "check_native_login(name, known)" in oci
    assert 'RUNNER_ENVIRONMENT") == "github-hosted"' in native
    assert 'GITHUB_EVENT_NAME") == "pull_request"' in native
    assert "Port 2223" in native and "ListenAddress 127.0.0.1" in native
    assert "ForceCommand /usr/bin/setpriv --no-new-privs" in native
    assert "NATIVE_OPENSSH_NO_SUDO_KERNEL_CHECKS=" in native
    assert "'four_sets_zero':nonbounding_zero" in native
    assert "'bounding_zero':bounding_zero" in native
    assert "zero=nonbounding_zero and bounding_zero" in native
    assert "admission_mask=(1<<6)|(1<<7)|(1<<8)|(1<<18)" in native
    assert "int(bounding_hex,16)==admission_mask" in native
    for negative in ("root_uid_denied", "root_gid_denied", "chroot_denied", "setgroups_denied"):
        assert negative in native
    assert "NATIVE_OPENSSH_NO_SUDO_LIMITED_BOUNDING_NEGATIVES_PASS_ONLY" in native
    assert "'nested_userns_denied':nested_userns_denied" in native
    assert "'seccomp_filter':seccomp_filter" in native
    assert "'/usr/bin/unshare','--user','--map-root-user','/usr/bin/true'" in native
    assert "Nested user namespaces can grant fresh capabilities" in native
    assert "Diagnostic candidate is NOT the five-zero production release gate" in native
    assert "original all-five-sets-zero release contract" in native
    assert "current_user_ns" not in native
    assert "NATIVE_OPENSSH_NO_SUDO_FULL_KERNEL_BOUNDARY_NOT_PROVEN" in native
    assert "NATIVE_OPENSSH_NO_SUDO_FULL_KERNEL_BOUNDARY_PASS" in native
    assert 'status.get("hostkey_denied") is True' in native
    assert '"caps_zero", "nnp", "hostkey_denied"' in native
    assert '"docker"' in native and '"exec"' in native and '"-d"' in native
    assert '"docker", "run"' not in native
    assert "sudo" not in native.split("FORCE = (", 1)[1].split("\n", 1)[0]
    assert "ENTRYPOINT" not in native
    assert "docker compose" not in native


def test_native_review_oci_is_only_ci_overlay_not_release_admission():
    overlay = (ROOT / "ops/mvp/mode_a_hosted_native_review.py").read_text()
    smoke = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    assert "GITHUB_ACTIONS" in overlay and "github-hosted" in overlay
    assert "old_gate = " in overlay and "new_gate = " in overlay
    assert "assert launcher_src.count(old_gate) == 1" in overlay
    assert "FOUR_CAPS == 0x401C0" in overlay
    assert 'or found.get("Seccomp") != "2"' in overlay
    assert "no-new-privs" in overlay
    assert "dst={dest},readonly" in overlay
    assert '"ForceCommand /usr/bin/sudo" not in cfg' in overlay
    assert 'IMAGE = "som-mvp-fs-native-review:local"' in smoke
    assert "native_mounts" not in smoke
    assert "NATIVE_FOUR_ZERO_LIMITED_CAPBND_TEST_ONLY=true" in smoke
    assert "NATIVE_FOUR_ZERO_LIMITED_CAPBND_TEST_ONLY=true" in smoke
    assert "FS_LAUNCHER_FIVE_ZERO_RELEASE_CONTRACT_UNCHANGED=true" in smoke
    assert "start_node(name, work / name, running)" in smoke
    builder = (ROOT / "ops/mvp/build_native_review_image.py").read_text()
    assert "FROM som-mvp-fs-privsep:local" in builder
    assert "COPY --chown=0:0 --chmod=0555" in builder
    assert "COPY --chown=0:0 --chmod=0644" in builder
    assert "ENTRYPOINT" in builder and "ssh-over-mcp-image-hold" in builder
    assert "stage(context)" in builder
    assert '"--network"' in builder and '"none"' in builder
    assert 'NATIVE_IMAGE = "som-mvp-fs-native-review:local"' in builder
    userns = (ROOT / "ops/mvp/mode_a_hosted_userns_verify.sh").read_text()
    assert "FS_NATIVE_REVIEW_IMAGE_ID=" in userns
    assert "som-mvp-fs-native-review:local" in userns
    assert "som-mvp-fs-privsep:local" not in userns
    assert "USERNS_REMAPPED_CENTRAL_LEDGER_TWO_NODE_TEST_ONLY_PASS" in smoke
    assert "USERNS_REMAPPED_NATIVE_NO_SUDO_TWO_REAL_FS_NODES_PASS" in smoke
    assert '"/usr/sbin/sshd"' in smoke and '"--entrypoint"' in smoke
    assert "ENTRYPOINT" not in overlay


def test_native_ci_mount_renders_exact_one_gate_change_without_host_sudo(tmp_path, monkeypatch):
    import importlib.util
    import sys

    module_path = ROOT / "ops/mvp/mode_a_hosted_native_review.py"
    spec = importlib.util.spec_from_file_location("mode_a_hosted_native_review", module_path)
    assert spec and spec.loader
    sys.path.insert(0, str(module_path.parent))
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    for k, v in {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_EVENT_NAME": "pull_request",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("SOM342_REMAPPED_ROOT_UID", raising=False)
    monkeypatch.delenv("SOM342_REMAPPED_ROOT_GID", raising=False)
    calls = []
    monkeypatch.setattr(module, "run", lambda args: calls.append(args))
    mounts = module.stage(tmp_path)
    assert len(calls) == 4 and all(
        x[:3] == ["sudo", "-n", "chown"] or x[:3] == ["sudo", "-n", "chmod"] for x in calls
    )
    assert len(mounts) == 4 and mounts[0] == "--mount" and mounts[2] == "--mount"
    launcher = (tmp_path / "fs-only-native-review.py").read_text()
    python = ROOT / "ops/mvp/ssh-over-mcp-fs-only-launcher.py"
    original = python.read_text()
    assert launcher.count('int(found["CapBnd"], 16) != 0x401c0') == 1
    assert launcher.count('found.get("Seccomp") != "2"') == 1
    assert 'found["NoNewPrivs"] != "1"' in launcher
    assert (
        'or any(found[name] != zero for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"))'
        in launcher
    )
    assert 'CapBnd", "CapAmb", "Seccomp"' in launcher
    assert 'int(found["CapBnd"], 16)' not in original
    assert "FsOnlyStartRefused" in launcher
    config = (tmp_path / "sshd_config.native-review").read_text()
    assert "ForceCommand /usr/bin/setpriv --no-new-privs /usr/bin/python3 -I -S" in config
    assert "ForceCommand /usr/bin/sudo" not in config
    assert "PermitRootLogin no" in config
    assert "DisableForwarding yes" in config


def test_attested_archive_handoff_never_claims_production_image_is_signed():
    runbook = (ROOT / "docs/runbooks/mvp-mode-a-oci-offline-handoff.md").read_text()
    assert "gh attestation verify" in runbook
    assert (
        "--signer-workflow zhangyuz/ssh-over-mcp/.github/workflows/mvp-342-oci-source-build.yml"
        in runbook
    )
    assert "--deny-self-hosted-runners" in runbook
    assert "f7a931a4644be812bd5493808d8613a7ef7a57ec" in runbook
    assert "TEST_ARCHIVE_GITHUB_PROVENANCE_ATTESTED=true" in runbook
    assert "historical f7a931a test archive" in runbook
    assert "NATIVE_NOSUDO_CODE_BAKED=true" in runbook
    assert "FS_NATIVE_REVIEW_IMAGE_ID" in runbook
    assert "SIGNED_RUNTIME_ID=false" in runbook
    assert "STOP78" in runbook


def test_baked_native_review_source_equals_official_patch_not_runtime_mount():
    smoke = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    builder = (ROOT / "ops/mvp/build_native_review_image.py").read_text()
    workflow = yaml.safe_load(WORKFLOW.read_text())["jobs"]["build-source"]
    assert 'IMAGE = "som-mvp-fs-native-review:local"' in smoke
    assert '"--entrypoint"' in smoke
    assert "native_mounts" not in smoke
    assert "stage(context)" in builder
    assert "fs-only-native-review.py" in builder
    assert "sshd_config.native-review" in builder
    assert "som-mvp-fs-native-review:local" in builder
    cmds = "\n".join(str(s.get("run", "")) for s in workflow["steps"])
    assert "python3 ops/mvp/build_native_review_image.py" in cmds
    assert "docker save som-mvp-fs-native-review:local" in cmds
    assert "FS_NATIVE_REVIEW_IMAGE_ID=" in cmds
    assert "som-mvp-fs-privsep:local" in cmds  # old base retained for provenance
    assert "SIGNED_IMAGE=false" in cmds and "DEPLOYED=false" in cmds


def test_hosted_directional_new_flow_acl_is_real_but_not_production_authority():
    acl = (ROOT / "ops/mvp/mode_a_hosted_directional_acl.py").read_text()
    smoke = (ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py").read_text()
    assert 'os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"' in acl
    assert 'os.getenv("GITHUB_EVENT_NAME") == "pull_request"' in acl
    assert 'control.startswith("som342-mcp-control-")' in acl
    assert '"--target"' in acl and "str(pid)" in acl and '"--net"' in acl
    assert '"INPUT"' in acl and '"--ctstate"' in acl and '"NEW"' in acl
    assert '"REJECT"' in acl and '"8000"' in acl
    assert "pre-policy node->control not reachable" in acl
    assert "NEW TCP/8000 reached control despite ACL" in acl
    assert "HOSTED_NODE_TO_CONTROL_TCP8000_NEW_DENIED_BOTH_PASS" in acl
    assert "prove_directional_acl(control, node_names, node_networks, run)" in smoke
    assert "NETWORK_DIRECTIONAL_ACL_PROVEN=false SIGNED_MEDIA=false DEPLOYED=false" in smoke
