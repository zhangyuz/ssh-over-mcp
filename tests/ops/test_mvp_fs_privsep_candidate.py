"""Source-only fixed OpenSSH-to-unprivileged FS runtime handoff.

This is an architecture candidate, not permission to run Docker or change caps.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = ROOT / "deploy/ssh-target/sshd_config.fs-privsep-review-candidate"
SUDO = ROOT / "deploy/ssh-target/sudoers.fs-privsep-review-candidate"
DOCKER = ROOT / "deploy/ssh-target/Dockerfile.fs-only-review-candidate"
COMPOSE = ROOT / "deploy/compose/compose.dev-ssh.yaml"

DROP = (
    "/usr/bin/setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs "
    "--reuid=2201 --regid=3201 --clear-groups "
    "/usr/bin/python3 -I -S "
    "/usr/local/libexec/ssh-over-mcp-fs-only-launcher.py"
)


def test_openssh_only_privsep_handoff_no_generic_root_escape():
    conf = CONF.read_text()
    assert "Port 2222" in conf
    assert "HostKey /etc/ssh/hostkeys/ssh_host_ed25519_key" in conf
    assert "AuthenticationMethods publickey" in conf
    assert "UsePAM no" in conf
    assert "StrictModes yes" in conf
    assert "PermitTTY no" in conf
    assert "DisableForwarding yes" in conf
    assert f"ForceCommand /usr/bin/sudo -n {DROP}" in conf
    assert "ForceCommand " in conf and conf.count("ForceCommand ") == 1
    assert "PasswordAuthentication no" in conf
    assert "KbdInteractiveAuthentication no" in conf
    assert "UsePrivilegeSeparation no" not in conf


def test_sudo_only_exact_fixed_zero_cap_fs_command():
    rules = SUDO.read_text()
    assert 'env_keep += "SSH_ORIGINAL_COMMAND"' in rules
    allowed = [
        line
        for line in rules.splitlines()
        if line and not line.startswith("#") and not line.startswith("Defaults:")
    ]
    assert allowed == [f"ssh-over-mcp-e2e-host ALL=(root) NOPASSWD: {DROP}"]
    assert "NOPASSWD: ALL" not in rules
    assert "SETENV:" not in rules
    assert "/bin/sh" not in rules
    assert "/bin/bash" not in rules


def test_candidate_not_wired_to_runtime_and_hard_stop_retained():
    deployed = DOCKER.read_text() + COMPOSE.read_text()
    assert "fs-privsep-review-candidate" not in deployed
    assert "sudoers.fs-privsep-review-candidate" not in deployed
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in deployed
    assert 'cap_drop: ["ALL"]' in COMPOSE.read_text()
    assert "no-new-privileges:true" in COMPOSE.read_text()
