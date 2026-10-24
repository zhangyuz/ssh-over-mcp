"""Operator-owned proposed sshd/ForceCommand asset; no host/Docker/SSH calls."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SSHD_CONFIG = ROOT / "deploy/ssh-target/sshd_config.proposed"


def _sshd_options(text: str) -> dict[str, str]:
    """Narrow shape inspection; NOT an sshd syntax/permission validator."""
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError("invalid directive")
        key = parts[0].lower()
        if key in result:
            raise ValueError("duplicate directive")
        result[key] = parts[1]
    return result


def _check_contract(text: str) -> None:
    opts = _sshd_options(text)
    expected = {
        "port": "22",
        "addressfamily": "inet",
        "hostkey": "/etc/ssh/hostkeys/ssh_host_ed25519_key",
        "authorizedkeysfile": "/etc/ssh/authorized_keys/%u",
        "allowusers": "ssh-over-mcp-e2e-host",
        "authenticationmethods": "publickey",
        "pubkeyauthentication": "yes",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "permitemptypasswords": "no",
        "permitrootlogin": "no",
        "usepam": "no",
        "strictmodes": "yes",
        "permittty": "no",
        "allowtcpforwarding": "no",
        "disableforwarding": "yes",
        "allowstreamlocalforwarding": "no",
        "allowagentforwarding": "no",
        "x11forwarding": "no",
        "permittunnel": "no",
        "permituserenvironment": "no",
        "permituserrc": "no",
        "gatewayports": "no",
        "forcecommand": "/usr/bin/sudo -n /usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-host-agent-launcher.py",
        "loglevel": "VERBOSE",
    }
    # Exact key set disallows accidental broadening by an alias/Match override
    # in the reviewed proposal. These tests do NOT authenticate production image.
    assert opts == expected


def test_proposed_sshd_config_matches_existing_guest_forcecommand_contract():
    _check_contract(SSHD_CONFIG.read_text(encoding="ascii"))


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("PasswordAuthentication no", "PasswordAuthentication yes"),
        ("PermitTTY no", "PermitTTY yes"),
        ("AllowTcpForwarding no", "AllowTcpForwarding yes"),
        ("DisableForwarding yes", "DisableForwarding no"),
        ("AllowStreamLocalForwarding no", "AllowStreamLocalForwarding yes"),
        ("PermitUserEnvironment no", "PermitUserEnvironment yes"),
        ("PermitUserRC no", "PermitUserRC yes"),
        ("PermitRootLogin no", "PermitRootLogin yes"),
        ("UsePAM no", "UsePAM yes"),
        ("AllowUsers ssh-over-mcp-e2e-host", "AllowUsers root"),
        ("StrictModes yes", "StrictModes no"),
        ("Port 22", "Port 2222"),
        ("HostKey /etc/ssh/hostkeys/ssh_host_ed25519_key", "HostKey /etc/ssh/hostkeys/other"),
        (
            "AuthorizedKeysFile /etc/ssh/authorized_keys/%u",
            "AuthorizedKeysFile .ssh/authorized_keys",
        ),
        (
            "ForceCommand /usr/bin/sudo -n /usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-host-agent-launcher.py",
            "ForceCommand /bin/sh",
        ),
    ],
)
def test_insecure_proposed_sshd_mutations_are_rejected(original, replacement):
    source = SSHD_CONFIG.read_text(encoding="ascii")
    assert original in source
    with pytest.raises(AssertionError):
        _check_contract(source.replace(original, replacement))


@pytest.mark.skipif(
    not Path("/usr/sbin/sshd").is_file(),
    reason="sshd binary not present: static contract tests still execute",
)
def test_real_installed_sshd_effective_config_has_no_forwarding():
    # Parses config but does NOT start sshd, open a socket or read a host key.
    result = subprocess.run(
        ["/usr/sbin/sshd", "-G", "-f", str(SSHD_CONFIG)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr[:180]
    effective = _sshd_options(result.stdout)
    assert effective["disableforwarding"] == "yes"
    assert effective["allowstreamlocalforwarding"] == "no"
    assert effective["allowtcpforwarding"] == "no"
    assert effective["permittty"] == "no"
    assert effective["passwordauthentication"] == "no"


def test_duplicate_option_and_unreviewed_match_block_refused():
    source = SSHD_CONFIG.read_text(encoding="ascii")
    with pytest.raises(ValueError, match="duplicate"):
        _check_contract(source + "\nPermitTTY yes\n")
    with pytest.raises(AssertionError):
        _check_contract(source + "\nMatch User root\n")


def test_current_mode_a_overlay_still_cannot_start_reviewed_sudo_handoff():
    # Intentional failing-runtime checkpoint: the checked-in runtime template
    # is render-only. NNP blocks sudo privilege escalation; cap_drop ALL
    # removes the capabilities required by the launcher and manager. Do NOT
    # 'fix' this by loosening Compose without a separately approved ADR.
    class Loader(yaml.SafeLoader):
        pass

    def load_override(loader, node):
        return (
            loader.construct_mapping(node)
            if isinstance(node, yaml.MappingNode)
            else loader.construct_sequence(node)
        )

    Loader.add_constructor("!override", load_override)
    doc = yaml.load((ROOT / "deploy/compose/compose.dev-ssh.yaml").read_text(), Loader=Loader)
    for node in ("node01", "node02"):
        container = doc["services"][node]
        assert container["cap_drop"] == ["ALL"]
        assert container["security_opt"] == ["no-new-privileges:true"]
        assert "cap_add" not in container
        assert "entrypoint" not in container
        assert "command" not in container
