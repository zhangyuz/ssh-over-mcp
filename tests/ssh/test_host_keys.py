import base64

import pytest

from ssh_over_mcp.ssh.errors import SSHHostKeyVerificationError
from ssh_over_mcp.ssh.host_keys import build_pinned_known_hosts

KEY = "ssh-ed25519 " + base64.b64encode(b"fake-key-material").decode()


def test_pinned_known_hosts_uses_alias():
    assert build_pinned_known_hosts("dev01", KEY) == (
        f"dev01 {KEY}\n".encode()
    )


def test_host_key_newline_injection_rejected():
    with pytest.raises(SSHHostKeyVerificationError):
        build_pinned_known_hosts("dev01", KEY + "\nevil " + KEY)


def test_alias_pattern_injection_rejected():
    with pytest.raises(SSHHostKeyVerificationError):
        build_pinned_known_hosts("*", KEY)
