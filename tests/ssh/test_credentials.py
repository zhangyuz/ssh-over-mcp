import pytest

from ssh_over_mcp.ssh.credentials import (
    SSHCredential,
    StaticCredentialProvider,
)
from ssh_over_mcp.ssh.errors import SSHCredentialError


@pytest.mark.asyncio
async def test_unknown_credential_ref_fails_closed():
    provider = StaticCredentialProvider({})

    with pytest.raises(SSHCredentialError):
        await provider.resolve("secret://missing")


def test_credential_requires_explicit_client_key():
    with pytest.raises(ValueError):
        SSHCredential(client_keys=())


def test_certificate_count_must_match_key_count():
    with pytest.raises(ValueError):
        SSHCredential(
            client_keys=("/run/key-a", "/run/key-b"),
            client_certs=("/run/key-a-cert.pub",),
        )


def test_key_without_certificate_is_explicitly_paired_with_none():
    credential = SSHCredential(client_keys=("/run/key",))
    assert credential.explicit_keypairs() == [("/run/key", None)]
