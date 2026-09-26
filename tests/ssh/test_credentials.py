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
