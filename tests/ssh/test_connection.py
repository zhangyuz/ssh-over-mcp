import base64

import pytest

from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.ssh.connection import SSHConnectionManager
from ssh_over_mcp.ssh.credentials import (
    SSHCredential,
    StaticCredentialProvider,
)


class Connection:
    def __init__(self):
        self.closed = False

    def is_closed(self):
        return self.closed

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def inventory() -> Inventory:
    key = "ssh-ed25519 " + base64.b64encode(b"key").decode()
    return Inventory(
        hosts={
            "dev01": Host(
                address="10.0.0.1",
                ssh_user="mcp",
                credential_ref="secret://dev",
                host_key=key,
            )
        }
    )


@pytest.mark.asyncio
async def test_connection_is_pinned_and_hardened():
    creds = StaticCredentialProvider(
        {
            "secret://dev": SSHCredential(
                client_keys=("/run/key",)
            )
        }
    )
    calls = []

    async def connector(host, **kwargs):
        calls.append((host, kwargs))
        return Connection()

    manager = SSHConnectionManager(
        inventory=inventory(),
        credentials=creds,
        connector=connector,
    )

    first = await manager.get_connection("dev01")
    second = await manager.get_connection("dev01")

    assert first is second
    assert len(calls) == 1

    host, kwargs = calls[0]
    assert host == "10.0.0.1"
    assert kwargs["known_hosts"].startswith(b"dev01 ssh-ed25519 ")
    assert kwargs["client_keys"] == [("/run/key", None)]
    assert kwargs["client_certs"] == []
    assert kwargs["host_key_alias"] == "dev01"
    assert kwargs["config"] is None
    assert kwargs["agent_path"] is None
    assert kwargs["agent_forwarding"] is False
    assert kwargs["password_auth"] is False
    assert kwargs["kbdint_auth"] is False
    assert kwargs["gss_auth"] is False
    assert kwargs["gss_kex"] is False
    assert kwargs["x509_trusted_certs"] is None
    assert kwargs["x509_trusted_cert_paths"] == []
    assert kwargs["disable_trivial_auth"] is True

    await manager.close()
    assert first.closed


@pytest.mark.asyncio
async def test_closed_connection_is_replaced():
    creds = StaticCredentialProvider(
        {
            "secret://dev": SSHCredential(
                client_keys=("/run/key",)
            )
        }
    )
    made = []

    async def connector(host, **kwargs):
        connection = Connection()
        made.append(connection)
        return connection

    manager = SSHConnectionManager(
        inventory=inventory(),
        credentials=creds,
        connector=connector,
    )

    first = await manager.get_connection("dev01")
    first.closed = True
    second = await manager.get_connection("dev01")

    assert first is not second
    assert len(made) == 2
