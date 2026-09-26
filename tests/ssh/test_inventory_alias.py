import base64

import pytest
from pydantic import ValidationError

from ssh_over_mcp.inventory.models import Host, Inventory


def test_known_hosts_metacharacters_rejected_in_alias():
    key = "ssh-ed25519 " + base64.b64encode(b"key").decode()

    with pytest.raises(ValidationError):
        Inventory(
            hosts={
                "*": Host(
                    address="10.0.0.1",
                    ssh_user="mcp",
                    credential_ref="ref",
                    host_key=key,
                )
            }
        )
