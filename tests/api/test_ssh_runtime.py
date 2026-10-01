from __future__ import annotations

import importlib
import traceback
from pathlib import Path

import pytest

from ssh_over_mcp.api.errors import RuntimeConfigurationError
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import PolicyDocument, RoleSpec
from ssh_over_mcp.ssh import (
    FileCredentialProvider,
    SSHConnectionManager,
    SSHExecutor,
    SSHFilesystemClient,
)
from ssh_over_mcp.ssh.transport import StructuredSSHTransport


def _ssh_runtime():
    return importlib.import_module("ssh_over_mcp.api.ssh_runtime")


def _inventory() -> Inventory:
    return Inventory(
        hosts={
            "host-a": Host(
                address="10.0.0.1",
                port=22,
                ssh_user="mcp",
                credential_ref="secret://host-a",
                host_key="ssh-ed25519 AAAATEST",
                allowed_roles=frozenset({"developer"}),
            )
        }
    )


def _policy(inventory: Inventory) -> PolicyEngine:
    document = PolicyDocument(
        roles={"developer": RoleSpec()},
        rules=(),
    )
    return PolicyEngine(inventory=inventory, policy=document)


def _write_key(tmp_path: Path, name: str = "host-a.key") -> Path:
    path = tmp_path / name
    path.write_text("test-key-material", encoding="utf-8")
    return path


def _write_map(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "credentials.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_load_credential_map_accepts_absolute_existing_key_files(tmp_path: Path) -> None:
    key_path = _write_key(tmp_path)
    path = _write_map(
        tmp_path,
        "credentials:\n"
        f'  "secret://host-a": "{key_path}"\n',
    )

    mapping = _ssh_runtime().load_credential_map(path)

    assert mapping == {"secret://host-a": key_path}


@pytest.mark.parametrize(
    "body",
    [
        (
            "credentials:\n"
            '  "secret://host-a": "relative.key"\n'
        ),
        (
            "credentials:\n"
            '  "secret://host-a": "/missing/key"\n'
        ),
        (
            "credentials:\n"
            '  "secret://host-a": "/tmp/key"\n'
            "private_key: SUPERSECRET\n"
        ),
        (
            "credentials:\n"
            '  "secret://host-a":\n'
            "    path: /tmp/key\n"
            "    private_key: SUPERSECRET\n"
        ),
    ],
)
def test_load_credential_map_rejects_invalid_shape_without_echoing_secrets(
    tmp_path: Path,
    body: str,
) -> None:
    path = _write_map(tmp_path, body)

    with pytest.raises(
        RuntimeConfigurationError,
        match="runtime configuration is invalid",
    ) as exc_info:
        _ssh_runtime().load_credential_map(path)

    message = str(exc_info.value)
    assert "SUPERSECRET" not in message
    assert "secret://host-a" not in message
    assert "/missing/key" not in message


def test_credential_map_failure_traceback_does_not_echo_sensitive_input(
    tmp_path: Path,
) -> None:
    path = _write_map(
        tmp_path,
        "credentials:\n"
        '  "secret://host-a": "/tmp/key"\n'
        "private_key: SUPERSECRET\n",
    )

    try:
        _ssh_runtime().load_credential_map(path)
    except RuntimeConfigurationError as exc:
        rendered = "".join(traceback.format_exception(exc))
    else:
        raise AssertionError("invalid credential map must fail closed")

    assert "SUPERSECRET" not in rendered
    assert "secret://host-a" not in rendered
    assert "/tmp/key" not in rendered


def test_build_ssh_runtime_requires_mapping_for_every_inventory_ref(
    tmp_path: Path,
) -> None:
    key_path = _write_key(tmp_path, "other.key")
    inventory = _inventory()

    with pytest.raises(
        RuntimeConfigurationError,
        match="runtime configuration is invalid",
    ):
        _ssh_runtime().build_ssh_runtime(
            inventory=inventory,
            policy=_policy(inventory),
            credential_map={"secret://other": key_path},
        )


def test_build_ssh_runtime_constructs_existing_hardened_components_without_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = _write_key(tmp_path)
    inventory = _inventory()
    calls = {"resolve": 0, "connect": 0}

    async def forbidden_resolve(self, credential_ref: str):
        calls["resolve"] += 1
        raise AssertionError("composition must not resolve credentials")

    async def forbidden_connect(self, alias: str):
        calls["connect"] += 1
        raise AssertionError("composition must not open SSH")

    monkeypatch.setattr(FileCredentialProvider, "resolve", forbidden_resolve)
    monkeypatch.setattr(SSHConnectionManager, "get_connection", forbidden_connect)

    runtime = _ssh_runtime().build_ssh_runtime(
        inventory=inventory,
        policy=_policy(inventory),
        credential_map={"secret://host-a": key_path},
    )

    assert isinstance(runtime.credentials, FileCredentialProvider)
    assert isinstance(runtime.connections, SSHConnectionManager)
    assert isinstance(runtime.executor, SSHExecutor)
    assert calls == {"resolve": 0, "connect": 0}


def test_build_ssh_runtime_shares_one_structured_transport(tmp_path: Path) -> None:
    key_path = _write_key(tmp_path)
    inventory = _inventory()

    runtime = _ssh_runtime().build_ssh_runtime(
        inventory=inventory,
        policy=_policy(inventory),
        credential_map={"secret://host-a": key_path},
    )

    assert isinstance(runtime.transport, StructuredSSHTransport)
    assert runtime.executor.transport is runtime.transport
    assert runtime.transport.connections is runtime.connections


def test_build_ssh_runtime_shares_transport_with_filesystem_client(
    tmp_path: Path,
) -> None:
    key_path = _write_key(tmp_path)
    inventory = _inventory()

    runtime = _ssh_runtime().build_ssh_runtime(
        inventory=inventory,
        policy=_policy(inventory),
        credential_map={"secret://host-a": key_path},
    )

    assert isinstance(runtime.filesystem, SSHFilesystemClient)
    assert runtime.filesystem.transport is runtime.transport
    assert runtime.filesystem.policy is runtime.executor.policy
