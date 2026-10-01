from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from ssh_over_mcp.inventory.models import Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.ssh import (
    FileCredentialProvider,
    SSHConnectionManager,
    SSHExecutor,
    SSHFilesystemClient,
)
from ssh_over_mcp.ssh.transport import StructuredSSHTransport

from .errors import RuntimeConfigurationError


class _CredentialMapDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    credentials: dict[str, Path]

    @field_validator("credentials")
    @classmethod
    def validate_credentials(
        cls,
        value: dict[str, Path],
    ) -> dict[str, Path]:
        if not value:
            raise ValueError("credential map must not be empty")

        for credential_ref, key_path in value.items():
            if not credential_ref or credential_ref != credential_ref.strip():
                raise ValueError("credential reference is invalid")
            if not key_path.is_absolute() or not key_path.is_file():
                raise ValueError("credential key path is invalid")
        return value


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: yaml.Loader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError("duplicate credential-map key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclass(frozen=True, slots=True)
class SSHRuntime:
    credentials: FileCredentialProvider
    connections: SSHConnectionManager
    transport: StructuredSSHTransport
    executor: SSHExecutor
    filesystem: SSHFilesystemClient


def _validate_mapping(
    credential_map: Mapping[str, Path],
) -> dict[str, Path]:
    try:
        document = _CredentialMapDocument(
            credentials=dict(credential_map),
        )
    except (TypeError, ValueError, ValidationError):
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from None
    return dict(document.credentials)


def load_credential_map(path: str | Path) -> dict[str, Path]:
    credential_map_path = Path(path)

    try:
        raw_text = credential_map_path.read_text(encoding="utf-8")
        suffix = credential_map_path.suffix.lower()
        if suffix in {".yaml", ".yml"}:
            raw = yaml.load(raw_text, Loader=_UniqueKeyLoader)
        elif suffix == ".json":
            raw = json.loads(raw_text)
        else:
            raise ValueError("unsupported credential-map format")

        document = _CredentialMapDocument.model_validate(raw)
    except (
        OSError,
        TypeError,
        ValueError,
        yaml.YAMLError,
        json.JSONDecodeError,
        ValidationError,
    ):
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        ) from None

    return dict(document.credentials)


def build_ssh_runtime(
    *,
    inventory: Inventory,
    policy: PolicyEngine,
    credential_map: Mapping[str, Path],
) -> SSHRuntime:
    validated = _validate_mapping(credential_map)
    required_refs = {
        host.credential_ref
        for host in inventory.hosts.values()
    }
    if not required_refs.issubset(validated):
        raise RuntimeConfigurationError(
            "runtime configuration is invalid"
        )

    credentials = FileCredentialProvider(validated)
    connections = SSHConnectionManager(
        inventory=inventory,
        credentials=credentials,
    )
    transport = StructuredSSHTransport(connections=connections)
    executor = SSHExecutor(
        policy=policy,
        connections=connections,
        transport=transport,
    )
    filesystem = SSHFilesystemClient(
        policy=policy,
        transport=transport,
    )
    return SSHRuntime(
        credentials=credentials,
        connections=connections,
        transport=transport,
        executor=executor,
        filesystem=filesystem,
    )
