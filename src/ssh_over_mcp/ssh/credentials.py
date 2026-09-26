from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from pydantic import SecretStr

from .errors import SSHCredentialError


@dataclass(frozen=True, slots=True)
class SSHCredential:
    client_keys: tuple[str, ...]
    client_certs: tuple[str, ...] = ()
    passphrase: SecretStr | None = None

    def __post_init__(self) -> None:
        if not self.client_keys:
            raise ValueError("at least one SSH client key is required")


class CredentialProvider(Protocol):
    async def resolve(self, credential_ref: str) -> SSHCredential: ...


class StaticCredentialProvider:
    """In-memory provider intended for tests and integration adapters."""

    def __init__(self, credentials: Mapping[str, SSHCredential]) -> None:
        self._credentials = dict(credentials)

    async def resolve(self, credential_ref: str) -> SSHCredential:
        try:
            return self._credentials[credential_ref]
        except KeyError as exc:
            raise SSHCredentialError(
                f"unknown SSH credential reference: {credential_ref}"
            ) from exc


class FileCredentialProvider:
    """Resolve refs to pre-mounted private-key files.

    Versioned policy/inventory config stores only a logical credential
    reference. Private key bytes remain outside versioned configuration.
    """

    def __init__(self, mapping: Mapping[str, str | Path]) -> None:
        self._mapping = {ref: Path(path) for ref, path in mapping.items()}

    async def resolve(self, credential_ref: str) -> SSHCredential:
        try:
            path = self._mapping[credential_ref]
        except KeyError as exc:
            raise SSHCredentialError(
                f"unknown SSH credential reference: {credential_ref}"
            ) from exc

        if not path.is_file():
            raise SSHCredentialError(
                f"SSH credential file is unavailable for ref: {credential_ref}"
            )

        return SSHCredential(client_keys=(str(path),))
