from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ssh_over_mcp.inventory.models import Inventory

from .credentials import CredentialProvider
from .errors import (
    SSHConnectionError,
    SSHCredentialError,
    SSHHostKeyVerificationError,
)
from .host_keys import build_pinned_known_hosts

Connector = Callable[..., Awaitable[Any]]


async def _asyncssh_connect(host: str, **kwargs: Any) -> Any:
    import asyncssh

    return await asyncssh.connect(host, **kwargs)


@dataclass(slots=True)
class _PoolEntry:
    connection: Any
    created_at: float


class SSHConnectionManager:
    """Open and pool hardened SSH connections by inventory alias."""

    def __init__(
        self,
        *,
        inventory: Inventory,
        credentials: CredentialProvider,
        connector: Connector | None = None,
        connect_timeout_seconds: float = 10.0,
        login_timeout_seconds: float = 15.0,
        keepalive_interval_seconds: float = 30.0,
        keepalive_count_max: int = 3,
        max_connection_age_seconds: float = 900.0,
        max_sessions_per_host: int = 4,
    ) -> None:
        if max_sessions_per_host <= 0:
            raise ValueError("max_sessions_per_host must be positive")

        self.inventory = inventory
        self.credentials = credentials
        self._connector = connector or _asyncssh_connect
        self.connect_timeout_seconds = connect_timeout_seconds
        self.login_timeout_seconds = login_timeout_seconds
        self.keepalive_interval_seconds = keepalive_interval_seconds
        self.keepalive_count_max = keepalive_count_max
        self.max_connection_age_seconds = max_connection_age_seconds

        self._pool: dict[str, _PoolEntry] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._slots = {
            alias: asyncio.Semaphore(max_sessions_per_host)
            for alias in inventory.hosts
        }

    def _lock_for(self, alias: str) -> asyncio.Lock:
        return self._locks.setdefault(alias, asyncio.Lock())

    def session_slot(self, alias: str) -> asyncio.Semaphore:
        try:
            return self._slots[alias]
        except KeyError as exc:
            raise SSHConnectionError(f"unknown host alias: {alias}") from exc

    def _connection_usable(self, entry: _PoolEntry) -> bool:
        if (
            time.monotonic() - entry.created_at
            >= self.max_connection_age_seconds
        ):
            return False

        try:
            return not bool(entry.connection.is_closed())
        except Exception:
            return False

    async def get_connection(self, alias: str) -> Any:
        try:
            host = self.inventory.hosts[alias]
        except KeyError as exc:
            raise SSHConnectionError(
                f"unknown host alias: {alias}"
            ) from exc

        async with self._lock_for(alias):
            entry = self._pool.get(alias)
            if entry and self._connection_usable(entry):
                return entry.connection

            if entry:
                await self._close_connection(entry.connection)
                self._pool.pop(alias, None)

            try:
                credential = await self.credentials.resolve(
                    host.credential_ref
                )
            except SSHCredentialError:
                raise
            except Exception as exc:
                raise SSHCredentialError(
                    "failed to resolve SSH credential ref: "
                    f"{host.credential_ref}"
                ) from exc

            known_hosts = build_pinned_known_hosts(alias, host.host_key)
            passphrase = (
                credential.passphrase.get_secret_value()
                if credential.passphrase
                else None
            )

            kwargs = dict(
                port=host.port,
                username=host.ssh_user,
                client_keys=credential.explicit_keypairs(),
                client_certs=[],
                passphrase=passphrase,
                known_hosts=known_hosts,
                host_key_alias=alias,
                # Never inherit ~/.ssh/config, ProxyCommand, IdentityAgent, etc.
                config=None,
                # Prevent ambient ssh-agent credentials from being used.
                agent_path=None,
                agent_forwarding=False,
                password_auth=False,
                kbdint_auth=False,
                host_based_auth=False,
                x509_trusted_certs=None,
                x509_trusted_cert_paths=[],
                gss_auth=False,
                gss_kex=False,
                public_key_auth=True,
                preferred_auth=("publickey",),
                # Reject "none" or other trivial authentication.
                disable_trivial_auth=True,
                connect_timeout=self.connect_timeout_seconds,
                login_timeout=self.login_timeout_seconds,
                keepalive_interval=self.keepalive_interval_seconds,
                keepalive_count_max=self.keepalive_count_max,
            )

            try:
                connection = await self._connector(
                    host.address, **kwargs
                )
            except Exception as exc:
                if _is_asyncssh_host_key_error(exc):
                    raise SSHHostKeyVerificationError(
                        f"SSH host key verification failed for {alias}"
                    ) from exc
                raise SSHConnectionError(
                    f"SSH connection failed for {alias}"
                ) from exc

            self._pool[alias] = _PoolEntry(
                connection=connection,
                created_at=time.monotonic(),
            )
            return connection

    async def invalidate(self, alias: str) -> None:
        async with self._lock_for(alias):
            entry = self._pool.pop(alias, None)
            if entry:
                await self._close_connection(entry.connection)

    async def close(self) -> None:
        entries = list(self._pool.values())
        self._pool.clear()
        for entry in entries:
            await self._close_connection(entry.connection)

    @staticmethod
    async def _close_connection(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            return

        try:
            result = connection.wait_closed()
            if inspect.isawaitable(result):
                await result
        except Exception:
            pass


def _is_asyncssh_host_key_error(exc: BaseException) -> bool:
    try:
        import asyncssh
    except ImportError:
        return exc.__class__.__name__ == "HostKeyNotVerifiable"

    return isinstance(exc, asyncssh.HostKeyNotVerifiable)
