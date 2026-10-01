from __future__ import annotations

import select
from collections.abc import Callable
from contextlib import ExitStack
from typing import Self

from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    UnixContainmentManagerListener,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    require_linux_process_identity,
)

from .dispatcher import AdminLedgerDispatcher, ExecutionLedgerDispatcher
from .ledger import SecurityLedgerStore
from .runtime import SecurityLedgerRuntimeSettings
from .storage import LedgerDatabase, load_ledger_hmac_key
from .transport import LedgerTransportError, serve_one_ledger_connection


class SecurityLedgerServiceError(RuntimeError):
    """The Security Ledger daemon lifecycle cannot proceed safely."""


class SecurityLedgerService:
    def __init__(
        self,
        *,
        settings: SecurityLedgerRuntimeSettings,
        database: LedgerDatabase,
        execution_listener: UnixContainmentManagerListener,
        admin_listener: UnixContainmentManagerListener,
        execution_dispatcher: ExecutionLedgerDispatcher,
        admin_dispatcher: AdminLedgerDispatcher,
    ) -> None:
        self._settings = settings
        self._database = database
        self._execution_listener = execution_listener
        self._admin_listener = admin_listener
        self._execution_dispatcher = execution_dispatcher
        self._admin_dispatcher = admin_dispatcher
        self._closed = False

    @classmethod
    def create(
        cls,
        settings: SecurityLedgerRuntimeSettings,
    ) -> SecurityLedgerService:
        # This MUST remain the first side-effecting check in startup.
        require_linux_process_identity(
            settings.process_identity_policy()
        )

        key = load_ledger_hmac_key(settings.storage_settings())
        with ExitStack() as stack:
            database = LedgerDatabase.open(settings.storage_settings())
            stack.callback(database.close)
            store = SecurityLedgerStore(database, key)

            execution_listener = UnixContainmentManagerListener.create(
                settings.execution_endpoint_policy()
            )
            stack.callback(execution_listener.close)

            admin_listener = UnixContainmentManagerListener.create(
                settings.admin_endpoint_policy()
            )
            stack.callback(admin_listener.close)

            service = cls(
                settings=settings,
                database=database,
                execution_listener=execution_listener,
                admin_listener=admin_listener,
                execution_dispatcher=ExecutionLedgerDispatcher(store),
                admin_dispatcher=AdminLedgerDispatcher(store),
            )
            stack.pop_all()
            return service

    def _serve_listener(
        self,
        listener: UnixContainmentManagerListener,
        *,
        peer_policy,
        dispatcher,
    ) -> None:
        connection = listener.accept()
        try:
            try:
                serve_one_ledger_connection(
                    connection,
                    peer_policy=peer_policy,
                    dispatcher=dispatcher,
                )
            except LedgerTransportError:
                # One malformed/unauthorized local connection must not kill
                # the foreground daemon.
                return
        finally:
            connection.close()

    def serve_one(self) -> None:
        if self._closed:
            raise SecurityLedgerServiceError(
                "Security Ledger service is closed"
            )
        try:
            readable, _writable, _exceptional = select.select(
                [
                    self._execution_listener.fileno,
                    self._admin_listener.fileno,
                ],
                [],
                [],
            )
        except (OSError, ValueError):
            raise SecurityLedgerServiceError(
                "cannot poll Security Ledger listeners"
            ) from None

        if self._execution_listener.fileno in readable:
            self._serve_listener(
                self._execution_listener,
                peer_policy=self._settings.execution_peer_policy(),
                dispatcher=self._execution_dispatcher,
            )
            return
        if self._admin_listener.fileno in readable:
            self._serve_listener(
                self._admin_listener,
                peer_policy=self._settings.admin_peer_policy(),
                dispatcher=self._admin_dispatcher,
            )

    def serve_forever(
        self,
        *,
        stop_requested: Callable[[], bool],
    ) -> None:
        if self._closed:
            raise SecurityLedgerServiceError(
                "Security Ledger service is closed"
            )

        while not stop_requested():
            try:
                readable, _writable, _exceptional = select.select(
                    [
                        self._execution_listener.fileno,
                        self._admin_listener.fileno,
                    ],
                    [],
                    [],
                    0.1,
                )
            except InterruptedError:
                continue
            except (OSError, ValueError):
                raise SecurityLedgerServiceError(
                    "cannot poll Security Ledger listeners"
                ) from None
            if stop_requested():
                return
            if self._execution_listener.fileno in readable:
                self._serve_listener(
                    self._execution_listener,
                    peer_policy=self._settings.execution_peer_policy(),
                    dispatcher=self._execution_dispatcher,
                )
            if self._admin_listener.fileno in readable:
                self._serve_listener(
                    self._admin_listener,
                    peer_policy=self._settings.admin_peer_policy(),
                    dispatcher=self._admin_dispatcher,
                )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        first_error: Exception | None = None
        for resource in (
            self._execution_listener,
            self._admin_listener,
            self._database,
        ):
            try:
                resource.close()
            except Exception as exc:  # noqa: BLE001
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
