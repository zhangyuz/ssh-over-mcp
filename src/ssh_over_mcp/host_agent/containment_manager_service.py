from __future__ import annotations

from .containment import ContainmentError
from .containment_manager import ContainmentManagerDispatcher
from .containment_manager_endpoint import (
    UnixContainmentManagerListener,
    UnixManagerEndpointPolicy,
)
from .containment_manager_identity import (
    LinuxProcessIdentityPolicy,
    require_linux_process_identity,
)
from .containment_manager_peer import LinuxPeerCredentialPolicy


class ContainmentManagerServiceError(ContainmentError):
    """The containment-manager service lifecycle cannot proceed safely."""


class ContainmentManagerService:
    """Foreground lifecycle owner for the local containment-manager endpoint."""

    def __init__(
        self,
        *,
        listener: UnixContainmentManagerListener,
        peer_policy: LinuxPeerCredentialPolicy,
        dispatcher: ContainmentManagerDispatcher,
    ) -> None:
        self._listener = listener
        self._peer_policy = peer_policy
        self._dispatcher = dispatcher
        self._closed = False

    @classmethod
    def create(
        cls,
        *,
        identity_policy: LinuxProcessIdentityPolicy,
        endpoint_policy: UnixManagerEndpointPolicy,
        peer_policy: LinuxPeerCredentialPolicy,
        dispatcher: ContainmentManagerDispatcher,
    ) -> "ContainmentManagerService":
        require_linux_process_identity(identity_policy)
        listener = UnixContainmentManagerListener.create(endpoint_policy)
        return cls(
            listener=listener,
            peer_policy=peer_policy,
            dispatcher=dispatcher,
        )

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._listener.close()
