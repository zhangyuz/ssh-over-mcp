"""ADR 0019 Slice 2A: explicitly UNBOUND production workspace lifecycle.

No provider marker ownership or run-reap authority is issued here.
Importing or calling this module never creates/removes staging directories.
"""

from __future__ import annotations

from staging_namespace_types import NamespaceError


def create_owned_workspace() -> None:
    """Refuse until a separately reviewed original O_EXCL-claim issuer exists."""
    raise NamespaceError("unbound")


class OwnedWorkspace:
    """Reserved, never-instantiable live handle; no QEMU completion issuer exists."""

    def __init__(self) -> None:
        raise NamespaceError("unbound")

    def dispose(self, receipt: object) -> None:
        """Live deletion remains forbidden, including for truthy/forged receipts."""
        raise NamespaceError("unbound")

    def close(self) -> None:
        """No owned descriptors exist in dormant Slice 2A."""
