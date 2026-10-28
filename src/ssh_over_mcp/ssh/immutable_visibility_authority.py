"""Inactive, fail-closed central visibility signer for a single immutable release.

This authority is deliberately NOT constructed by the live MCP runtime.
The release controller must own the ingress fence and provide a durable
generation-active predicate. Each host has a separate 32-byte HMAC key.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping

from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    SignedVisibilitySnapshot,
    VisibilitySnapshotV5,
    sign_snapshot,
)
from ssh_over_mcp.policy.engine import PolicyEngine


class VisibilityAuthorityUnavailable(ValueError):
    """No trusted release or signer is available; do not issue a grant."""


class ImmutableVisibilityAuthority:
    """Opt-in authority; no hot reload, no network access and no default keys.

    A production adapter must prove the fence and both host attestations.
    A supplied callback alone is NOT evidence of a durable barrier.
    """

    def __init__(
        self,
        *,
        engine: PolicyEngine,
        epoch: int,
        host_keys: Mapping[str, bytes],
        generation_active: Callable[[], bool],
    ) -> None:
        if type(epoch) is not int or epoch < 1 or not callable(generation_active):
            raise VisibilityAuthorityUnavailable("invalid visibility release")
        if not isinstance(engine, PolicyEngine):
            raise VisibilityAuthorityUnavailable("invalid central policy")
        if not isinstance(host_keys, Mapping) or set(host_keys) != set(engine.inventory.hosts):
            raise VisibilityAuthorityUnavailable("incomplete host signer configuration")
        if any(type(key) is not bytes or len(key) != 32 for key in host_keys.values()):
            raise VisibilityAuthorityUnavailable("invalid host signer configuration")
        values = tuple(host_keys.values())
        if any(hmac.compare_digest(a, b) for i, a in enumerate(values) for b in values[i + 1 :]):
            raise VisibilityAuthorityUnavailable("host signing keys must be independent")
        self.engine = engine
        self._epoch = epoch
        self._policy_sha256 = self._digest()
        self._keys = dict(host_keys)
        self._active = generation_active

    def _digest(self) -> str:
        version = self.engine.policy_version
        if not version.startswith("sha256:") or len(version) != 71:
            raise VisibilityAuthorityUnavailable("central policy digest unavailable")
        return version[7:]

    def _require_active(self, host: str, policy_sha256: str) -> None:
        if (
            host not in self._keys
            or policy_sha256 != self._policy_sha256
            or self._digest() != self._policy_sha256
            or self._active() is not True
        ):
            raise VisibilityAuthorityUnavailable("visibility release inactive")

    def current_epoch(self, *, host: str, policy_sha256: str) -> int:
        self._require_active(host, policy_sha256)
        return self._epoch

    def sign(self, snapshot: VisibilitySnapshotV5) -> SignedVisibilitySnapshot:
        if not isinstance(snapshot, VisibilitySnapshotV5):
            raise VisibilityAuthorityUnavailable("invalid visibility request")
        self._require_active(snapshot.host, snapshot.central_policy_sha256)
        if snapshot.policy_epoch != self._epoch:
            raise VisibilityAuthorityUnavailable("visibility epoch changed")
        if snapshot.host_key_sha256 != self._pinned_host_digest(snapshot.host):
            raise VisibilityAuthorityUnavailable("host key identity changed")
        return sign_snapshot(snapshot, key=self._keys[snapshot.host])

    def _pinned_host_digest(self, host: str) -> str:
        from ssh_over_mcp.ssh.filesystem_list_v2 import pinned_host_identity

        return pinned_host_identity(self.engine.inventory.hosts[host].host_key)

    def is_active(self, snapshot: VisibilitySnapshotV5) -> bool:
        try:
            return (
                isinstance(snapshot, VisibilitySnapshotV5)
                and snapshot.policy_epoch == self._epoch
                and snapshot.host_key_sha256 == self._pinned_host_digest(snapshot.host)
                and self._check_active(snapshot)
            )
        except Exception:  # noqa: BLE001 - trusted callback failures deny authority
            return False

    def _check_active(self, snapshot: VisibilitySnapshotV5) -> bool:
        self._require_active(snapshot.host, snapshot.central_policy_sha256)
        return True
