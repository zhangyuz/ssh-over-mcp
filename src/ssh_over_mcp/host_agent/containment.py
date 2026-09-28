from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Self

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
REQUIRED_CGROUP_V2_CONTROLLERS = frozenset({"cpu", "memory", "pids"})


class ContainmentError(RuntimeError):
    """Base error for descendant-containment operations."""


class ContainmentUnavailableError(ContainmentError):
    """The configured containment backend cannot enforce its contract."""


@dataclass(frozen=True, slots=True)
class ContainmentLimits:
    """Finite cgroup-style ceilings for one execution scope."""

    memory_max_bytes: int
    pids_max: int
    cpu_quota_us: int
    cpu_period_us: int

    def __post_init__(self) -> None:
        values = {
            "memory_max_bytes": self.memory_max_bytes,
            "pids_max": self.pids_max,
            "cpu_quota_us": self.cpu_quota_us,
            "cpu_period_us": self.cpu_period_us,
        }
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

        # Keep absurd configuration values out of backend-specific serializers.
        if self.memory_max_bytes > 1024 * 1024 * 1024 * 1024:
            raise ValueError("memory_max_bytes exceeds contract maximum")
        if self.pids_max > 1_000_000:
            raise ValueError("pids_max exceeds contract maximum")
        if self.cpu_quota_us > 1_000_000_000:
            raise ValueError("cpu_quota_us exceeds contract maximum")
        if not 1_000 <= self.cpu_period_us <= 1_000_000:
            raise ValueError("cpu_period_us is outside supported range")


@dataclass(frozen=True, slots=True)
class ContainmentRequest:
    request_id: str
    limits: ContainmentLimits

    def __post_init__(self) -> None:
        if not _REQUEST_ID_RE.fullmatch(self.request_id):
            raise ValueError("invalid containment request id")


@dataclass(frozen=True, slots=True)
class ContainmentStats:
    """Backend-neutral accounting snapshot."""

    memory_current_bytes: int | None = None
    pids_current: int | None = None
    cpu_usage_usec: int | None = None
    populated: bool | None = None


@dataclass(frozen=True, slots=True)
class CgroupV2Probe:
    root: Path
    unified: bool
    controllers: frozenset[str]
    missing_required: frozenset[str]
    reason: str | None = None

    @property
    def ready_for_containment(self) -> bool:
        return self.unified and not self.missing_required and self.reason is None


class ContainmentHandle(ABC):
    """One prepared descendant-containment scope.

    A concrete handle owns exactly one request scope. attach() moves the initial
    child into that scope; descendants then inherit membership. kill_all()
    must terminate the entire scope subtree, not just the direct child.
    """

    @property
    @abstractmethod
    def scope_id(self) -> str:
        """Opaque backend-owned scope identifier."""

    @abstractmethod
    def attach(self, pid: int) -> None:
        """Attach the initial child process to this scope."""

    @abstractmethod
    def kill_all(self) -> None:
        """Terminate all processes in the scope and descendant scopes."""

    @abstractmethod
    def stats(self) -> ContainmentStats:
        """Read a best-effort accounting snapshot."""

    @abstractmethod
    def close(self) -> None:
        """Release backend resources after the scope is empty."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class ContainmentBackend(ABC):
    """Factory for fail-closed per-request containment scopes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable backend name for logs/audit."""

    @abstractmethod
    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        """Create a scope before the execution child is released."""


def probe_cgroup_v2(
    root: str | Path = "/sys/fs/cgroup",
) -> CgroupV2Probe:
    """Read-only host probe for the cgroup-v2 controllers we require.

    This intentionally does not claim write/delegation capability. A concrete
    backend must separately prove that it can create a child cgroup, enable the
    required controllers, attach a pid, and use cgroup.kill.
    """

    root_path = Path(root)
    controllers_file = root_path / "cgroup.controllers"

    try:
        if not root_path.is_dir():
            return CgroupV2Probe(
                root=root_path,
                unified=False,
                controllers=frozenset(),
                missing_required=REQUIRED_CGROUP_V2_CONTROLLERS,
                reason="cgroup root is not a directory",
            )

        raw = controllers_file.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return CgroupV2Probe(
            root=root_path,
            unified=False,
            controllers=frozenset(),
            missing_required=REQUIRED_CGROUP_V2_CONTROLLERS,
            reason="cgroup v2 controllers file is unavailable",
        )

    controllers = frozenset(raw.split())
    missing = REQUIRED_CGROUP_V2_CONTROLLERS.difference(controllers)
    return CgroupV2Probe(
        root=root_path,
        unified=True,
        controllers=controllers,
        missing_required=frozenset(missing),
        reason=None if not missing else "required cgroup v2 controllers are missing",
    )
