from __future__ import annotations

import os
from pathlib import Path

from .containment import (
    REQUIRED_CGROUP_V2_CONTROLLERS,
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentRequest,
    ContainmentStats,
    ContainmentUnavailableError,
    probe_cgroup_v2,
)

_SCOPE_PREFIX = "ssh-over-mcp-"


def _read_ascii(path: Path, *, purpose: str) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ContainmentError(f"cannot read {purpose}") from exc


def _write_control(
    path: Path,
    value: str,
    *,
    purpose: str,
    unavailable: bool = False,
) -> None:
    error_type = ContainmentUnavailableError if unavailable else ContainmentError
    flags = os.O_WRONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise error_type(f"cannot open {purpose}") from exc

    data = value.encode("ascii")
    offset = 0
    try:
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short cgroup control write")
            offset += written
    except OSError as exc:
        raise error_type(f"cannot write {purpose}") from exc
    finally:
        os.close(fd)


def _parse_flat_keyed(raw: str, *, purpose: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) != 2:
            raise ContainmentError(f"invalid {purpose}")
        key, value = parts
        result[key] = value
    return result


def _parse_nonnegative_int(raw: str, *, purpose: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ContainmentError(f"invalid {purpose}") from exc
    if value < 0:
        raise ContainmentError(f"invalid {purpose}")
    return value


class CgroupV2Handle(ContainmentHandle):
    def __init__(self, scope: Path) -> None:
        self._scope = scope
        self._scope_id = scope.name
        self._closed = False

    @property
    def scope_id(self) -> str:
        return self._scope_id

    @property
    def path(self) -> Path:
        return self._scope

    def _require_open(self) -> None:
        if self._closed:
            raise ContainmentError("containment scope is closed")

    def attach(self, pid: int) -> None:
        self._require_open()
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive integer")

        _write_control(
            self._scope / "cgroup.procs",
            f"{pid}\n",
            purpose="cgroup.procs",
        )

    def kill_all(self) -> None:
        self._require_open()
        _write_control(
            self._scope / "cgroup.kill",
            "1\n",
            purpose="cgroup.kill",
        )

    def stats(self) -> ContainmentStats:
        self._require_open()

        memory_current = _parse_nonnegative_int(
            _read_ascii(
                self._scope / "memory.current",
                purpose="memory.current",
            ),
            purpose="memory.current",
        )
        pids_current = _parse_nonnegative_int(
            _read_ascii(
                self._scope / "pids.current",
                purpose="pids.current",
            ),
            purpose="pids.current",
        )

        cpu_stat = _parse_flat_keyed(
            _read_ascii(self._scope / "cpu.stat", purpose="cpu.stat"),
            purpose="cpu.stat",
        )
        if "usage_usec" not in cpu_stat:
            raise ContainmentError("cpu.stat lacks usage_usec")
        cpu_usage = _parse_nonnegative_int(
            cpu_stat["usage_usec"],
            purpose="cpu.stat usage_usec",
        )

        events = _parse_flat_keyed(
            _read_ascii(
                self._scope / "cgroup.events",
                purpose="cgroup.events",
            ),
            purpose="cgroup.events",
        )
        populated_raw = events.get("populated")
        if populated_raw not in {"0", "1"}:
            raise ContainmentError("cgroup.events lacks valid populated")
        populated = populated_raw == "1"

        return ContainmentStats(
            memory_current_bytes=memory_current,
            pids_current=pids_current,
            cpu_usage_usec=cpu_usage,
            populated=populated,
        )

    def close(self) -> None:
        if self._closed:
            return

        stats = self.stats()
        if stats.populated:
            raise ContainmentError("containment scope is still populated")

        try:
            os.rmdir(self._scope)
        except OSError as exc:
            raise ContainmentError("cannot remove containment scope") from exc

        self._closed = True


class CgroupV2Backend(ContainmentBackend):
    def __init__(
        self,
        root: str | Path,
        *,
        scope_prefix: str = _SCOPE_PREFIX,
    ) -> None:
        root_path = Path(root)
        if not root_path.is_absolute():
            raise ValueError("cgroup root must be absolute")

        try:
            resolved = root_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ContainmentUnavailableError(
                "cgroup root cannot be resolved"
            ) from exc

        if resolved != root_path:
            raise ContainmentUnavailableError(
                "cgroup root must be canonical"
            )
        if "/" in scope_prefix or not scope_prefix:
            raise ValueError("invalid cgroup scope prefix")

        self._root = resolved
        self._scope_prefix = scope_prefix

    @property
    def name(self) -> str:
        return "cgroup-v2"

    @property
    def root(self) -> Path:
        return self._root

    def _enable_required_controllers(self) -> None:
        probe = probe_cgroup_v2(self._root)
        if not probe.ready_for_containment:
            reason = probe.reason or "cgroup v2 is unavailable"
            raise ContainmentUnavailableError(reason)

        subtree_control = self._root / "cgroup.subtree_control"
        try:
            enabled = frozenset(
                subtree_control.read_text(encoding="ascii").split()
            )
        except (OSError, UnicodeError) as exc:
            raise ContainmentUnavailableError(
                "cannot read cgroup.subtree_control"
            ) from exc

        missing = REQUIRED_CGROUP_V2_CONTROLLERS.difference(enabled)
        if missing:
            request = " ".join(f"+{name}" for name in sorted(missing))
            _write_control(
                subtree_control,
                f"{request}\n",
                purpose="cgroup.subtree_control",
                unavailable=True,
            )
            try:
                enabled = frozenset(
                    subtree_control.read_text(encoding="ascii").split()
                )
            except (OSError, UnicodeError) as exc:
                raise ContainmentUnavailableError(
                    "cannot verify cgroup.subtree_control"
                ) from exc

        still_missing = REQUIRED_CGROUP_V2_CONTROLLERS.difference(enabled)
        if still_missing:
            raise ContainmentUnavailableError(
                "required cgroup controllers are not enabled"
            )

    def _create_scope_directory(self, scope: Path) -> None:
        try:
            scope.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ContainmentError(
                "containment scope already exists"
            ) from exc
        except OSError as exc:
            raise ContainmentUnavailableError(
                "cannot create containment scope"
            ) from exc

    def _verify_scope_interfaces(self, scope: Path) -> None:
        required = (
            "cgroup.procs",
            "cgroup.kill",
            "cgroup.events",
            "memory.max",
            "memory.current",
            "pids.max",
            "pids.current",
            "cpu.max",
            "cpu.stat",
        )
        for name in required:
            path = scope / name
            if not path.exists():
                raise ContainmentUnavailableError(
                    f"required cgroup interface is unavailable: {name}"
                )

        for name in (
            "cgroup.procs",
            "cgroup.kill",
            "memory.max",
            "pids.max",
            "cpu.max",
        ):
            if not os.access(scope / name, os.W_OK):
                raise ContainmentUnavailableError(
                    f"required cgroup interface is not writable: {name}"
                )

    def _configure_limits(
        self,
        scope: Path,
        request: ContainmentRequest,
    ) -> None:
        limits = request.limits
        desired = {
            "memory.max": str(limits.memory_max_bytes),
            "pids.max": str(limits.pids_max),
            "cpu.max": f"{limits.cpu_quota_us} {limits.cpu_period_us}",
        }

        for name, value in desired.items():
            _write_control(
                scope / name,
                f"{value}\n",
                purpose=name,
                unavailable=True,
            )

        for name, value in desired.items():
            actual = _read_ascii(scope / name, purpose=name)
            if actual != value:
                raise ContainmentUnavailableError(
                    f"cgroup limit did not apply: {name}"
                )

    def create(self, request: ContainmentRequest) -> CgroupV2Handle:
        self._enable_required_controllers()

        scope = self._root / f"{self._scope_prefix}{request.request_id}"
        self._create_scope_directory(scope)

        try:
            self._verify_scope_interfaces(scope)
            self._configure_limits(scope, request)
        except BaseException:
            try:
                os.rmdir(scope)
            except OSError:
                pass
            raise

        return CgroupV2Handle(scope)
