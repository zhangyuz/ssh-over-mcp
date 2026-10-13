"""One fixed /private/tmp incident inspection; NO recovery or disposition authority."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from pathlib import Path
from time import monotonic


def _sibling(name: str):
    source = Path(__file__).parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("_private_tmp_" + name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed inspection unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


old_forensic = _sibling("inspect_provider_residuals")
preflight = old_forensic.preflight
inventory = old_forensic.inventory
recovery = old_forensic.recovery
_UID = 502
_SYSTEM_UID = 0
_CATALOG = old_forensic._CATALOG
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
MAX_TOTAL_ENTRIES = 4096
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SECONDS = 420
_REFUSAL_PHASE = "startup"


def _open_root() -> int:
    return os.open("/", _DIR_FLAGS)


def _stat_root():
    return os.stat("/", follow_symlinks=False)


def _validate_context() -> dict[str, str]:
    recovery._validate_context(os.environ)
    values = {
        "authority_sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if (
        os.geteuid() != _UID
        or os.environ.get("GITHUB_WORKFLOW_REF") != (
            "zhangyuz/ssh-over-mcp/.github/workflows/"
            "live-local-e2e-private-tmp-forensic.yml@refs/heads/main"
        )
        or os.environ.get("GITHUB_WORKFLOW_SHA") != values["authority_sha"]
        or re.fullmatch(r"[0-9a-f]{40}", values["authority_sha"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", values["run_id"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,4}", values["run_attempt"]) is None
    ):
        raise preflight.PreflightError()
    return values


@contextmanager
def _pin_private_tmp():
    """Pin literal /private/tmp with a *separate* sticky-parent policy.

    Unlike the getconf staging parent, /private/tmp is root-owned and 01777.
    Sticky parent never licenses access to anything except the three fixed
    UID-502 0700 roots, opened with no-follow component descriptors.
    """
    owned: list[int] = []
    snapshots = []
    parts = ("private", "tmp")
    uncertain = False
    invalid = False
    try:
        root_fd = _open_root()
        owned.append(root_fd)
        original = preflight._metadata(os.fstat(root_fd))
        snapshots.append(original)
        if (
            original != preflight._metadata(_stat_root())
            or original.uid != _SYSTEM_UID
            or original.mode != 0o755
        ):
            raise preflight.PreflightError()
        for name, mode in zip(parts, (0o755, 0o1777), strict=True):
            before = preflight._metadata(os.stat(
                name, dir_fd=owned[-1], follow_symlinks=False,
            ))
            if (
                before.uid != _SYSTEM_UID or before.mode != mode
                or before.device != original.device
            ):
                raise preflight.PreflightError()
            child = os.open(name, _DIR_FLAGS, dir_fd=owned[-1])
            owned.append(child)
            after = preflight._metadata(os.fstat(child))
            if after != before:
                raise preflight.PreflightError()
            snapshots.append(after)
        chain = preflight._PinnedDirectoryChain(tuple(owned), parts, tuple(snapshots))
        yield chain
        chain.revalidate()
    except preflight.PreflightError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, MemoryError):
        raise preflight.PreflightError() from None
    finally:
        # One close per owned descriptor, reverse edge checks after child
        # close, and a final fixed-root snapshot. Never retry ambiguous closes.
        for index in range(len(owned) - 1, -1, -1):
            fd = owned[index]
            try:
                os.close(fd)
            except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
                uncertain = True
            if index > 0:
                try:
                    now = preflight._metadata(os.stat(
                        parts[index - 1], dir_fd=owned[index - 1],
                        follow_symlinks=False,
                    ))
                    if index >= len(snapshots) or now != snapshots[index]:
                        invalid = True
                except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
                    invalid = True
        try:
            if snapshots and preflight._metadata(_stat_root()) != snapshots[0]:
                invalid = True
        except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
            invalid = True
        if uncertain:
            raise preflight.PreflightError(cleanup_uncertain=True) from None
        if invalid:
            raise preflight.PreflightError() from None


def _probe_rejected_inventory(root_fd: int) -> str:
    """Failure-only metadata probe; a later raceable snapshot, never authority.

    Limit traversal, never open regular files, never follow symlinks or print
    names, paths, values or OS exceptions. The strict collector still refuses.
    """
    observed = 0
    deadline = monotonic() + 10
    try:
        root_info = os.fstat(root_fd)
        device = root_info.st_dev
        seen: set[tuple[int, int]] = set()

        def validate(info: os.stat_result) -> str | None:
            identity = (info.st_dev, info.st_ino)
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                return "unsupported-kind"
            if info.st_uid != _UID:
                return "foreign-owner"
            if info.st_dev != device:
                return "foreign-device"
            if stat.S_IMODE(info.st_mode) & 0o022:
                return "unsafe-mode"
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                return "hardlink"
            if identity in seen:
                return "duplicate"
            seen.add(identity)
            return None

        def walk(fd: int, depth: int, path_size: int) -> str:
            nonlocal observed
            if monotonic() > deadline or observed >= 128 or depth > 12:
                return "bounds"
            before = os.fstat(fd)
            invalid = validate(before)
            if invalid:
                return invalid
            observed += 1
            with os.scandir(fd) as entries:
                for item in entries:
                    name = item.name
                    if (
                        type(name) is not str
                        or name in {"", ".", ".."}
                        or "/" in name
                        or "\x00" in name
                    ):
                        return "bounds"
                    size = path_size + len(os.fsencode(name)) + 1
                    if size > 4096 or depth >= 12 or monotonic() > deadline or observed >= 128:
                        return "bounds"
                    child_before = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    invalid = validate(child_before)
                    if invalid:
                        return invalid
                    observed += 1
                    if stat.S_ISDIR(child_before.st_mode):
                        child_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                        try:
                            if os.fstat(child_fd) != child_before:
                                return "unstable"
                            # The directory was validated above; walk checks
                            # it again without treating the second sighting
                            # as a duplicate identity.
                            seen.remove((child_before.st_dev, child_before.st_ino))
                            result = walk(child_fd, depth + 1, size)
                            if result != "unresolved":
                                return result
                        finally:
                            os.close(child_fd)
                    if os.stat(name, dir_fd=fd, follow_symlinks=False) != child_before:
                        return "unstable"
            return "unresolved" if os.fstat(fd) == before else "unstable"

        return walk(root_fd, 0, 0)
    except (OSError, ValueError, TypeError, OverflowError, MemoryError, RuntimeError):
        return "unavailable"


def inspect_residuals() -> bytes:
    """Observe fixed historical roots only; successful evidence denies cleanup."""
    global _REFUSAL_PHASE
    _REFUSAL_PHASE = "context"
    context = _validate_context()
    deadline = monotonic() + MAX_TOTAL_SECONDS

    def check_deadline():
        if monotonic() > deadline:
            raise preflight.PreflightError()

    with ExitStack() as stack:
        _REFUSAL_PHASE = "private-tmp-parent"
        parent = stack.enter_context(_pin_private_tmp())
        _REFUSAL_PHASE = "marker-cache"
        cache = stack.enter_context(preflight._pin_observed_fixed_cache_chain())
        _REFUSAL_PHASE = "marker"
        marker = preflight._read_marker(cache._fds[-1], uid=_UID)
        chains = []
        for index, (name, device, inode) in enumerate(_CATALOG, 1):
            _REFUSAL_PHASE = f"catalog-open-{index}"
            # Pin even beneath sticky 01777. Never relax the child's UID/0700
            # rules or accept a basename as an identity in place of dev/inode.
            chain = stack.enter_context(preflight._pin_directory_chain(
                parent._fds[-1], (name,), ((_UID, (0o700,)),),
                post_close_validate=True,
            ))
            _REFUSAL_PHASE = f"catalog-identity-{index}"
            selected = chain.metadata[-1]
            if (
                (selected.device, selected.inode, selected.uid, selected.mode)
                != (device, inode, _UID, 0o700)
                or selected.device != parent.metadata[-1].device
            ):
                raise preflight.PreflightError()
            chains.append(chain)
        _REFUSAL_PHASE = "process-a"
        preflight._observe_fixed_process_snapshot_checked()
        _REFUSAL_PHASE = "inventory-a"
        original = []
        roots = []
        count = 0
        for index, ((name, _, _), chain) in enumerate(zip(_CATALOG, chains, strict=True), 1):
            _REFUSAL_PHASE = f"inventory-a-{index}"
            check_deadline()
            try:
                entries = inventory.collect_residual_inventory(chain._fds[-1], uid=_UID)
            except inventory.InventoryError:
                _REFUSAL_PHASE = (
                    f"inventory-a-{index}-probe-"
                    + _probe_rejected_inventory(chain._fds[-1])
                )
                raise
            count += len(entries)
            if count > MAX_TOTAL_ENTRIES:
                raise preflight.PreflightError()
            original.append(entries)
            roots.append({
                "name": name,
                "classification": (
                    "directory-only-residual"
                    if all(entry.kind == "directory" for entry in entries)
                    else "nonempty-or-unknown"
                ),
                "entries": [asdict(entry) for entry in entries],
            })
        _REFUSAL_PHASE = "inventory-b"
        for index, (chain, entries) in enumerate(zip(chains, original, strict=True), 1):
            _REFUSAL_PHASE = f"inventory-b-{index}"
            check_deadline()
            if inventory.collect_residual_inventory(chain._fds[-1], uid=_UID) != entries:
                raise preflight.PreflightError()
        _REFUSAL_PHASE = "process-b"
        preflight._observe_fixed_process_snapshot_checked()
        _REFUSAL_PHASE = "final-namespace"
        preflight._revalidate_marker(cache._fds[-1], marker, uid=_UID)
        for chain in reversed(chains):
            chain.revalidate()
        cache.revalidate()
        parent.revalidate()
        check_deadline()
        result = {
            "schema_version": 1,
            "kind": "private-tmp-residual-forensic-inspection",
            "parent": "fixed-private-tmp",
            **context,
            "workflow": "live-local-e2e-private-tmp-forensic.yml",
            "recovery_eligible": False,
            "snapshot_scope": "metadata-only; no process quiescence or cleanup authority",
            "marker": {
                "target": "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
                "owner_pid": 38013,
                "metadata": asdict(marker.metadata),
            },
            "roots": roots,
        }
        _REFUSAL_PHASE = "encode"
        encoded = json.dumps(
            result, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode()
        if len(encoded) + 1 > MAX_EVIDENCE_BYTES:
            raise preflight.PreflightError()
        _REFUSAL_PHASE = "descriptor-close"
    check_deadline()
    _REFUSAL_PHASE = "complete"
    return encoded + b"\n"


def main(argv: list[str] | None = None) -> int:
    if list(sys.argv[1:] if argv is None else argv):
        raise preflight.PreflightError()
    encoded = inspect_residuals()
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):  # noqa: BLE001
        print(
            f"fixed private tmp inspection refused at {_REFUSAL_PHASE}; "
            "no recovery authorized", file=sys.stderr,
        )
        raise SystemExit(70) from None
