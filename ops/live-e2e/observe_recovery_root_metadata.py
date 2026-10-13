"""Fixed recovery residual observer: no-follow metadata, never cleanup authority."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from time import monotonic


def _sibling(name: str):
    path = Path(__file__).parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("_root_observe_" + name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed observer unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


private_tmp = _sibling("inspect_private_tmp_residuals")
preflight = private_tmp.preflight
inventory = private_tmp.inventory
recovery = private_tmp.recovery
_UID = 502
_CATALOG = private_tmp._CATALOG[1]
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
MAX_ENTRIES = 4096
MAX_DEPTH = 64
MAX_PATH_BYTES = 4096
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SECONDS = 420
MAX_PASS_SECONDS = 60
_REFUSAL_PHASE = "startup"
_COLLECT_PHASE = "start"


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
            "live-local-e2e-recovery-root-observe.yml@refs/heads/main"
        )
        or os.environ.get("GITHUB_WORKFLOW_SHA") != values["authority_sha"]
        or re.fullmatch(r"[0-9a-f]{40}", values["authority_sha"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", values["run_id"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,4}", values["run_attempt"]) is None
    ):
        raise preflight.PreflightError()
    return values


def _kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    return "other"


def _record(path: str, info: os.stat_result) -> dict[str, int | str]:
    return {
        "path": path,
        "kind": _kind(info.st_mode),
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _path_violation_kind(path: str) -> str:
    """Fixed refusal-only taxonomy for an already-rejected relative path.

    Never return the path, an exception, or an observed component.
    """
    try:
        if (
            type(path) is not str
            or not path
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            return "invalid"
        if len(path.split("/")) > MAX_DEPTH:
            return "depth"
        if len(path) > MAX_PATH_BYTES:
            return "bytes"
        if len(os.fsencode(path)) > MAX_PATH_BYTES:
            return "bytes"
    except (OSError, ValueError, TypeError, UnicodeError, MemoryError):
        return "unavailable"
    return "unresolved"


def _observe_path_key(path: str) -> None:
    """Observer-only finite path envelope; no effect on staging eligibility."""
    if (
        type(path) is not str
        or not path
        or len(path) > MAX_PATH_BYTES
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or len(path.split("/")) > MAX_DEPTH
        or len(os.fsencode(path)) > MAX_PATH_BYTES
    ):
        raise preflight.PreflightError()


def _collect_special_metadata(root_fd: int, *, uid: int) -> tuple[dict[str, int | str], ...]:
    """Borrow pinned root FD; collect no-follow node metadata only.

    All directories must be safe to enter. Symlink and special *leaves*
    are observed via stat(follow_symlinks=False), never opened or resolved.
    """
    global _COLLECT_PHASE
    _COLLECT_PHASE = "root-fstat"
    entries: list[dict[str, int | str]] = []
    started = monotonic()
    used_bytes = 32
    discovered = 1  # The root itself; reserve every child before stat.
    try:
        root_dev = os.fstat(root_fd).st_dev

        def append(path: str, info: os.stat_result) -> None:
            nonlocal used_bytes
            global _COLLECT_PHASE
            _COLLECT_PHASE = "entry-budget"
            if monotonic() - started > MAX_PASS_SECONDS or len(entries) >= MAX_ENTRIES:
                raise preflight.PreflightError()
            entry = _record(path, info)
            used_bytes += len(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()) + 1
            if used_bytes > MAX_EVIDENCE_BYTES:
                raise preflight.PreflightError()
            entries.append(entry)

        def walk(fd: int, relative: str, depth: int) -> None:
            nonlocal discovered
            global _COLLECT_PHASE
            _COLLECT_PHASE = "directory-budget"
            if monotonic() - started > MAX_PASS_SECONDS or depth > MAX_DEPTH:
                raise preflight.PreflightError()
            _COLLECT_PHASE = "directory-fstat"
            original = os.fstat(fd)
            _COLLECT_PHASE = "directory-policy"
            if (
                not stat.S_ISDIR(original.st_mode)
                or original.st_uid != uid
                or original.st_dev != root_dev
                or stat.S_IMODE(original.st_mode) & 0o022
            ):
                raise preflight.PreflightError()
            append(relative, original)
            observed: dict[str, os.stat_result] = {}
            _COLLECT_PHASE = "entry-enumeration"
            with os.scandir(fd) as iterator:
                for child in iterator:
                    name = child.name
                    child_path = name if relative == "." else relative + "/" + name
                    # This separate metadata-only observer has its own
                    # finite depth envelope. Strict staging remains at 12.
                    _COLLECT_PHASE = "entry-path"
                    try:
                        _observe_path_key(child_path)
                    except preflight.PreflightError:
                        _COLLECT_PHASE = "entry-path-" + _path_violation_kind(child_path)
                        raise
                    _COLLECT_PHASE = "entry-budget"
                    if (
                        discovered >= MAX_ENTRIES or name in observed
                        or monotonic() - started > MAX_PASS_SECONDS
                    ):
                        raise preflight.PreflightError()
                    discovered += 1
                    _COLLECT_PHASE = "entry-stat"
                    observed[name] = os.stat(name, dir_fd=fd, follow_symlinks=False)
            for name in sorted(observed, key=os.fsencode):
                first = observed[name]
                child_path = name if relative == "." else relative + "/" + name
                if stat.S_ISDIR(first.st_mode):
                    if depth >= MAX_DEPTH:
                        raise preflight.PreflightError()
                    _COLLECT_PHASE = "directory-open"
                    child_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                    try:
                        _COLLECT_PHASE = "directory-identity"
                        if _record(child_path, os.fstat(child_fd)) != _record(child_path, first):
                            raise preflight.PreflightError()
                        walk(child_fd, child_path, depth + 1)
                    finally:
                        try:
                            os.close(child_fd)
                        except (OSError, ValueError, TypeError, RuntimeError, MemoryError):
                            raise preflight.PreflightError(cleanup_uncertain=True) from None
                else:
                    # Never open a regular/symlink/FIFO/socket/device leaf.
                    append(child_path, first)
                _COLLECT_PHASE = "entry-changed"
                if _record(
                    child_path, os.stat(name, dir_fd=fd, follow_symlinks=False),
                ) != _record(child_path, first):
                    raise preflight.PreflightError()
            _COLLECT_PHASE = "directory-changed"
            # Compare published fields: reads may change atime; raw tuple equality
            # can miss nanosecond mtime/ctime drift.
            if _record(relative, os.fstat(fd)) != _record(relative, original):
                raise preflight.PreflightError()

        walk(root_fd, ".", 0)
        return tuple(sorted(entries, key=lambda x: os.fsencode(str(x["path"]))))
    except preflight.PreflightError:
        raise
    except (inventory.InventoryError, OSError, ValueError, TypeError, OverflowError, MemoryError):
        raise preflight.PreflightError() from None


def observe_recovery_root() -> bytes:
    """A complete stable *observation*, never staging/recovery eligibility."""
    global _REFUSAL_PHASE
    _REFUSAL_PHASE = "context"
    context = _validate_context()
    started = monotonic()

    def check_time():
        if monotonic() - started > MAX_TOTAL_SECONDS:
            raise preflight.PreflightError()

    with ExitStack() as stack:
        _REFUSAL_PHASE = "private-tmp-parent"
        parent = stack.enter_context(private_tmp._pin_private_tmp())
        _REFUSAL_PHASE = "marker-cache"
        cache = stack.enter_context(preflight._pin_observed_fixed_cache_chain())
        _REFUSAL_PHASE = "marker"
        marker = preflight._read_marker(cache._fds[-1], uid=_UID)
        _REFUSAL_PHASE = "catalog"
        name, device, inode = _CATALOG
        chain = stack.enter_context(preflight._pin_directory_chain(
            parent._fds[-1], (name,), ((_UID, (0o700,)),),
            post_close_validate=True,
        ))
        root = chain.metadata[-1]
        if (
            (root.device, root.inode, root.uid, root.mode)
            != (device, inode, _UID, 0o700)
            or root.device != parent.metadata[-1].device
        ):
            raise preflight.PreflightError()
        _REFUSAL_PHASE = "process-a"
        preflight._observe_fixed_process_snapshot_checked()
        _REFUSAL_PHASE = "inventory-a"
        try:
            first = _collect_special_metadata(chain._fds[-1], uid=_UID)
        except preflight.PreflightError:
            _REFUSAL_PHASE = "inventory-a-" + _COLLECT_PHASE
            raise
        check_time()
        _REFUSAL_PHASE = "inventory-b"
        try:
            second = _collect_special_metadata(chain._fds[-1], uid=_UID)
        except preflight.PreflightError:
            _REFUSAL_PHASE = "inventory-b-" + _COLLECT_PHASE
            raise
        if second != first:
            raise preflight.PreflightError()
        check_time()
        _REFUSAL_PHASE = "process-b"
        preflight._observe_fixed_process_snapshot_checked()
        _REFUSAL_PHASE = "final-namespace"
        preflight._revalidate_marker(cache._fds[-1], marker, uid=_UID)
        chain.revalidate()
        cache.revalidate()
        parent.revalidate()
        check_time()
        _REFUSAL_PHASE = "encode"
        result = {
            "schema_version": 1,
            "kind": "recovery-root-special-node-observation",
            "workflow": "live-local-e2e-recovery-root-observe.yml",
            **context,
            "catalog_identity": {"device": device, "inode": inode, "uid": _UID, "mode": 0o700},
            "recovery_eligible": False,
            "snapshot_scope": "metadata-only; no link target or file contents",
            "process_evidence": "two bounded executable-name snapshots; not exclusive quiescence",
            "marker": {
                "target": "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
                "owner_pid": 38013,
                "metadata": asdict(marker.metadata),
            },
            "entries": first,
        }
        encoded = json.dumps(
            result, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode()
        if len(encoded) + 1 > MAX_EVIDENCE_BYTES:
            raise preflight.PreflightError()
        _REFUSAL_PHASE = "descriptor-close"
    check_time()
    _REFUSAL_PHASE = "complete"
    return encoded + b"\n"


def main(argv: list[str] | None = None) -> int:
    if list(sys.argv[1:] if argv is None else argv):
        raise preflight.PreflightError()
    evidence = observe_recovery_root()
    sys.stdout.buffer.write(evidence)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):  # noqa: BLE001
        print(
            f"recovery root observation refused at {_REFUSAL_PHASE}; "
            "no disposition authorized", file=sys.stderr,
        )
        raise SystemExit(70) from None
