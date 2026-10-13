"""Fixed incident forensic inspection; metadata evidence is never cleanup authority."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from time import monotonic


def _sibling(name: str):
    path = Path(__file__).parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("_residual_" + name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("residual inspection unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


preflight = _sibling("staging_preflight")
inventory = _sibling("staging_inventory")
recovery = _sibling("recover_provider")
_UID = 502
_CATALOG = (
    ("ssh-over-mcp-e2e-i8ow1ni6", 16777220, 187176421),
    ("ssh-over-mcp-e2e-recover.cc8Del", 16777220, 186815322),
    ("ssh-over-mcp-e2e-w_kn4rus", 16777220, 186877220),
)
MAX_TOTAL_ENTRIES = 4096
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SECONDS = 420
# Fixed, non-sensitive diagnostic phase; never log exceptions or source paths.
_REFUSAL_PHASE = "startup"


def _validate_context() -> dict[str, str]:
    recovery._validate_context(os.environ)
    if os.geteuid() != _UID:
        raise preflight.PreflightError()
    values = {
        "authority_sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if (
        os.environ.get("GITHUB_WORKFLOW_REF") != (
            "zhangyuz/ssh-over-mcp/.github/workflows/live-local-e2e-forensic.yml@refs/heads/main"
        )
        or os.environ.get("GITHUB_WORKFLOW_SHA") != values["authority_sha"]
        or re.fullmatch(r"[0-9a-f]{40}", values["authority_sha"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", values["run_id"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,4}", values["run_attempt"]) is None
    ):
        raise preflight.PreflightError()
    return values


def _marker_metadata(observation) -> dict[str, int]:
    return asdict(observation.metadata)


def inspect_residuals() -> bytes:
    """No operator-selected paths or fixture parameters; return only after cleanup."""
    global _REFUSAL_PHASE
    _REFUSAL_PHASE = "context"
    context = _validate_context()
    deadline = monotonic() + MAX_TOTAL_SECONDS

    def check_deadline():
        if monotonic() > deadline:
            raise preflight.PreflightError()

    with ExitStack() as owned:
        # These existing helpers verify pinned authority before native capture,
        # derive T only from fixed getconf, and pin literal / ancestry no-follow.
        _REFUSAL_PHASE = "native-temp"
        temp = owned.enter_context(preflight._pin_observed_native_temp_chain())
        _REFUSAL_PHASE = "marker-cache"
        cache = owned.enter_context(preflight._pin_observed_fixed_cache_chain())
        _REFUSAL_PHASE = "marker"
        marker = preflight._read_marker(cache._fds[-1], uid=_UID)
        _REFUSAL_PHASE = "catalog-roots"
        chains = []
        for name, device, inode in _CATALOG:
            chain = owned.enter_context(preflight._pin_safe_directory_chain(
                temp._fds[-1], (name,), ((_UID, (0o700,)),),
                system_uid=_UID, root_mode=0o700, post_close_validate=True,
            ))
            selected = chain.metadata[-1]
            if (selected.device, selected.inode) != (device, inode):
                raise preflight.PreflightError()
            chains.append(chain)
        _REFUSAL_PHASE = "process-a"
        preflight._observe_fixed_process_snapshot_checked()
        _REFUSAL_PHASE = "inventory-a"
        records = []
        original = []
        count = 0
        for (name, _, _), chain in zip(_CATALOG, chains, strict=True):
            check_deadline()
            entries = inventory.collect_residual_inventory(chain._fds[-1], uid=_UID)
            count += len(entries)
            if count > MAX_TOTAL_ENTRIES:
                raise preflight.PreflightError()
            original.append(entries)
            records.append({
                "name": name,
                "classification": (
                    "directory-only-residual" if all(e.kind == "directory" for e in entries)
                    else "nonempty-or-unknown"
                ),
                "entries": [asdict(entry) for entry in entries],
            })
        _REFUSAL_PHASE = "inventory-b"
        # Detect changes after a previously collected root, not only while its
        # own walk runs. Same-account ABA/concurrency remains an explicit limit.
        for chain, entries in zip(chains, original, strict=True):
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
        temp.revalidate()
        check_deadline()
        result = {
            "schema_version": 1,
            "kind": "provider-residual-forensic-inspection",
            **context,
            "workflow": "live-local-e2e-forensic.yml",
            "recovery_eligible": False,
            "snapshot_scope": "bounded executable-name observations; not exclusive quiescence or provenance",
            "marker": {
                "target": "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
                "owner_pid": 38013,
                "metadata": _marker_metadata(marker),
            },
            "roots": records,
        }
        _REFUSAL_PHASE = "encode"
        encoded = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) + 1 > MAX_EVIDENCE_BYTES:
            raise preflight.PreflightError()
        _REFUSAL_PHASE = "descriptor-close"
    # Context exit runs final namespace checks and closes owned descriptors.
    # Failure during that stage prevents any successful bytes from escaping.
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
        # Never expose paths, file content, child output or lower-level errors.
        print(
            f"provider residual inspection refused at {_REFUSAL_PHASE}; no recovery authorized",
            file=sys.stderr,
        )
        raise SystemExit(70) from None
