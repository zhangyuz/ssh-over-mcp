"""Observe only the two exact historical staging roots; NEVER authorize recovery."""
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
    source = Path(__file__).parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("_remaining_roots_" + name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed observer unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


observer = _sibling("observe_recovery_root_metadata")
preflight = observer.preflight
recovery = observer.recovery
_UID = 502
_CATALOG = (observer.private_tmp._CATALOG[0], observer.private_tmp._CATALOG[2])
MAX_TOTAL_ENTRIES = 4096
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SECONDS = 420
_REFUSAL_PHASE = "startup"


def _validate_context() -> dict[str, str]:
    recovery._validate_context(os.environ)
    result = {
        "authority_sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if (
        os.geteuid() != _UID
        or os.environ.get("GITHUB_WORKFLOW_REF") != (
            "zhangyuz/ssh-over-mcp/.github/workflows/"
            "live-local-e2e-staging-roots-observe.yml@refs/heads/main"
        )
        or os.environ.get("GITHUB_WORKFLOW_SHA") != result["authority_sha"]
        or re.fullmatch(r"[0-9a-f]{40}", result["authority_sha"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", result["run_id"]) is None
        or re.fullmatch(r"[1-9][0-9]{0,4}", result["run_attempt"]) is None
    ):
        raise preflight.PreflightError()
    return result


def observe_staging_roots() -> bytes:
    """Only pinned root identities and no-follow metadata; never cleanup authority."""
    global _REFUSAL_PHASE
    _REFUSAL_PHASE = "context"
    context = _validate_context()
    begun = monotonic()

    def check_deadline() -> None:
        if monotonic() - begun > MAX_TOTAL_SECONDS:
            raise preflight.PreflightError()

    with ExitStack() as stack:
        _REFUSAL_PHASE = "private-tmp-parent"
        parent = stack.enter_context(observer.private_tmp._pin_private_tmp())
        _REFUSAL_PHASE = "marker-cache"
        cache = stack.enter_context(preflight._pin_observed_fixed_cache_chain())
        _REFUSAL_PHASE = "marker"
        marker = preflight._read_marker(cache._fds[-1], uid=_UID)
        chains = []
        for index, (name, device, inode) in zip((1, 3), _CATALOG, strict=True):
            _REFUSAL_PHASE = f"catalog-open-{index}"
            chain = stack.enter_context(preflight._pin_directory_chain(
                parent._fds[-1], (name,), ((_UID, (0o700,)),),
                post_close_validate=True,
            ))
            _REFUSAL_PHASE = f"catalog-identity-{index}"
            root = chain.metadata[-1]
            if (
                (root.device, root.inode, root.uid, root.mode)
                != (device, inode, _UID, 0o700)
                or root.device != parent.metadata[-1].device
            ):
                raise preflight.PreflightError()
            chains.append(chain)
        _REFUSAL_PHASE = "process-a"
        preflight._observe_fixed_process_snapshot_checked()
        original = []
        totals = 0
        for index, chain in zip((1, 3), chains, strict=True):
            _REFUSAL_PHASE = f"inventory-a-{index}"
            try:
                entries = observer._collect_special_metadata(chain._fds[-1], uid=_UID)
            except preflight.PreflightError:
                _REFUSAL_PHASE += "-" + observer._COLLECT_PHASE
                raise
            totals += len(entries)
            if totals > MAX_TOTAL_ENTRIES:
                raise preflight.PreflightError()
            original.append(entries)
            check_deadline()
        for index, (chain, expected) in zip((1, 3), zip(chains, original, strict=True), strict=True):
            _REFUSAL_PHASE = f"inventory-b-{index}"
            try:
                repeat = observer._collect_special_metadata(chain._fds[-1], uid=_UID)
            except preflight.PreflightError:
                _REFUSAL_PHASE += "-" + observer._COLLECT_PHASE
                raise
            if repeat != expected:
                raise preflight.PreflightError()
            check_deadline()
        _REFUSAL_PHASE = "process-b"
        preflight._observe_fixed_process_snapshot_checked()
        _REFUSAL_PHASE = "final-namespace"
        preflight._revalidate_marker(cache._fds[-1], marker, uid=_UID)
        for chain in reversed(chains):
            chain.revalidate()
        cache.revalidate()
        parent.revalidate()
        check_deadline()
        _REFUSAL_PHASE = "encode"
        evidence = {
            "schema_version": 1,
            "kind": "two-historical-staging-roots-observation",
            "workflow": "live-local-e2e-staging-roots-observe.yml",
            **context,
            "recovery_eligible": False,
            "snapshot_scope": "two matching bounded metadata snapshots; no recovery authority",
            "marker": {
                "target": "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
                "owner_pid": 38013,
                "metadata": asdict(marker.metadata),
            },
            "roots": [
                {
                    "catalog_identity": {
                        "device": device, "inode": inode, "uid": _UID, "mode": 0o700,
                    },
                    "entries": entries,
                }
                for (_, device, inode), entries in zip(_CATALOG, original, strict=True)
            ],
        }
        encoded = json.dumps(evidence, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) + 1 > MAX_EVIDENCE_BYTES:
            raise preflight.PreflightError()
        _REFUSAL_PHASE = "descriptor-close"
    check_deadline()
    _REFUSAL_PHASE = "complete"
    return encoded + b"\n"


def main(argv: list[str] | None = None) -> int:
    if list(sys.argv[1:] if argv is None else argv):
        raise preflight.PreflightError()
    payload = observe_staging_roots()
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):  # noqa: BLE001
        print(
            f"fixed staging roots observation refused at {_REFUSAL_PHASE}; "
            "no disposition authorized",
            file=sys.stderr,
        )
        raise SystemExit(70) from None
