"""Bounded offline cross-check of a topology manifest and rendered Compose JSON.

Consistent declarations are not attested Engines, trusted images or deployment.
Never invoke Docker, SSH, networking or host operations.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from compose_config_preflight import check_mode_a, check_mode_b
from topology_preflight import Refused, _read_one_regular_file, check_topology

_REPORT = "som-mvp-compose-bundle-preflight-v1"
_CONTROL_IMAGE_ROLES = ("ledger-init", "ledger", "mcp", "approvalctl")
_ALIASES = ("node01", "node02")


def check_bundle(
    topology: object, control: object, node01: object | None = None, node02: object | None = None
) -> dict[str, Any]:
    """Validate each static schema first, then enforce literal image consistency.

    The node01/node02 input *ordering* is operator declared, not a verified
    binding between actual host identities, pinned SSH keys and Docker Engines.
    """
    manifest_report = check_topology(topology)
    mode = manifest_report["mode"]
    if mode == "dev-e2e":
        if node01 is not None or node02 is not None:
            raise Refused("INVALID_MODE_FILES")
        check_mode_a(control)
    else:
        if node01 is None or node02 is None:
            raise Refused("MISSING_TARGET_PROJECT")
        check_mode_b(control, node01, node02)

    # Both validators already ensured exact shape, valid aliases, digest-only
    # syntax, role configurations and two SSH volume/network partitions.
    manifest = topology  # validated dict by check_topology
    actual_control = control  # validated dict by check_mode_a / check_mode_b
    expected_control_image = manifest["control"]["image"]
    for role in _CONTROL_IMAGE_ROLES:
        if (
            role in actual_control["services"]
            and actual_control["services"][role]["image"] != expected_control_image
        ):
            raise Refused("IMAGE_DECLARATION_MISMATCH")

    expected_targets = {item["alias"]: item["image"] for item in manifest["targets"]}
    for alias in _ALIASES:
        service = (
            actual_control["services"][alias]
            if mode == "dev-e2e"
            else (node01 if alias == "node01" else node02)["services"]["ssh-target"]
        )
        if service["image"] != expected_targets[alias]:
            raise Refused("IMAGE_DECLARATION_MISMATCH")

    return {
        "schema": _REPORT,
        "mode": mode,
        "target_count": 2,
        "static_artifacts_consistent": True,
        "topology_shape_valid": True,
        "compose_shape_valid": True,
        "image_declarations_match": True,
        "deployment_ready": False,
        "image_trust_verified": False,
        "host_identity_verified": False,
        "network_acl_verified": False,
        "runtime_verified": False,
        "live_e2e_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline consistency of topology and rendered Compose declarations only."
    )
    parser.add_argument("--topology-json", required=True, type=Path)
    parser.add_argument("--control-json", required=True, type=Path)
    parser.add_argument("--node01-json", type=Path)
    parser.add_argument("--node02-json", type=Path)
    args = parser.parse_args()
    try:
        # Refuse repeated lexical paths, including mode-B target alias swaps
        # which cannot prove two independent host project descriptions.
        paths = (args.topology_json, args.control_json, args.node01_json, args.node02_json)
        supplied = [os.path.normpath(os.path.abspath(p)) for p in paths if p is not None]
        if len(set(supplied)) != len(supplied):
            raise Refused("DUPLICATE_INPUT_PATH")
        topology = _read_one_regular_file(args.topology_json)
        control = _read_one_regular_file(args.control_json)
        node01 = _read_one_regular_file(args.node01_json) if args.node01_json else None
        node02 = _read_one_regular_file(args.node02_json) if args.node02_json else None
        report = check_bundle(topology, control, node01, node02)
    except (Refused, OSError, TypeError, ValueError, KeyError, RecursionError) as exc:
        # Only fixed reason codes are safe for operator logs: never reflect the
        # input path, document bytes, SSH pins or token-like user data.
        code = exc.code if isinstance(exc, Refused) else "INVALID_INPUT"
        parser.error("preflight refused: " + code)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
