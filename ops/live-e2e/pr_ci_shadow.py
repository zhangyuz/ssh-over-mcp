"""Trusted-hosted, informational PR CI shadow observer (NEVER a native E2E gate)."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from pr_ci_admission import Refused, ShadowObservation, decide
from pr_ci_github import GitHubReadAPI

_MAX_EVENT_BYTES = 256 * 1024


def _read_event(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_EVENT_BYTES + 1)
    except OSError:
        raise Refused("EVENT_UNAVAILABLE") from None
    if len(raw) > _MAX_EVENT_BYTES:
        raise Refused("EVENT_TOO_LARGE")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Refused("EVENT_JSON_INVALID") from None
    if not isinstance(data, dict) or not all(isinstance(key, str) for key in data):
        raise Refused("EVENT_SHAPE_INVALID")
    return data


def _emit(result: dict[str, object]) -> None:
    # Never serialize source payloads, exceptions, PR titles or tokens.
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def main(event_file: Path, *, token: str) -> int:
    """Return 0 for a safe informational verdict; 1 for provider/format errors."""
    try:
        event = _read_event(event_file)
    except Refused as error:
        _emit({"verdict": "ERROR", "reason_code": error.reason_code})
        return 1

    try:
        snapshot = GitHubReadAPI(token).load(event)
    except Refused as error:
        _emit({"verdict": "ERROR", "reason_code": error.reason_code})
        return 1
    except Exception:  # noqa: BLE001 - never emit network or token-bearing exceptions
        _emit({"verdict": "ERROR", "reason_code": "API_UNEXPECTED_ERROR"})
        return 1

    try:
        observed: ShadowObservation = decide(event, *snapshot)
    except Refused as error:
        _emit({"verdict": "REFUSED", "reason_code": error.reason_code})
        return 0
    except Exception:  # noqa: BLE001 - metadata is untrusted; no unfiltered traceback
        _emit({"verdict": "ERROR", "reason_code": "CLASSIFIER_UNEXPECTED_ERROR"})
        return 1

    _emit(
        {
            "verdict": "METADATA_MATCH_SHADOW",
            "reason_code": "CI_METADATA_MATCHED_NO_AUTHORITY",
            "ci_run_id": observed.ci_run_id,
            "ci_attempt": observed.ci_attempt,
            "pr_number": observed.pr_number,
            "head_sha": observed.head_sha,
            "base_freshness_proven": False,
            "trusted_suite_proven": False,
            "dispatch_authorized": False,
        }
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Informational PR CI metadata observer only")
    parser.add_argument("--event", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    args = parser.parse_args()
    if args.event is None:
        _emit({"verdict": "ERROR", "reason_code": "EVENT_UNAVAILABLE"})
        raise SystemExit(1)
    raise SystemExit(main(args.event, token=os.environ.get("GITHUB_TOKEN", "")))
