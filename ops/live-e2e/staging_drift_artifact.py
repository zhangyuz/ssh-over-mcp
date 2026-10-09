"""Bounded, canonical, checksum-checked *offline* drift report exchange.

Digest checking detects mismatch with a separately supplied digest, not
authenticity: anyone can replace both bytes and checksum. No inspection,
recovery, receipt, signing, or source provenance authority is added.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from staging_drift import ChangedEntry, DetachedDriftReport

MAX_BYTES = 2 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_ITEMS = 4096
_FAILURE = "staging drift artifact rejected"
_FIELDS = frozenset(
    {
        "schema_version",
        "incident",
        "before_sha256",
        "after_sha256",
        "marker_changed",
        "parent_changed",
        "selected_metadata_changed",
        "added_paths",
        "removed_paths",
        "modified_entries",
        "has_drift",
    }
)
_ENTRY_FIELDS = (
    "kind",
    "device",
    "inode",
    "uid",
    "gid",
    "mode",
    "nlink",
    "size",
    "mtime_ns",
    "ctime_ns",
)


class DriftArtifactError(RuntimeError):
    """Sanitized strict offline-wire refusal."""


@dataclass(frozen=True, slots=True)
class DriftArtifact:
    """Canonical bytes and independently checkable *content* SHA-256 only."""

    payload: bytes
    sha256: str


def _digest_valid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _path_bytes(path: object) -> bytes:
    if type(path) is not str or not path or len(path) > MAX_PATH_BYTES or "\x00" in path:
        raise DriftArtifactError(_FAILURE)
    pieces = path.split("/")
    if path != "." and (len(pieces) > 12 or any(part in {"", ".", ".."} for part in pieces)):
        raise DriftArtifactError(_FAILURE)
    raw = os.fsencode(path)  # Pure string->bytes conversion; never opens a file.
    if len(raw) > MAX_PATH_BYTES:
        raise DriftArtifactError(_FAILURE)
    return raw


def _paths(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > MAX_ITEMS:
        raise DriftArtifactError(_FAILURE)
    prev: bytes | None = None
    for path in value:
        raw = _path_bytes(path)
        if prev is not None and prev >= raw:
            raise DriftArtifactError(_FAILURE)
        prev = raw
    return value


def _payload_dict(report: object) -> dict:
    if type(report) is not DetachedDriftReport:
        raise DriftArtifactError(_FAILURE)
    if (
        type(report.incident) is not str
        or report.incident not in {"stale-target", "older-target"}
        or not _digest_valid(report.before_sha256)
        or not _digest_valid(report.after_sha256)
        or any(
            type(getattr(report, field)) is not bool
            for field in (
                "marker_changed",
                "parent_changed",
                "selected_metadata_changed",
                "has_drift",
            )
        )
    ):
        raise DriftArtifactError(_FAILURE)
    added = _paths(report.added_paths)
    removed = _paths(report.removed_paths)
    if type(report.modified_entries) is not tuple or len(report.modified_entries) > MAX_ITEMS:
        raise DriftArtifactError(_FAILURE)

    modified = []
    last_path = None
    for change in report.modified_entries:
        if type(change) is not ChangedEntry:
            raise DriftArtifactError(_FAILURE)
        raw = _path_bytes(change.path)
        if last_path is not None and last_path >= raw:
            raise DriftArtifactError(_FAILURE)
        last_path = raw
        fields = change.changed_fields
        if (
            type(fields) is not tuple
            or not fields
            or any(type(field) is not str or field not in _ENTRY_FIELDS for field in fields)
            or tuple(field for field in _ENTRY_FIELDS if field in fields) != fields
        ):
            raise DriftArtifactError(_FAILURE)
        modified.append({"path": change.path, "changed_fields": list(fields)})
    if (
        (set(added) & set(removed))
        or (set(added) & {item["path"] for item in modified})
        or (set(removed) & {item["path"] for item in modified})
    ):
        raise DriftArtifactError(_FAILURE)
    expected_drift = bool(
        added
        or removed
        or modified
        or report.marker_changed
        or report.parent_changed
        or report.selected_metadata_changed
        or report.before_sha256 != report.after_sha256
    )
    if report.has_drift is not expected_drift:
        raise DriftArtifactError(_FAILURE)
    return {
        "schema_version": 1,
        "incident": report.incident,
        "before_sha256": report.before_sha256,
        "after_sha256": report.after_sha256,
        "marker_changed": report.marker_changed,
        "parent_changed": report.parent_changed,
        "selected_metadata_changed": report.selected_metadata_changed,
        "added_paths": list(added),
        "removed_paths": list(removed),
        "modified_entries": modified,
        "has_drift": report.has_drift,
    }


def encode_detached_drift(report: object) -> DriftArtifact:
    """Serialize one exact typed summary into stable bounded ASCII JSON bytes."""
    try:
        value = _payload_dict(report)
        raw = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
        if not 1 <= len(raw) <= MAX_BYTES:
            raise DriftArtifactError(_FAILURE)
        return DriftArtifact(payload=raw, sha256=hashlib.sha256(raw).hexdigest())
    except DriftArtifactError:
        raise
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DriftArtifactError(_FAILURE) from None


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise DriftArtifactError(_FAILURE)
        result[key] = value
    return result


def _reject_number(_token: str) -> None:
    raise DriftArtifactError(_FAILURE)


def decode_detached_drift(raw: object, *, expected_sha256: object) -> DetachedDriftReport:
    """Verify supplied content SHA and canonical v1 bytes; no provenance claim."""
    try:
        if (
            type(raw) is not bytes
            or not 1 <= len(raw) <= MAX_BYTES
            or not _digest_valid(expected_sha256)
            or hashlib.sha256(raw).hexdigest() != expected_sha256
        ):
            raise DriftArtifactError(_FAILURE)
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if (
            type(value) is not dict
            or set(value) != _FIELDS
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
        ):
            raise DriftArtifactError(_FAILURE)
        changes = value["modified_entries"]
        if type(changes) is not list or len(changes) > MAX_ITEMS:
            raise DriftArtifactError(_FAILURE)
        modified = []
        for change in changes:
            if (
                type(change) is not dict
                or set(change) != {"path", "changed_fields"}
                or type(change["changed_fields"]) is not list
            ):
                raise DriftArtifactError(_FAILURE)
            modified.append(ChangedEntry(change["path"], tuple(change["changed_fields"])))
        if type(value["added_paths"]) is not list or type(value["removed_paths"]) is not list:
            raise DriftArtifactError(_FAILURE)
        report = DetachedDriftReport(
            incident=value["incident"],
            before_sha256=value["before_sha256"],
            after_sha256=value["after_sha256"],
            marker_changed=value["marker_changed"],
            parent_changed=value["parent_changed"],
            selected_metadata_changed=value["selected_metadata_changed"],
            added_paths=tuple(value["added_paths"]),
            removed_paths=tuple(value["removed_paths"]),
            modified_entries=tuple(modified),
            has_drift=value["has_drift"],
        )
        if encode_detached_drift(report).payload != raw:
            raise DriftArtifactError(_FAILURE)
        return report
    except DriftArtifactError:
        raise
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DriftArtifactError(_FAILURE) from None
