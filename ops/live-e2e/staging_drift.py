"""Offline comparison of two *untrusted* detached preflight observations.

Only reviewed, canonical projected payloads are compared. This is a detached
change report for disposable evidence, not a second capture, trusted preflight
decision, recovery eligibility check, or permission to touch provider state.
"""

from __future__ import annotations

from dataclasses import dataclass

import staging_preflight as preflight
from staging_projection import project_detached_inventory

_FAILURE = "staging drift rejected"
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
_SELECTED_FIELDS = (
    "selector",
    "basename",
    "device",
    "inode",
    "uid",
    "mode",
    "expected_commit",
    "expected_metadata",
)


class DriftError(RuntimeError):
    """Fixed, sanitized refusal; does not confer incident cleanup authority."""


@dataclass(frozen=True, slots=True)
class ChangedEntry:
    path: str
    changed_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetachedDriftReport:
    incident: str
    before_sha256: str
    after_sha256: str
    marker_changed: bool
    parent_changed: bool
    selected_metadata_changed: bool
    added_paths: tuple[str, ...]
    removed_paths: tuple[str, ...]
    modified_entries: tuple[ChangedEntry, ...]
    has_drift: bool


def compare_detached_observations(before: object, after: object) -> DetachedDriftReport:
    """Return a deterministic data-only drift summary for one fixed incident.

    Each supplied record is independently passed through the strict canonical
    inventory projector first. No host read, runtime authority, envelope,
    receipt, process lookup, UID-502 operation or real revalidation occurs.
    """
    try:
        if (
            type(before) is not preflight._DetachedJointPreflightObservation
            or type(after) is not preflight._DetachedJointPreflightObservation
            or type(before.selected) is not preflight._SelectedInventoryEvidence
            or type(after.selected) is not preflight._SelectedInventoryEvidence
            or type(before.selected.selector) is not str
            or before.selected.selector != after.selected.selector
        ):
            raise DriftError(_FAILURE)
        before_projected = project_detached_inventory(before)
        after_projected = project_detached_inventory(after)

        before_entries = {entry.path: entry for entry in before.selected.inventory}
        after_entries = {entry.path: entry for entry in after.selected.inventory}
        added = tuple(
            entry.path for entry in after.selected.inventory if entry.path not in before_entries
        )
        removed = tuple(
            entry.path for entry in before.selected.inventory if entry.path not in after_entries
        )
        modified = tuple(
            ChangedEntry(
                entry.path,
                tuple(
                    field
                    for field in _ENTRY_FIELDS
                    if getattr(before_entries[entry.path], field) != getattr(entry, field)
                ),
            )
            for entry in after.selected.inventory
            if entry.path in before_entries and entry != before_entries[entry.path]
        )

        marker_changed = (
            before.marker_target != after.marker_target
            or before.marker_owner_pid != after.marker_owner_pid
            or before.marker_metadata != after.marker_metadata
        )
        parent_changed = before.parent != after.parent
        selected_changed = any(
            getattr(before.selected, field) != getattr(after.selected, field)
            for field in _SELECTED_FIELDS
        )
        has_drift = bool(
            added
            or removed
            or modified
            or marker_changed
            or parent_changed
            or selected_changed
            or before_projected.sha256 != after_projected.sha256
        )
        return DetachedDriftReport(
            incident=before.selected.selector,
            before_sha256=before_projected.sha256,
            after_sha256=after_projected.sha256,
            marker_changed=marker_changed,
            parent_changed=parent_changed,
            selected_metadata_changed=selected_changed,
            added_paths=added,
            removed_paths=removed,
            modified_entries=modified,
            has_drift=has_drift,
        )
    except DriftError:
        raise
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DriftError(_FAILURE) from None
