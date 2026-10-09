"""Pure, dormant detached-observation -> canonical inventory payload projection.

This is a serializer/validator of *supplied* immutable fixture evidence, not
authentication of the evidence's source, an incident inspector, or a receipt.
No process, filesystem, network, workflow or other authority is acquired.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import staging_preflight as preflight
from staging_envelope import _inventory_valid
from staging_wire import encode_inventory_payload

_FAILURE = "staging projection rejected"

_FIELDS = (
    "path",
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
_META_FIELDS = ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")


class ProjectionError(RuntimeError):
    """Sanitized pure-data validation failure, with no incident cleanup authority."""


@dataclass(frozen=True, slots=True)
class ProjectedInventory:
    """Canonical detached bytes + content checksum; not trusted provenance."""

    payload: bytes
    sha256: str


def project_detached_inventory(observation: object) -> ProjectedInventory:
    """Validate one supplied detached report and encode the fixed v1 inventory.

    No inspection authority/run ID/attempt is accepted or manufactured. This
    function does not call the observation producer or read host incident data.
    Even a valid projected payload is NOT evidence the host was inspected.
    """
    try:
        if type(observation) is not preflight._DetachedJointPreflightObservation:
            raise ProjectionError(_FAILURE)
        parent = observation.parent
        selected = observation.selected
        marker = observation.marker_metadata
        if (
            type(parent) is not preflight._TempAncestryEvidence
            or type(selected) is not preflight._SelectedInventoryEvidence
            or type(marker) is not preflight._RegularMetadata
            or type(parent.ancestors) is not tuple
            or len(parent.ancestors) != 7
            or type(selected.inventory) is not tuple
            or not 13 <= len(selected.inventory) <= 4096
            or type(selected.expected_metadata) is not preflight._RegularMetadata
        ):
            raise ProjectionError(_FAILURE)

        # A dataclass annotation is not a runtime scalar guard. In
        # particular bool compares equal to 0/1 and omitted marker fields
        # would otherwise bypass the wire serializer's exact-type checks.
        for metadata in (marker, selected.expected_metadata):
            for field in _META_FIELDS:
                value = getattr(metadata, field)
                if type(value) is not int or (field not in {"mtime_ns", "ctime_ns"} and value < 0):
                    raise ProjectionError(_FAILURE)

        catalog = preflight._select_incident(selected.selector)
        if (
            selected.basename != catalog.basename
            or selected.device != catalog.device
            or selected.inode != catalog.inode
            or selected.uid != catalog.uid
            or selected.mode != catalog.mode
            or selected.expected_commit != catalog.expected_commit
            or observation.marker_target != preflight._MARKER_TARGET
            or type(observation.marker_owner_pid) is not int
            or observation.marker_owner_pid != 38013
            or marker.uid != 502
            or marker.mode != 0o600
            or marker.nlink != 1
            or not 1 <= marker.size <= 4096
        ):
            raise ProjectionError(_FAILURE)

        if type(parent.path) is not str or len(parent.path) > 24578:
            raise ProjectionError(_FAILURE)

        parts = ("private", "var", "folders")
        path = ""
        ancestor_rows = []
        for index, ancestor in enumerate(parent.ancestors):
            if (
                type(ancestor) is not preflight._DirectoryAncestor
                or type(ancestor.path) is not str
                or len(ancestor.path) > 24578
                or type(ancestor.metadata) is not preflight.DirectoryMetadata
            ):
                raise ProjectionError(_FAILURE)
            if index == 0:
                path = "/"
            elif index <= 3:
                path = "/" + "/".join(parts[:index])
            else:
                # The two getconf-derived path components are constrained by
                # the hardened native observer, and the wire domain validator
                # checks the complete literal rooted pathname.
                components = parent.path.split("/")
                if len(components) != 7:
                    raise ProjectionError(_FAILURE)
                path = "/" + "/".join(components[1 : index + 1])
            if ancestor.path != path:
                raise ProjectionError(_FAILURE)
            metadata = ancestor.metadata
            ancestor_rows.append(
                {
                    "path": path,
                    "device": metadata.device,
                    "inode": metadata.inode,
                    "uid": metadata.uid,
                    "gid": metadata.gid,
                    "mode": metadata.mode,
                }
            )
        if parent.path != ancestor_rows[-1]["path"]:
            raise ProjectionError(_FAILURE)

        # The real pinned inventory observer initializes this cache while
        # collecting records. Never import/execute checkout code from a
        # supposedly pure projection call, including cold-cache failures.
        inventory_module = preflight._FIXED_INVENTORY_MODULE
        if inventory_module is None:
            raise ProjectionError(_FAILURE)
        entry_type = inventory_module.InventoryEntry
        entries = []
        expected_entry = None
        for entry in selected.inventory:
            if type(entry) is not entry_type:
                raise ProjectionError(_FAILURE)
            if type(entry.path) is not str or len(entry.path) > 4096:
                raise ProjectionError(_FAILURE)
            record = {name: getattr(entry, name) for name in _FIELDS}
            entries.append(record)
            if entry.path == "payload-content/expected_commit":
                if expected_entry is not None:
                    raise ProjectionError(_FAILURE)
                expected_entry = entry
        if expected_entry is None or any(
            getattr(expected_entry, field) != getattr(selected.expected_metadata, field)
            for field in _META_FIELDS
        ):
            raise ProjectionError(_FAILURE)

        inventory = {
            "schema_version": 1,
            "incident": selected.selector,
            "parent": {"path": parent.path, "ancestors": ancestor_rows},
            "marker": {
                "device": marker.device,
                "inode": marker.inode,
                "target": observation.marker_target,
                "owner_pid": observation.marker_owner_pid,
            },
            "staging": {
                "basename": selected.basename,
                "device": selected.device,
                "inode": selected.inode,
                "uid": selected.uid,
                "mode": selected.mode,
                "expected_commit": selected.expected_commit,
            },
            "entries": entries,
        }
        # Use only the already-reviewed wire domain and exact canonical
        # encoder; do not add a second permissive JSON serializer.
        _inventory_valid(inventory)
        payload = encode_inventory_payload(inventory)
        return ProjectedInventory(payload=payload, sha256=hashlib.sha256(payload).hexdigest())
    except ProjectionError:
        raise
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ProjectionError(_FAILURE) from None
