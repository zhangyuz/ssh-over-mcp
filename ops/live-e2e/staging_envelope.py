"""Dormant data-only envelope; supplied provenance is not authenticated here."""

from __future__ import annotations

import hashlib
import os
import re

from staging_wire import EnvelopeError, encode_inventory_payload, encode_wire, parse_wire

_CATALOG = {
    "stale-target": (
        "ssh-over-mcp-e2e-i8ow1ni6",
        187176421,
        "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
    ),
    "older-target": (
        "ssh-over-mcp-e2e-w_kn4rus",
        186877220,
        "bf84c7aafa5c79d629fc04488b5e0bda1cd98cef",
    ),
}
_LAYOUT = {
    "bootstrap-wheels": "directory",
    "payload-content": "directory",
    "payload-iso": "directory",
    "seed": "directory",
    "target.git": "directory",
    "wheels": "directory",
    "git-askpass": "regular",
    "overlay.qcow2": "regular",
    "payload.iso": "regular",
    "seed.iso": "regular",
    "target.bundle": "regular",
}


def _require(condition: bool) -> None:
    if not condition:
        raise EnvelopeError("staging envelope rejected") from None


def _inventory_valid(inventory: dict) -> None:
    staging = inventory["staging"]
    basename, inode, commit = _CATALOG[inventory["incident"]]
    _require(
        staging
        == {
            "basename": basename,
            "inode": inode,
            "expected_commit": commit,
            "device": 16777220,
            "uid": 502,
            "mode": 0o700,
        }
    )
    marker = inventory["marker"]
    _require(marker["target"] == _CATALOG["stale-target"][2] and marker["owner_pid"] == 38013)
    parent = inventory["parent"]
    path = parent["path"]
    _require(re.fullmatch(r"/private/var/folders/[a-z0-9]{2}/[a-z0-9_]+/T", path) is not None)
    components = path.split("/")[1:]
    prefixes = ["/"] + ["/" + "/".join(components[:i]) for i in range(1, len(components) + 1)]
    _require([entry["path"] for entry in parent["ancestors"]] == prefixes)
    for index, ancestor in enumerate(parent["ancestors"]):
        _require(not ancestor["mode"] & 0o022)
        _require(ancestor["uid"] == (502 if index >= 5 else 0))
        if index == 5:
            _require(ancestor["mode"] in {0o700, 0o755})
        if index == 6:
            _require(ancestor["mode"] == 0o700)
    entries = inventory["entries"]
    paths = set()
    identities = set()
    kinds = {}
    previous = None
    for entry in entries:
        path = entry["path"]
        _require(bool(path) and "\x00" not in path)
        parts = path.split("/")
        _require(
            path == "." or (len(parts) <= 12 and all(part not in {"", ".", ".."} for part in parts))
        )
        raw = os.fsencode(path)
        _require(len(raw) <= 4096 and (previous is None or previous < raw))
        previous = raw
        _require(
            entry["device"] == staging["device"]
            and entry["uid"] == 502
            and not entry["mode"] & 0o022
        )
        _require(entry["kind"] != "regular" or entry["nlink"] == 1)
        identity = (entry["device"], entry["inode"])
        _require(identity not in identities and path not in paths)
        identities.add(identity)
        paths.add(path)
        kinds[path] = entry["kind"]
        if path != ".":
            parent_path = path.rsplit("/", 1)[0] if "/" in path else "."
            _require(kinds.get(parent_path) == "directory")
    root = entries[0]
    _require(
        root["path"] == "."
        and root["kind"] == "directory"
        and root["inode"] == inode
        and root["mode"] == 0o700
    )
    _require(
        {name: kind for name, kind in kinds.items() if name != "." and "/" not in name} == _LAYOUT
    )
    expected = next(
        (entry for entry in entries if entry["path"] == "payload-content/expected_commit"), None
    )
    _require(expected is not None and expected["kind"] == "regular" and expected["size"] == 41)


def validate_envelope(raw: bytes) -> None:
    try:
        envelope = parse_wire(raw, kind="envelope")
        inventory = envelope["inventory"]
        _inventory_valid(inventory)
        _require(
            hashlib.sha256(encode_inventory_payload(inventory)).hexdigest()
            == envelope["inventory_sha256"]
        )
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise EnvelopeError("staging envelope rejected") from None


def encode_envelope(inventory: dict, inspection: dict) -> bytes:
    try:
        inventory_bytes = encode_inventory_payload(inventory)
        raw = encode_wire(
            {
                "schema_version": 1,
                "inventory": inventory,
                "inspection": inspection,
                "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            },
            kind="envelope",
        )
        # Validate the detached final bytes; concurrent input mutation cannot bless
        # a different inventory with the earlier digest or earlier domain checks.
        validate_envelope(raw)
        return raw
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise EnvelopeError("staging envelope rejected") from None
