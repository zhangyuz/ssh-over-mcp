"""Offline typed preflight evidence -> canonical inventory payload, never trusted provenance."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).parent / "fixtures/staging-envelope-v1"


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_preflight"), importlib.import_module(
        "staging_projection"
    )


@pytest.fixture
def evidence(modules):
    p, _ = modules
    fixture = json.loads((GOLDEN / "inventory.json").read_bytes())
    ancestors = tuple(
        p._DirectoryAncestor(
            path=item["path"],
            metadata=p.DirectoryMetadata(
                *(item[key] for key in ("device", "inode", "uid", "gid", "mode"))
            ),
        )
        for item in fixture["parent"]["ancestors"]
    )
    selected = fixture["staging"]
    entries = tuple(
        p._fixed_inventory_module().InventoryEntry(
            *(
                item[key]
                for key in (
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
            )
        )
        for item in fixture["entries"]
    )
    meta = next(
        item for item in fixture["entries"] if item["path"] == "payload-content/expected_commit"
    )
    selected_observation = p._SelectedInventoryEvidence(
        selector=fixture["incident"],
        basename=selected["basename"],
        device=selected["device"],
        inode=selected["inode"],
        uid=selected["uid"],
        mode=selected["mode"],
        expected_commit=selected["expected_commit"],
        expected_metadata=p._RegularMetadata(
            *(
                meta[key]
                for key in (
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
            )
        ),
        inventory=entries,
    )
    marker = fixture["marker"]
    return p._DetachedJointPreflightObservation(
        parent=p._TempAncestryEvidence(path=fixture["parent"]["path"], ancestors=ancestors),
        marker_target=marker["target"],
        marker_owner_pid=marker["owner_pid"],
        marker_metadata=p._RegularMetadata(
            marker["device"], marker["inode"], 502, 502, 0o600, 1, 110, 1, 2
        ),
        selected=selected_observation,
    )


def test_golden_inventory_payload_and_digest_are_exact(modules, evidence):
    _p, projection = modules
    result = projection.project_detached_inventory(evidence)
    raw = (GOLDEN / "inventory.json").read_bytes()
    assert type(result) is projection.ProjectedInventory
    assert result.payload == raw
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert type(result.payload) is bytes
    with pytest.raises(FrozenInstanceError):
        result.payload = b"changed"


def test_projection_never_observes_host_or_claims_workflow_authority(
    modules, evidence, monkeypatch
):
    p, projection = modules

    def forbidden(*_a, **_kw):
        pytest.fail("pure projection acquired host or workflow authority")

    with monkeypatch.context() as patch:
        for method in ("open", "stat", "scandir", "listdir", "kill", "system", "fork"):
            if hasattr(os, method):
                patch.setattr(os, method, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        result = projection.project_detached_inventory(evidence)
    assert result.payload == (GOLDEN / "inventory.json").read_bytes()
    for absent in ("inspection", "authority_sha", "run_id", "attempt", "receipt", "fds"):
        assert absent.encode() not in result.payload
        assert not hasattr(result, absent)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("marker_target", "0" * 40),
        ("marker_owner_pid", 0),
        ("parent", None),
        ("selected", None),
        ("marker_metadata", None),
    ],
)
def test_refuse_invalid_top_level_evidence(modules, evidence, field, bad):
    _p, projection = modules
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(replace(evidence, **{field: bad}))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("device", 123),
        ("inode", 42),
        ("uid", 3),
        ("mode", 0o777),
        ("expected_commit", "0" * 40),
        ("expected_metadata", None),
        ("inventory", ()),
    ],
)
def test_refuse_mismatched_selected_identity_or_inventory(modules, evidence, field, bad):
    _p, projection = modules
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(
            replace(evidence, selected=replace(evidence.selected, **{field: bad}))
        )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("path", "/tmp/untrusted"),
        ("ancestors", ()),
    ],
)
def test_refuse_wrong_parent_ancestry(modules, evidence, field, bad):
    _p, projection = modules
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(
            replace(evidence, parent=replace(evidence.parent, **{field: bad}))
        )


def test_refuse_expected_commit_entry_metadata_drift(modules, evidence):
    _p, projection = modules
    entries = list(evidence.selected.inventory)
    index = next(
        i for i, entry in enumerate(entries) if entry.path == "payload-content/expected_commit"
    )
    entries[index] = replace(entries[index], mtime_ns=entries[index].mtime_ns + 1)
    altered = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(altered)


@pytest.mark.parametrize("mutation", ["permuted", "extra", "boolean", "badpath"])
def test_reject_invalid_collector_layout_or_scalar(modules, evidence, mutation):
    _p, projection = modules
    entries = list(evidence.selected.inventory)
    if mutation == "permuted":
        entries[1], entries[2] = entries[2], entries[1]
    elif mutation == "extra":
        entries.append(entries[-1])
    elif mutation == "boolean":
        entries[0] = replace(entries[0], inode=True)
    else:
        entries[1] = replace(entries[1], path="../untrusted")
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(
            replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
        )


def test_wrong_input_shape_fails_without_host_actions(modules):
    _p, projection = modules
    for item in ({}, None, [], True, "stale-target", b"fixture"):
        with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
            projection.project_detached_inventory(item)


def test_second_fixed_catalog_selector_projects_to_canonical_schema(modules, evidence):
    p, projection = modules
    original = evidence.selected
    alternate = p._select_incident("older-target")
    entries = list(original.inventory)
    entries[0] = replace(entries[0], inode=alternate.inode)
    entries[5] = replace(entries[5], ctime_ns=17)
    expected = replace(original.expected_metadata, ctime_ns=17)
    selected = replace(
        original,
        selector="older-target",
        basename=alternate.basename,
        inode=alternate.inode,
        expected_commit=alternate.expected_commit,
        expected_metadata=expected,
        inventory=tuple(entries),
    )
    result = projection.project_detached_inventory(replace(evidence, selected=selected))
    inventory = json.loads(result.payload)
    assert inventory["incident"] == "older-target"
    assert inventory["staging"]["basename"] == alternate.basename
    assert inventory["staging"]["expected_commit"] == alternate.expected_commit
    assert inventory["entries"][0]["inode"] == alternate.inode
    assert inventory["entries"][5]["ctime_ns"] == 17
    assert hashlib.sha256(result.payload).hexdigest() == result.sha256


@pytest.mark.parametrize("field,bad", [("uid", 501), ("mode", 0o666), ("nlink", 2)])
def test_marker_metadata_cannot_be_loosened(modules, evidence, field, bad):
    _p, projection = modules
    changed = replace(evidence, marker_metadata=replace(evidence.marker_metadata, **{field: bad}))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(changed)


def test_all_records_are_detached_and_stable_after_input_reference_reassignment(modules, evidence):
    _p, projection = modules
    first = projection.project_detached_inventory(evidence)
    mutated_entries = list(evidence.selected.inventory)
    mutated_entries[2] = replace(mutated_entries[2], size=mutated_entries[2].size + 9)
    altered = replace(
        evidence, selected=replace(evidence.selected, inventory=tuple(mutated_entries))
    )
    second = projection.project_detached_inventory(altered)
    assert first.payload != second.payload
    assert first.sha256 != second.sha256
    assert first.payload == (GOLDEN / "inventory.json").read_bytes()


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("nlink", True),
        ("gid", []),
        ("mtime_ns", {}),
        ("ctime_ns", "2"),
    ],
)
def test_forged_marker_metadata_scalars_fail_even_if_not_wire_fields(
    modules, evidence, field, value
):
    _p, projection = modules
    fake = replace(evidence, marker_metadata=replace(evidence.marker_metadata, **{field: value}))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(fake)


def test_expected_metadata_bool_equal_to_integer_must_still_fail(modules, evidence):
    _p, projection = modules
    metadata = replace(evidence.selected.expected_metadata, nlink=True)
    fake = replace(evidence, selected=replace(evidence.selected, expected_metadata=metadata))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(fake)


@pytest.mark.parametrize("field,value", [("path", "z" * 4100), ("path", "../" * 2500)])
def test_bounded_paths_refused_before_expensive_encode(modules, evidence, field, value):
    _p, projection = modules
    entries = list(evidence.selected.inventory)
    entries[1] = replace(entries[1], **{field: value})
    fake = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(fake)


class _DeceptiveAncestorPath(str):
    def __ne__(self, other):
        return False


@pytest.mark.parametrize(
    "spoofed",
    [
        _DeceptiveAncestorPath("/wrong/untrusted/ancestor"),
        None,
        3,
        b"/private",
    ],
)
def test_reject_forged_ancestor_path_exact_type(modules, evidence, spoofed):
    _p, projection = modules
    ancestors = list(evidence.parent.ancestors)
    ancestors[3] = replace(ancestors[3], path=spoofed)
    fake = replace(evidence, parent=replace(evidence.parent, ancestors=tuple(ancestors)))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(fake)


def test_reject_oversized_ancestor_without_copying_it(modules, evidence):
    _p, projection = modules
    ancestors = list(evidence.parent.ancestors)
    ancestors[2] = replace(ancestors[2], path="a" * 24600)
    fake = replace(evidence, parent=replace(evidence.parent, ancestors=tuple(ancestors)))
    with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
        projection.project_detached_inventory(fake)


def test_cold_cache_refuses_before_any_fixed_module_load_or_host_access(
    modules, evidence, monkeypatch
):
    p, projection = modules

    # Evidence was assembled from the real fixed InventoryEntry type while
    # cache was warm. A fresh uninitialized projection MUST NOT dynamically
    # fetch/execute that module just to perform an entry type check.
    def forbidden(*_args, **_kwargs):
        pytest.fail("cold-cache projection attempted to load or access host")

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        for method in ("open", "scandir", "stat", "listdir", "system", "kill", "fork"):
            if hasattr(os, method):
                patch.setattr(os, method, forbidden)
        cold = replace(evidence, selected=replace(evidence.selected, inventory=(None,) * 13))
        with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
            projection.project_detached_inventory(cold)
        assert p._FIXED_INVENTORY_MODULE is None


def test_warm_evidence_but_cold_module_cache_fails_closed_without_loader(
    modules, evidence, monkeypatch
):
    p, projection = modules

    def forbidden(*_args, **_kwargs):
        pytest.fail("cold cache should fail closed rather than load a module")

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(projection.ProjectionError, match="^staging projection rejected$"):
            projection.project_detached_inventory(evidence)


@pytest.fixture
def drift(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_drift")


def test_offline_drift_same_observation_is_stable_and_immutable(drift, evidence, modules):
    _, projector = modules
    report = drift.compare_detached_observations(evidence, evidence)
    sha = projector.project_detached_inventory(evidence).sha256
    assert type(report) is drift.DetachedDriftReport
    assert report.before_sha256 == report.after_sha256 == sha
    assert report.incident == "stale-target"
    assert not report.has_drift
    assert report.added_paths == ()
    assert report.removed_paths == ()
    assert report.modified_entries == ()
    assert not report.marker_changed
    assert not report.parent_changed
    assert not report.selected_metadata_changed
    with pytest.raises(FrozenInstanceError):
        report.has_drift = True


def test_offline_drift_reports_one_changed_regular_file_metadata(drift, evidence, modules):
    _p, projector = modules
    entries = list(evidence.selected.inventory)
    index = next(i for i, x in enumerate(entries) if x.path == "target.bundle")
    entries[index] = replace(entries[index], size=entries[index].size + 1)
    altered = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    report = drift.compare_detached_observations(evidence, altered)
    assert report.has_drift
    assert report.before_sha256 == projector.project_detached_inventory(evidence).sha256
    assert report.after_sha256 == projector.project_detached_inventory(altered).sha256
    assert report.before_sha256 != report.after_sha256
    assert report.modified_entries == (drift.ChangedEntry("target.bundle", ("size",)),)
    assert not report.marker_changed
    assert not report.parent_changed
    assert report.added_paths == report.removed_paths == ()


def test_offline_drift_detects_unencoded_marker_timestamp_change(drift, evidence, modules):
    _, projector = modules
    altered = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=31))
    report = drift.compare_detached_observations(evidence, altered)
    assert report.before_sha256 == report.after_sha256
    assert report.before_sha256 == projector.project_detached_inventory(evidence).sha256
    assert report.has_drift
    assert report.marker_changed
    assert report.modified_entries == ()


def test_offline_drift_detects_getconf_ancestor_metadata_change(drift, evidence):
    ancestors = list(evidence.parent.ancestors)
    ancestor = ancestors[1]
    ancestors[1] = replace(
        ancestor, metadata=replace(ancestor.metadata, inode=ancestor.metadata.inode + 1)
    )
    altered = replace(evidence, parent=replace(evidence.parent, ancestors=tuple(ancestors)))
    report = drift.compare_detached_observations(evidence, altered)
    assert report.parent_changed
    assert report.has_drift
    assert report.added_paths == report.removed_paths == report.modified_entries == ()


def test_offline_drift_rejects_mixed_catalogs(drift, evidence, modules):
    p, _ = modules
    alt = p._select_incident("older-target")
    entries = list(evidence.selected.inventory)
    entries[0] = replace(entries[0], inode=alt.inode)
    selected = replace(
        evidence.selected,
        selector="older-target",
        basename=alt.basename,
        inode=alt.inode,
        expected_commit=alt.expected_commit,
        inventory=tuple(entries),
    )
    altered = replace(evidence, selected=selected)
    with pytest.raises(drift.DriftError, match="^staging drift rejected$"):
        drift.compare_detached_observations(evidence, altered)


@pytest.mark.parametrize("side", ["before", "after"])
def test_offline_drift_refuses_invalid_or_forged_source(drift, evidence, side):
    forged = replace(evidence, selected=replace(evidence.selected, inventory=(None,) * 13))
    one, two = (forged, evidence) if side == "before" else (evidence, forged)
    with pytest.raises(drift.DriftError, match="^staging drift rejected$") as failure:
        drift.compare_detached_observations(one, two)
    assert failure.value.__cause__ is None


def test_offline_drift_does_not_access_host_or_observer(drift, evidence, modules, monkeypatch):
    p, _projector = modules

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline diff attempted any host I/O or live observation")

    with monkeypatch.context() as patch:
        for method in ("open", "stat", "scandir", "listdir", "system", "kill", "fork"):
            if hasattr(os, method):
                patch.setattr(os, method, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        report = drift.compare_detached_observations(evidence, evidence)
    assert not report.has_drift


def test_offline_drift_rejects_cold_inventory_cache_without_loader(
    drift, evidence, modules, monkeypatch
):
    p, _ = modules
    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", lambda: pytest.fail("unexpected module load"))
        with pytest.raises(drift.DriftError, match="^staging drift rejected$"):
            drift.compare_detached_observations(evidence, evidence)


def test_offline_drift_identifies_added_and_removed_nested_entry(drift, evidence, modules):
    _p, projector = modules
    old_entries = list(evidence.selected.inventory)
    parent_index = next(
        i for i, item in enumerate(old_entries) if item.path == "payload-content/expected_commit"
    )
    additional = replace(
        old_entries[parent_index],
        path="payload-content/extra.bin",
        inode=202601,
        size=17,
    )
    expanded = old_entries[: parent_index + 1] + [additional] + old_entries[parent_index + 1 :]
    later = replace(evidence, selected=replace(evidence.selected, inventory=tuple(expanded)))
    assert (
        projector.project_detached_inventory(later).sha256
        != projector.project_detached_inventory(evidence).sha256
    )
    added = drift.compare_detached_observations(evidence, later)
    assert added.has_drift
    assert added.added_paths == ("payload-content/extra.bin",)
    assert added.removed_paths == added.modified_entries == ()
    removed = drift.compare_detached_observations(later, evidence)
    assert removed.has_drift
    assert removed.removed_paths == ("payload-content/extra.bin",)
    assert removed.added_paths == removed.modified_entries == ()


def test_offline_drift_tracks_expected_file_metadata_and_selected_binding(drift, evidence):
    entries = list(evidence.selected.inventory)
    index = next(
        i for i, item in enumerate(entries) if item.path == "payload-content/expected_commit"
    )
    entries[index] = replace(entries[index], ctime_ns=entries[index].ctime_ns + 1)
    changed_meta = replace(evidence.selected.expected_metadata, ctime_ns=entries[index].ctime_ns)
    updated = replace(
        evidence,
        selected=replace(
            evidence.selected, inventory=tuple(entries), expected_metadata=changed_meta
        ),
    )
    report = drift.compare_detached_observations(evidence, updated)
    assert report.has_drift
    assert report.selected_metadata_changed
    assert report.modified_entries == (
        drift.ChangedEntry("payload-content/expected_commit", ("ctime_ns",)),
    )


@pytest.mark.parametrize("invalid", [None, True, "stale-target", {}, [], b"fixture"])
def test_offline_drift_refuses_untyped_inputs(drift, evidence, invalid):
    with pytest.raises(drift.DriftError, match="^staging drift rejected$") as failure:
        drift.compare_detached_observations(invalid, evidence)
    assert failure.value.__cause__ is None


def test_offline_drift_artifact_full_comparison_round_trip(drift, evidence, modules, monkeypatch):
    """End-to-end: two pinned-style evidence values -> drift -> bytes -> verified report."""
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    codec = importlib.import_module("staging_drift_artifact")
    entries = list(evidence.selected.inventory)
    at = next(i for i, record in enumerate(entries) if record.path == "target.bundle")
    entries[at] = replace(entries[at], size=entries[at].size + 1)
    changed = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    original_report = drift.compare_detached_observations(evidence, changed)
    artifact = codec.encode_detached_drift(original_report)
    restored = codec.decode_detached_drift(artifact.payload, expected_sha256=artifact.sha256)
    assert restored == original_report
    assert restored.modified_entries == (drift.ChangedEntry("target.bundle", ("size",)),)
    assert restored.has_drift
    assert codec.encode_detached_drift(restored) == artifact
    assert not hasattr(artifact, "inspection")
    assert not hasattr(restored, "receipt")
