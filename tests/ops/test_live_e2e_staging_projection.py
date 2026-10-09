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


@pytest.fixture
def binding(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_drift_binding")


@pytest.fixture
def later_snapshot(evidence):
    entries = list(evidence.selected.inventory)
    index = next(i for i, record in enumerate(entries) if record.path == "target.bundle")
    entries[index] = replace(entries[index], size=entries[index].size + 9)
    return replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))


def test_offline_binding_full_build_verify_round_trip(binding, evidence, later_snapshot, modules):
    _p, projection = modules
    codec = importlib.import_module("staging_drift_artifact")
    artifact = binding.build_detached_drift_artifact(evidence, later_snapshot)
    verified = binding.verify_detached_drift_artifact(
        evidence, later_snapshot, artifact.payload, expected_sha256=artifact.sha256
    )
    assert type(verified) is binding.ConsistentDetachedDrift
    assert verified.report.has_drift
    assert verified.report.modified_entries == (
        importlib.import_module("staging_drift").ChangedEntry("target.bundle", ("size",)),
    )
    assert verified.report.before_sha256 == projection.project_detached_inventory(evidence).sha256
    assert (
        verified.report.after_sha256 == projection.project_detached_inventory(later_snapshot).sha256
    )
    assert verified.artifact_sha256 == artifact.sha256
    assert (
        codec.decode_detached_drift(artifact.payload, expected_sha256=artifact.sha256)
        == verified.report
    )
    with pytest.raises(FrozenInstanceError):
        verified.report = None


def test_offline_binding_identical_snapshots_no_drift(binding, evidence):
    artifact = binding.build_detached_drift_artifact(evidence, evidence)
    report = binding.verify_detached_drift_artifact(
        evidence, evidence, artifact.payload, expected_sha256=artifact.sha256
    )
    assert not report.report.has_drift
    assert report.report.before_sha256 == report.report.after_sha256


def test_offline_binding_rejects_recomputed_checksum_of_forged_metadata_claim(
    binding, evidence, later_snapshot
):
    codec = importlib.import_module("staging_drift_artifact")
    legitimate = binding.build_detached_drift_artifact(evidence, later_snapshot)
    report = codec.decode_detached_drift(legitimate.payload, expected_sha256=legitimate.sha256)
    forged = codec.encode_detached_drift(replace(report, marker_changed=True))
    assert forged.sha256 != legitimate.sha256
    assert codec.decode_detached_drift(forged.payload, expected_sha256=forged.sha256).marker_changed
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$") as failure:
        binding.verify_detached_drift_artifact(
            evidence, later_snapshot, forged.payload, expected_sha256=forged.sha256
        )
    assert failure.value.__cause__ is None


def test_offline_binding_detects_nonwire_marker_mutation_even_with_same_inventory_sha(
    binding, evidence
):
    updated = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=42))
    artifact = binding.build_detached_drift_artifact(evidence, updated)
    report = binding.verify_detached_drift_artifact(
        evidence, updated, artifact.payload, expected_sha256=artifact.sha256
    )
    assert report.report.has_drift
    assert report.report.marker_changed
    assert report.report.before_sha256 == report.report.after_sha256
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.verify_detached_drift_artifact(
            evidence, evidence, artifact.payload, expected_sha256=artifact.sha256
        )


def test_offline_binding_rejects_same_content_digest_but_wrong_report_claims(binding, evidence):
    codec = importlib.import_module("staging_drift_artifact")
    artifact = binding.build_detached_drift_artifact(evidence, evidence)
    report = codec.decode_detached_drift(artifact.payload, expected_sha256=artifact.sha256)
    forged = codec.encode_detached_drift(replace(report, marker_changed=True, has_drift=True))
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.verify_detached_drift_artifact(
            evidence, evidence, forged.payload, expected_sha256=forged.sha256
        )


@pytest.mark.parametrize("invalid", [None, 1, b"garbage", {}, []])
def test_offline_binding_refuses_forged_sources(binding, evidence, invalid):
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$") as failure:
        binding.build_detached_drift_artifact(invalid, evidence)
    assert failure.value.__cause__ is None


def test_offline_binding_rejects_wrong_order_and_one_changed_source(
    binding, evidence, later_snapshot
):
    artifact = binding.build_detached_drift_artifact(evidence, later_snapshot)
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.verify_detached_drift_artifact(
            later_snapshot, evidence, artifact.payload, expected_sha256=artifact.sha256
        )
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.verify_detached_drift_artifact(
            evidence, evidence, artifact.payload, expected_sha256=artifact.sha256
        )


def test_offline_binding_rejects_checksum_and_noncanonical_bytes(binding, evidence):
    artifact = binding.build_detached_drift_artifact(evidence, evidence)
    for raw, digest in [
        (artifact.payload, "0" * 64),
        (
            artifact.payload + b" ",
            importlib.import_module("hashlib").sha256(artifact.payload + b" ").hexdigest(),
        ),
        (b"{" + b"x" * 50, "0" * 64),
    ]:
        with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
            binding.verify_detached_drift_artifact(evidence, evidence, raw, expected_sha256=digest)


def test_offline_binding_cold_cache_fail_closed_without_loader(
    binding, evidence, modules, monkeypatch
):
    p, _ = modules

    def fail(*args, **kwargs):
        pytest.fail("binding triggered a runtime inventory loader")

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", fail)
        with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
            binding.build_detached_drift_artifact(evidence, evidence)
        assert p._FIXED_INVENTORY_MODULE is None


def test_offline_binding_no_live_or_host_calls(
    binding, evidence, later_snapshot, modules, monkeypatch
):
    p, _ = modules

    def fail(*args, **kwargs):
        pytest.fail("offline binding accessed host, process or actual incident")

    artifact = binding.build_detached_drift_artifact(evidence, later_snapshot)
    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "kill", "fork", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, fail)
        patch.setattr(p, "_observe_detached_joint_preflight", fail)
        patch.setattr(p, "_fixed_inventory_module", fail)
        verified = binding.verify_detached_drift_artifact(
            evidence, later_snapshot, artifact.payload, expected_sha256=artifact.sha256
        )
        assert verified.report.has_drift
    for absent in ("receipt", "inspection", "workflow", "authority", "run_id"):
        assert not hasattr(verified, absent)


@pytest.mark.parametrize("field", ["marker_metadata", "parent", "selected"])
def test_offline_binding_detects_changed_source_after_artifact_issuance(
    binding, evidence, later_snapshot, field
):
    artifact = binding.build_detached_drift_artifact(evidence, later_snapshot)
    if field == "marker_metadata":
        modified = replace(
            later_snapshot, marker_metadata=replace(later_snapshot.marker_metadata, ctime_ns=25)
        )
    elif field == "parent":
        ancestors = list(later_snapshot.parent.ancestors)
        ancestors[2] = replace(
            ancestors[2],
            metadata=replace(ancestors[2].metadata, inode=ancestors[2].metadata.inode + 1),
        )
        modified = replace(
            later_snapshot, parent=replace(later_snapshot.parent, ancestors=tuple(ancestors))
        )
    else:
        entries = list(later_snapshot.selected.inventory)
        i = next(i for i, item in enumerate(entries) if item.path == "target.bundle")
        entries[i] = replace(entries[i], mtime_ns=entries[i].mtime_ns + 5)
        modified = replace(
            later_snapshot, selected=replace(later_snapshot.selected, inventory=tuple(entries))
        )
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.verify_detached_drift_artifact(
            evidence, modified, artifact.payload, expected_sha256=artifact.sha256
        )


def test_offline_binding_rejects_cross_incident_build(binding, evidence, modules):
    p, _ = modules
    alternate = p._select_incident("older-target")
    entries = list(evidence.selected.inventory)
    entries[0] = replace(entries[0], inode=alternate.inode)
    before = evidence
    after = replace(
        evidence,
        selected=replace(
            evidence.selected,
            selector="older-target",
            basename=alternate.basename,
            inode=alternate.inode,
            expected_commit=alternate.expected_commit,
            inventory=tuple(entries),
        ),
    )
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.build_detached_drift_artifact(before, after)


@pytest.mark.parametrize("bad", [None, True, 0, "a" * 64, bytearray(b"data")])
def test_offline_binding_rejects_untyped_artifact_payload(binding, evidence, bad):
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$") as failure:
        binding.verify_detached_drift_artifact(evidence, evidence, bad, expected_sha256="0" * 64)
    assert failure.value.__cause__ is None


def test_offline_binding_artifact_flags_forged_with_correct_content_digest(
    binding, evidence, later_snapshot
):
    codec = importlib.import_module("staging_drift_artifact")
    original = binding.build_detached_drift_artifact(evidence, later_snapshot)
    report = codec.decode_detached_drift(original.payload, expected_sha256=original.sha256)
    forged = codec.encode_detached_drift(
        replace(
            report,
            parent_changed=True,
            selected_metadata_changed=True,
        )
    )
    with pytest.raises(binding.BindingError, match="^staging drift binding rejected$"):
        binding.verify_detached_drift_artifact(
            evidence, later_snapshot, forged.payload, expected_sha256=forged.sha256
        )


def test_offline_binding_v1_nonwire_marker_values_are_not_uniquely_bound(binding, evidence):
    """Regression for reviewed lossy v1 semantics; not a raw source fingerprint."""
    before = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=1))
    after_42 = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=42))
    after_99 = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=99))
    artifact = binding.build_detached_drift_artifact(before, after_42)
    baseline = binding.verify_detached_drift_artifact(
        before, after_42, artifact.payload, expected_sha256=artifact.sha256
    )
    same_report_different_value = binding.verify_detached_drift_artifact(
        before, after_99, artifact.payload, expected_sha256=artifact.sha256
    )
    same_report_reversed_pair = binding.verify_detached_drift_artifact(
        after_42, before, artifact.payload, expected_sha256=artifact.sha256
    )
    assert baseline.report.marker_changed
    assert baseline.report.before_sha256 == baseline.report.after_sha256
    assert same_report_different_value == baseline
    assert same_report_reversed_pair == baseline
    assert after_42.marker_metadata != after_99.marker_metadata
    assert before.marker_metadata != after_42.marker_metadata


@pytest.fixture
def seal(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_snapshot_seal")


def test_snapshot_seal_end_to_end_v1(seal, binding, evidence):
    after = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=42))
    drift_artifact = binding.build_detached_drift_artifact(evidence, after)
    artifact = seal.build_snapshot_pair_seal(
        evidence, after, drift_artifact.payload, drift_artifact.sha256
    )
    verified = seal.verify_snapshot_pair_seal(
        evidence,
        after,
        drift_artifact.payload,
        drift_artifact.sha256,
        artifact.payload,
        artifact.sha256,
    )
    assert verified.seal_sha256 == artifact.sha256
    assert verified.before_snapshot_sha256 != verified.after_snapshot_sha256
    assert verified.drift_report.marker_changed
    assert verified.drift_report.before_sha256 == verified.drift_report.after_sha256
    with pytest.raises(FrozenInstanceError):
        verified.after_snapshot_sha256 = "0" * 64
    with pytest.raises(FrozenInstanceError):
        artifact.payload = b""


def test_snapshot_seal_rejects_replaced_nonwire_timestamp_with_same_v1_report(
    seal, binding, evidence
):
    after = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=42))
    after_99 = replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=99))
    drift = binding.build_detached_drift_artifact(evidence, after)
    binding.verify_detached_drift_artifact(
        evidence, after_99, drift.payload, expected_sha256=drift.sha256
    )  # v1 intentionally lossy; the exact same v1 artifact passes.
    full = seal.build_snapshot_pair_seal(evidence, after, drift.payload, drift.sha256)
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.verify_snapshot_pair_seal(
            evidence, after_99, drift.payload, drift.sha256, full.payload, full.sha256
        )


def test_snapshot_seal_rejects_reversal_of_only_nonwire_marker_change(seal, binding, evidence):
    after = replace(evidence, marker_metadata=replace(evidence.marker_metadata, ctime_ns=42))
    drift = binding.build_detached_drift_artifact(evidence, after)
    full = seal.build_snapshot_pair_seal(evidence, after, drift.payload, drift.sha256)
    binding.verify_detached_drift_artifact(
        after, evidence, drift.payload, expected_sha256=drift.sha256
    )  # v1 no direction for marker boolean
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.verify_snapshot_pair_seal(
            after, evidence, drift.payload, drift.sha256, full.payload, full.sha256
        )


def test_snapshot_seal_same_snapshots_has_identical_ordered_fingerprints(seal, binding, evidence):
    drift = binding.build_detached_drift_artifact(evidence, evidence)
    seal_data = seal.build_snapshot_pair_seal(evidence, evidence, drift.payload, drift.sha256)
    verified = seal.verify_snapshot_pair_seal(
        evidence, evidence, drift.payload, drift.sha256, seal_data.payload, seal_data.sha256
    )
    assert verified.before_snapshot_sha256 == verified.after_snapshot_sha256
    assert not verified.drift_report.has_drift
    assert (
        seal.build_snapshot_pair_seal(evidence, evidence, drift.payload, drift.sha256) == seal_data
    )


@pytest.mark.parametrize("field", ["size", "gid", "mtime_ns", "ctime_ns"])
def test_snapshot_seal_binds_all_nonwire_marker_fields(seal, binding, evidence, field):
    after = replace(
        evidence,
        marker_metadata=replace(
            evidence.marker_metadata, **{field: getattr(evidence.marker_metadata, field) + 1}
        ),
    )
    if field == "size":
        # A changed size must remain valid marker 1..4096.
        assert after.marker_metadata.size <= 4096
    drift = binding.build_detached_drift_artifact(evidence, after)
    full = seal.build_snapshot_pair_seal(evidence, after, drift.payload, drift.sha256)
    after_more = replace(
        after,
        marker_metadata=replace(
            after.marker_metadata, **{field: getattr(after.marker_metadata, field) + 1}
        ),
    )
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.verify_snapshot_pair_seal(
            evidence, after_more, drift.payload, drift.sha256, full.payload, full.sha256
        )


def test_snapshot_seal_rejects_self_consistent_forged_fingerprints(seal, binding, evidence):
    import hashlib

    drift = binding.build_detached_drift_artifact(evidence, evidence)
    good = seal.build_snapshot_pair_seal(evidence, evidence, drift.payload, drift.sha256)
    payload = json.loads(good.payload)
    payload["after_snapshot_sha256"] = "f" * 64
    forged = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(forged).hexdigest()
    assert digest != good.sha256
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.verify_snapshot_pair_seal(
            evidence, evidence, drift.payload, drift.sha256, forged, digest
        )


@pytest.mark.parametrize(
    "corruption",
    [
        b"{}",
        b"null",
        b"[]",
        b"\xff",
        b'{"schema_version":1,"schema_version":1}',
        b" " * 1025,
    ],
)
def test_snapshot_seal_rejects_malformed_or_oversized_wire(seal, binding, evidence, corruption):
    import hashlib

    drift = binding.build_detached_drift_artifact(evidence, evidence)
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.verify_snapshot_pair_seal(
            evidence,
            evidence,
            drift.payload,
            drift.sha256,
            corruption,
            hashlib.sha256(corruption).hexdigest(),
        )


@pytest.mark.parametrize("bad", [None, True, 1, b"untyped", {}])
def test_snapshot_seal_refuses_invalid_snapshot_sources(seal, binding, evidence, bad):
    drift = binding.build_detached_drift_artifact(evidence, evidence)
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.build_snapshot_pair_seal(bad, evidence, drift.payload, drift.sha256)


def test_snapshot_seal_no_io_and_cold_cache_fail_closed(
    seal, binding, evidence, modules, monkeypatch
):
    p, _ = modules
    drift = binding.build_detached_drift_artifact(evidence, evidence)
    full = seal.build_snapshot_pair_seal(evidence, evidence, drift.payload, drift.sha256)

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline snapshot seal performed host operation/module load")

    with monkeypatch.context() as patch:
        for name in ("open", "scandir", "stat", "listdir", "system", "fork", "kill"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        assert (
            seal.verify_snapshot_pair_seal(
                evidence, evidence, drift.payload, drift.sha256, full.payload, full.sha256
            ).seal_sha256
            == full.sha256
        )

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
            seal.build_snapshot_pair_seal(evidence, evidence, drift.payload, drift.sha256)


@pytest.mark.parametrize("digits", [5001, 10001])
@pytest.mark.parametrize("negative", [False, True])
@pytest.mark.parametrize("source", ["marker", "expected_commit"])
def test_snapshot_seal_large_signed_timestamp_reuses_local_bounded_decimal(
    seal, binding, evidence, source, digits, negative, monkeypatch
):
    """Existing projector/wire domain allows >4300 signed timestamp digits."""
    import sys

    guard = sys.get_int_max_str_digits()
    value = 10 ** (digits - 1)
    if negative:
        value = -value

    def forbidden(*_args):
        pytest.fail("snapshot seal changed the process-wide integer guard")

    monkeypatch.setattr(sys, "set_int_max_str_digits", forbidden)
    if source == "marker":
        changed = replace(
            evidence,
            marker_metadata=replace(evidence.marker_metadata, mtime_ns=value),
        )
    else:
        entries = list(evidence.selected.inventory)
        index = next(
            i for i, entry in enumerate(entries) if entry.path == "payload-content/expected_commit"
        )
        entries[index] = replace(entries[index], ctime_ns=value)
        changed = replace(
            evidence,
            selected=replace(
                evidence.selected,
                inventory=tuple(entries),
                expected_metadata=replace(evidence.selected.expected_metadata, ctime_ns=value),
            ),
        )
    artifact = binding.build_detached_drift_artifact(evidence, changed)
    assert binding.verify_detached_drift_artifact(
        evidence, changed, artifact.payload, expected_sha256=artifact.sha256
    ).report.has_drift
    packed = seal.build_snapshot_pair_seal(evidence, changed, artifact.payload, artifact.sha256)
    verified = seal.verify_snapshot_pair_seal(
        evidence, changed, artifact.payload, artifact.sha256, packed.payload, packed.sha256
    )
    assert verified.before_snapshot_sha256 != verified.after_snapshot_sha256
    assert verified.seal_sha256 == packed.sha256
    assert sys.get_int_max_str_digits() == guard


def test_snapshot_seal_metadata_bytes_remain_backward_compatible(seal, evidence):
    """No hash-format change for previously accepted ordinary metadata."""
    marker = evidence.marker_metadata
    expected = evidence.selected.expected_metadata
    fields = ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")
    previous = json.dumps(
        {
            "marker_metadata": {name: getattr(marker, name) for name in fields},
            "selected_expected_metadata": {name: getattr(expected, name) for name in fields},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert seal._metadata_fingerprint_bytes(marker, expected) == previous


def test_snapshot_seal_rejects_forged_huge_signed_marker_value(seal, binding, evidence):
    """Both values have the same lossy v1 marker_changed flag, not the same seal."""
    huge = -(10**5000)
    changed = replace(evidence, marker_metadata=replace(evidence.marker_metadata, ctime_ns=huge))
    forged = replace(changed, marker_metadata=replace(changed.marker_metadata, ctime_ns=huge - 1))
    artifact = binding.build_detached_drift_artifact(evidence, changed)
    assert binding.verify_detached_drift_artifact(
        evidence, forged, artifact.payload, expected_sha256=artifact.sha256
    ).report.marker_changed
    pair = seal.build_snapshot_pair_seal(evidence, changed, artifact.payload, artifact.sha256)
    with pytest.raises(seal.SnapshotSealError, match="^staging snapshot seal rejected$"):
        seal.verify_snapshot_pair_seal(
            evidence, forged, artifact.payload, artifact.sha256, pair.payload, pair.sha256
        )
