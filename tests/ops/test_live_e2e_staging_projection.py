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


@pytest.fixture
def timeline(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_snapshot_timeline")


@pytest.fixture
def timeline_sources(evidence):
    return (
        replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=1)),
        replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=42)),
        replace(evidence, marker_metadata=replace(evidence.marker_metadata, mtime_ns=99)),
    )


def test_snapshot_timeline_three_step_complete_build_verify(timeline, timeline_sources):
    assembled = timeline.build_snapshot_timeline(timeline_sources)
    assert len(assembled.hops) == 2
    assert 0 < len(assembled.manifest.payload) < timeline.MAX_MANIFEST_BYTES
    verified = timeline.verify_snapshot_timeline(
        timeline_sources,
        assembled.hops,
        assembled.manifest.payload,
        expected_sha256=assembled.manifest.sha256,
    )
    assert verified.incident == "stale-target"
    assert len(verified.snapshot_sha256s) == 3
    assert len(verified.seal_sha256s) == 2
    assert verified.snapshot_sha256s[0] != verified.snapshot_sha256s[1]
    assert verified.snapshot_sha256s[1] != verified.snapshot_sha256s[2]
    assert verified.changed_hops == (0, 1)
    assert verified.timeline_sha256 == assembled.manifest.sha256
    assert timeline.build_snapshot_timeline(timeline_sources) == assembled
    with pytest.raises(FrozenInstanceError):
        verified.incident = "older-target"


def test_snapshot_timeline_unchanged_snapshots_are_deterministic(timeline, evidence):
    same = (evidence, evidence, evidence)
    assembled = timeline.build_snapshot_timeline(same)
    verified = timeline.verify_snapshot_timeline(
        same,
        assembled.hops,
        assembled.manifest.payload,
        expected_sha256=assembled.manifest.sha256,
    )
    assert verified.changed_hops == ()
    assert len(set(verified.snapshot_sha256s)) == 1


def test_snapshot_timeline_detects_intermediate_value_splice(timeline, timeline_sources):
    built = timeline.build_snapshot_timeline(timeline_sources)
    manipulated = list(timeline_sources)
    manipulated[1] = replace(
        manipulated[1],
        marker_metadata=replace(manipulated[1].marker_metadata, mtime_ns=43),
    )
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            tuple(manipulated),
            built.hops,
            built.manifest.payload,
            expected_sha256=built.manifest.sha256,
        )


def test_snapshot_timeline_rejects_hop_swap(timeline, timeline_sources):
    built = timeline.build_snapshot_timeline(timeline_sources)
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            tuple(reversed(built.hops)),
            built.manifest.payload,
            expected_sha256=built.manifest.sha256,
        )


def test_snapshot_timeline_rejects_changed_terminal_timestamp_and_reversal(
    timeline,
    timeline_sources,
):
    built = timeline.build_snapshot_timeline(timeline_sources)
    swapped = (timeline_sources[2], timeline_sources[1], timeline_sources[0])
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            swapped, built.hops, built.manifest.payload, expected_sha256=built.manifest.sha256
        )


def test_snapshot_timeline_rejects_forged_canonical_manifest_with_recomputed_sha(
    timeline,
    timeline_sources,
):
    import hashlib

    built = timeline.build_snapshot_timeline(timeline_sources)
    obj = json.loads(built.manifest.payload)
    obj["snapshot_sha256s"][1] = "f" * 64
    forged = json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources, built.hops, forged, expected_sha256=hashlib.sha256(forged).hexdigest()
        )


@pytest.mark.parametrize("raw", [b"{}", b"null", b"[]", b"\xff", b'{"a":1,"a":2}', b"X" * 9000])
def test_snapshot_timeline_rejects_malformed_manifest(timeline, timeline_sources, raw):
    import hashlib

    built = timeline.build_snapshot_timeline(timeline_sources)
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            built.hops,
            raw,
            expected_sha256=hashlib.sha256(raw).hexdigest(),
        )


@pytest.mark.parametrize("count", [0, 1, 18, 19])
def test_snapshot_timeline_strict_source_count(timeline, evidence, count):
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.build_snapshot_timeline((evidence,) * count)


def test_snapshot_timeline_refuses_forged_hop_types(timeline, timeline_sources):
    assembled = timeline.build_snapshot_timeline(timeline_sources)
    forged = (None, assembled.hops[1])
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            forged,
            assembled.manifest.payload,
            expected_sha256=assembled.manifest.sha256,
        )


def test_snapshot_timeline_no_host_calls_and_cold_cache(
    timeline, timeline_sources, modules, monkeypatch
):
    p, _ = modules
    assembled = timeline.build_snapshot_timeline(timeline_sources)

    def forbidden(*_args, **_kwargs):
        pytest.fail("timeline touched host or dynamically loaded module")

    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "fork", "kill", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        assert (
            timeline.verify_snapshot_timeline(
                timeline_sources,
                assembled.hops,
                assembled.manifest.payload,
                expected_sha256=assembled.manifest.sha256,
            ).timeline_sha256
            == assembled.manifest.sha256
        )

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
            timeline.build_snapshot_timeline(timeline_sources)


def test_snapshot_timeline_allows_sixteen_bounded_hops(timeline, evidence):
    maximal = (evidence,) * 17
    built = timeline.build_snapshot_timeline(maximal)
    report = timeline.verify_snapshot_timeline(
        maximal,
        built.hops,
        built.manifest.payload,
        expected_sha256=built.manifest.sha256,
    )
    assert len(report.snapshot_sha256s) == 17
    assert len(report.seal_sha256s) == 16
    assert report.changed_hops == ()


def test_snapshot_timeline_supports_extreme_negative_nonwire_value(timeline, timeline_sources):
    middle = replace(
        timeline_sources[1],
        marker_metadata=replace(timeline_sources[1].marker_metadata, mtime_ns=-(10**5000)),
    )
    chain = (timeline_sources[0], middle, timeline_sources[2])
    built = timeline.build_snapshot_timeline(chain)
    verified = timeline.verify_snapshot_timeline(
        chain,
        built.hops,
        built.manifest.payload,
        expected_sha256=built.manifest.sha256,
    )
    assert verified.changed_hops == (0, 1)
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            built.hops,
            built.manifest.payload,
            expected_sha256=built.manifest.sha256,
        )


def test_snapshot_timeline_refuses_wrong_container_type_and_hop_count(
    timeline, evidence, timeline_sources
):
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.build_snapshot_timeline([evidence, evidence])
    built = timeline.build_snapshot_timeline(timeline_sources)
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            built.hops[:-1],
            built.manifest.payload,
            expected_sha256=built.manifest.sha256,
        )
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            list(built.hops),
            built.manifest.payload,
            expected_sha256=built.manifest.sha256,
        )


def test_snapshot_timeline_rejects_correct_hash_noncanonical_json(
    timeline,
    timeline_sources,
):
    import hashlib

    built = timeline.build_snapshot_timeline(timeline_sources)
    raw = json.dumps(
        json.loads(built.manifest.payload),
        sort_keys=False,
        indent=1,
        ensure_ascii=True,
    ).encode("ascii")
    assert raw != built.manifest.payload
    with pytest.raises(timeline.TimelineError, match="^staging snapshot timeline rejected$"):
        timeline.verify_snapshot_timeline(
            timeline_sources,
            built.hops,
            raw,
            expected_sha256=hashlib.sha256(raw).hexdigest(),
        )


@pytest.fixture
def timeline_summary(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_timeline_summary")


def _make_timeline_summary(timeline, timeline_summary, snapshots):
    chain = timeline.build_snapshot_timeline(snapshots)
    summary = timeline_summary.build_timeline_change_summary(
        snapshots,
        chain.hops,
        chain.manifest.payload,
        expected_timeline_sha256=chain.manifest.sha256,
    )
    return chain, summary


def test_timeline_summary_reports_only_bounded_counts_and_flags(
    timeline, timeline_summary, timeline_sources
):
    chain, summary = _make_timeline_summary(timeline, timeline_summary, timeline_sources)
    parsed = json.loads(summary.payload)
    assert parsed["schema_version"] == 1
    assert parsed["incident"] == "stale-target"
    assert parsed["timeline_sha256"] == chain.manifest.sha256
    assert parsed["changed_hops"] == [0, 1]
    assert len(parsed["hops"]) == 2
    assert all(hop["marker_changed"] and hop["changed"] for hop in parsed["hops"])
    assert all(hop["added_count"] == 0 and hop["removed_count"] == 0 for hop in parsed["hops"])
    assert all(
        hop["modified_count"] == 0 and not hop["inventory_changed"] for hop in parsed["hops"]
    )
    assert b"mtime_ns" not in summary.payload
    assert b"payload-content" not in summary.payload
    checked = timeline_summary.verify_timeline_change_summary(
        timeline_sources,
        chain.hops,
        chain.manifest.payload,
        summary.payload,
        expected_timeline_sha256=chain.manifest.sha256,
        expected_summary_sha256=summary.sha256,
    )
    assert checked.summary_sha256 == summary.sha256
    assert checked.timeline_sha256 == chain.manifest.sha256
    assert checked.changed_hops == (0, 1)
    assert len(checked.hops) == 2
    assert (
        timeline_summary.build_timeline_change_summary(
            timeline_sources,
            chain.hops,
            chain.manifest.payload,
            expected_timeline_sha256=chain.manifest.sha256,
        )
        == summary
    )
    with pytest.raises(FrozenInstanceError):
        checked.hops = ()


def test_timeline_summary_empty_changes(timeline, timeline_summary, evidence):
    sources = (evidence, evidence, evidence)
    _, summary = _make_timeline_summary(timeline, timeline_summary, sources)
    raw = json.loads(summary.payload)
    assert raw["changed_hops"] == []
    assert all(not hop["changed"] for hop in raw["hops"])


def test_timeline_summary_rejects_intermediate_splice(timeline, timeline_summary, timeline_sources):
    chain, summary = _make_timeline_summary(timeline, timeline_summary, timeline_sources)
    mutated = list(timeline_sources)
    mutated[1] = replace(
        mutated[1],
        marker_metadata=replace(mutated[1].marker_metadata, mtime_ns=77),
    )
    with pytest.raises(
        timeline_summary.TimelineSummaryError, match="^staging timeline summary rejected$"
    ):
        timeline_summary.verify_timeline_change_summary(
            tuple(mutated),
            chain.hops,
            chain.manifest.payload,
            summary.payload,
            expected_timeline_sha256=chain.manifest.sha256,
            expected_summary_sha256=summary.sha256,
        )


def test_timeline_summary_rejects_swapped_hops(timeline, timeline_summary, timeline_sources):
    chain, summary = _make_timeline_summary(timeline, timeline_summary, timeline_sources)
    with pytest.raises(timeline_summary.TimelineSummaryError):
        timeline_summary.verify_timeline_change_summary(
            timeline_sources,
            tuple(reversed(chain.hops)),
            chain.manifest.payload,
            summary.payload,
            expected_timeline_sha256=chain.manifest.sha256,
            expected_summary_sha256=summary.sha256,
        )


def test_timeline_summary_rejects_recomputed_forged_digest(
    timeline, timeline_summary, timeline_sources
):
    chain, summary = _make_timeline_summary(timeline, timeline_summary, timeline_sources)
    forged = json.loads(summary.payload)
    forged["hops"][0]["marker_changed"] = False
    raw = json.dumps(forged, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    with pytest.raises(
        timeline_summary.TimelineSummaryError, match="^staging timeline summary rejected$"
    ):
        timeline_summary.verify_timeline_change_summary(
            timeline_sources,
            chain.hops,
            chain.manifest.payload,
            raw,
            expected_timeline_sha256=chain.manifest.sha256,
            expected_summary_sha256=hashlib.sha256(raw).hexdigest(),
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"\xff",
        b'{"schema_version":1,"schema_version":1}',
        b"x" * 9000,
    ],
)
def test_timeline_summary_rejects_malformed_wire(timeline, timeline_summary, timeline_sources, raw):
    chain, _ = _make_timeline_summary(timeline, timeline_summary, timeline_sources)
    with pytest.raises(
        timeline_summary.TimelineSummaryError, match="^staging timeline summary rejected$"
    ):
        timeline_summary.verify_timeline_change_summary(
            timeline_sources,
            chain.hops,
            chain.manifest.payload,
            raw,
            expected_timeline_sha256=chain.manifest.sha256,
            expected_summary_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_timeline_summary_rejects_noncanonical_even_with_new_hash(
    timeline, timeline_summary, timeline_sources
):
    chain, summary = _make_timeline_summary(timeline, timeline_summary, timeline_sources)
    raw = json.dumps(json.loads(summary.payload), indent=1).encode("ascii")
    with pytest.raises(timeline_summary.TimelineSummaryError):
        timeline_summary.verify_timeline_change_summary(
            timeline_sources,
            chain.hops,
            chain.manifest.payload,
            raw,
            expected_timeline_sha256=chain.manifest.sha256,
            expected_summary_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_timeline_summary_max_sixteen_hops(timeline, timeline_summary, evidence):
    chain, summary = _make_timeline_summary(timeline, timeline_summary, (evidence,) * 17)
    assert len(json.loads(summary.payload)["hops"]) == 16
    assert len(summary.payload) <= timeline_summary.MAX_SUMMARY_BYTES
    assert len(chain.hops) == 16


def test_timeline_summary_huge_signed_metadata_and_no_global_guard_change(
    timeline, timeline_summary, timeline_sources
):
    import sys

    guard_before = sys.get_int_max_str_digits()
    middle = replace(
        timeline_sources[1],
        marker_metadata=replace(timeline_sources[1].marker_metadata, mtime_ns=-(10**5000)),
    )
    chain, summary = _make_timeline_summary(
        timeline, timeline_summary, (timeline_sources[0], middle, timeline_sources[2])
    )
    assert json.loads(summary.payload)["changed_hops"] == [0, 1]
    assert len(chain.hops) == 2
    assert sys.get_int_max_str_digits() == guard_before


def test_timeline_summary_no_host_io(
    timeline, timeline_summary, timeline_sources, modules, monkeypatch
):
    p, _ = modules
    chain, summary = _make_timeline_summary(timeline, timeline_summary, timeline_sources)

    def forbidden(*_args, **_kwargs):
        pytest.fail("summary accessed host or trusted workflow")

    with monkeypatch.context() as patch:
        for method in ("open", "stat", "scandir", "listdir", "kill", "system", "fork"):
            if hasattr(os, method):
                patch.setattr(os, method, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        checked = timeline_summary.verify_timeline_change_summary(
            timeline_sources,
            chain.hops,
            chain.manifest.payload,
            summary.payload,
            expected_timeline_sha256=chain.manifest.sha256,
            expected_summary_sha256=summary.sha256,
        )
    assert checked.timeline_sha256 == chain.manifest.sha256


def test_timeline_summary_reports_inventory_modification_counts(
    timeline, timeline_summary, evidence
):
    entries = list(evidence.selected.inventory)
    index = next(i for i, entry in enumerate(entries) if entry.path == "target.bundle")
    entries[index] = replace(entries[index], size=entries[index].size + 1)
    altered = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    _, summary = _make_timeline_summary(timeline, timeline_summary, (evidence, altered))
    hop = json.loads(summary.payload)["hops"][0]
    assert hop["modified_count"] == 1
    assert hop["added_count"] == hop["removed_count"] == 0
    assert hop["inventory_changed"]
    assert hop["changed"]
    assert not hop["marker_changed"]
    assert b"target.bundle" not in summary.payload


def test_timeline_summary_rejects_cold_fixed_inventory_cache(
    timeline, timeline_summary, timeline_sources, modules, monkeypatch
):
    p, _ = modules
    chain = timeline.build_snapshot_timeline(timeline_sources)
    monkeypatch.setattr(p, "_FIXED_INVENTORY_MODULE", None)

    def forbidden(*_args, **_kwargs):
        pytest.fail("cold inventory cache tried to access host")

    monkeypatch.setattr(p, "_fixed_inventory_module", forbidden)
    with pytest.raises(
        timeline_summary.TimelineSummaryError, match="^staging timeline summary rejected$"
    ):
        timeline_summary.build_timeline_change_summary(
            timeline_sources,
            chain.hops,
            chain.manifest.payload,
            expected_timeline_sha256=chain.manifest.sha256,
        )


def test_timeline_summary_oversized_valid_json_rejected_before_parse(
    timeline, timeline_summary, timeline_sources, monkeypatch
):
    chain = timeline.build_snapshot_timeline(timeline_sources)
    raw = b'{"pad":"' + (b"x" * timeline_summary.MAX_SUMMARY_BYTES) + b'"}'
    assert len(raw) > timeline_summary.MAX_SUMMARY_BYTES

    def forbidden(*_args, **_kwargs):
        pytest.fail("oversize summary reached JSON parser")

    with monkeypatch.context() as patch:
        patch.setattr(timeline_summary.json, "loads", forbidden)
        with pytest.raises(
            timeline_summary.TimelineSummaryError,
            match="^staging timeline summary rejected$",
        ):
            timeline_summary.verify_timeline_change_summary(
                timeline_sources,
                chain.hops,
                chain.manifest.payload,
                raw,
                expected_timeline_sha256=chain.manifest.sha256,
                expected_summary_sha256=hashlib.sha256(raw).hexdigest(),
            )


@pytest.fixture
def timeline_audit(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_timeline_audit")


def _audit_build(timeline, audit, sources):
    built = timeline.build_snapshot_timeline(sources)
    report = audit.build_timeline_audit(
        sources,
        built.hops,
        built.manifest.payload,
        expected_timeline_sha256=built.manifest.sha256,
    )
    return built, report


def _audit_verify(timeline, audit, sources, built, report):
    return audit.verify_timeline_audit(
        sources,
        built.hops,
        built.manifest.payload,
        report.payload,
        expected_timeline_sha256=built.manifest.sha256,
        expected_audit_sha256=report.sha256,
    )


def test_timeline_audit_full_transition_and_net_change(timeline, timeline_audit, timeline_sources):
    built, report = _audit_build(timeline, timeline_audit, timeline_sources)
    verified = _audit_verify(timeline, timeline_audit, timeline_sources, built, report)
    assert verified.incident == "stale-target"
    assert verified.timeline_sha256 == built.manifest.sha256
    assert verified.audit_sha256 == report.sha256
    assert verified.net_changed is True
    assert verified.changed_hops == (0, 1)
    assert verified.stable_hops == ()
    assert verified.revisited_snapshots == ()
    assert len(verified.hops) == 2
    assert all(hop.marker_changed for hop in verified.hops)
    assert all(hop.has_drift for hop in verified.hops)
    assert report == timeline_audit.build_timeline_audit(
        timeline_sources,
        built.hops,
        built.manifest.payload,
        expected_timeline_sha256=built.manifest.sha256,
    )
    with pytest.raises(FrozenInstanceError):
        verified.net_changed = False


def test_timeline_audit_revisit_and_stable_hops(timeline, timeline_audit, timeline_sources):
    a, b, _ = timeline_sources
    sources = (a, b, a, a)
    built, report = _audit_build(timeline, timeline_audit, sources)
    verified = _audit_verify(timeline, timeline_audit, sources, built, report)
    assert verified.net_changed is False
    assert verified.changed_hops == (0, 1)
    assert verified.stable_hops == (2,)
    assert verified.revisited_snapshots == ((2, 0),)
    assert verified.hops[2].has_drift is False
    assert len(verified.hops) == 3


def test_timeline_audit_rejects_forged_content_even_with_new_digest(
    timeline, timeline_audit, timeline_sources
):
    import hashlib

    built, report = _audit_build(timeline, timeline_audit, timeline_sources)
    for field, replacement in (
        ("net_changed", False),
        ("changed_hops", []),
        ("timeline_sha256", "0" * 64),
    ):
        forged = json.loads(report.payload)
        forged[field] = replacement
        raw = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode("ascii")
        with pytest.raises(timeline_audit.AuditError):
            timeline_audit.verify_timeline_audit(
                timeline_sources,
                built.hops,
                built.manifest.payload,
                raw,
                expected_timeline_sha256=built.manifest.sha256,
                expected_audit_sha256=hashlib.sha256(raw).hexdigest(),
            )


def test_timeline_audit_rejects_invalid_json_and_types(timeline, timeline_audit, timeline_sources):
    import hashlib

    built, report = _audit_build(timeline, timeline_audit, timeline_sources)
    mutated = (
        report.payload + b" ",
        b"{}",
        b'{"schema_version":1,"schema_version":1}',
        b"\xff",
        b"x" * (timeline_audit.MAX_AUDIT_BYTES + 1),
    )
    for raw in mutated:
        with pytest.raises(timeline_audit.AuditError) as error:
            timeline_audit.verify_timeline_audit(
                timeline_sources,
                built.hops,
                built.manifest.payload,
                raw,
                expected_timeline_sha256=built.manifest.sha256,
                expected_audit_sha256=hashlib.sha256(raw).hexdigest(),
            )
        assert str(error.value) == "staging timeline audit rejected"
        assert error.value.__cause__ is None
    for bad in ("bytes", bytearray(report.payload), None):
        with pytest.raises(timeline_audit.AuditError):
            timeline_audit.verify_timeline_audit(
                timeline_sources,
                built.hops,
                built.manifest.payload,
                bad,
                expected_timeline_sha256=built.manifest.sha256,
                expected_audit_sha256=report.sha256,
            )


def test_timeline_audit_rejects_source_splice_and_hop_swap(
    timeline, timeline_audit, timeline_sources
):
    built, report = _audit_build(timeline, timeline_audit, timeline_sources)
    changed = list(timeline_sources)
    changed[1] = replace(
        changed[1], marker_metadata=replace(changed[1].marker_metadata, mtime_ns=43)
    )
    with pytest.raises(timeline_audit.AuditError):
        _audit_verify(timeline, timeline_audit, tuple(changed), built, report)
    bad = replace(built, hops=tuple(reversed(built.hops)))
    with pytest.raises(timeline_audit.AuditError):
        _audit_verify(timeline, timeline_audit, timeline_sources, bad, report)


def test_timeline_audit_sixteen_hops_and_rejects_bad_counts(
    timeline, timeline_audit, timeline_sources
):
    a, b, _ = timeline_sources
    sources = tuple(a if i % 2 == 0 else b for i in range(17))
    built, report = _audit_build(timeline, timeline_audit, sources)
    verified = _audit_verify(timeline, timeline_audit, sources, built, report)
    assert len(verified.hops) == 16
    assert len(verified.changed_hops) == 16
    assert len(verified.revisited_snapshots) == 15
    with pytest.raises(timeline_audit.AuditError):
        timeline_audit.build_timeline_audit(
            sources + (a,),
            built.hops,
            built.manifest.payload,
            expected_timeline_sha256=built.manifest.sha256,
        )
    with pytest.raises(timeline_audit.AuditError):
        timeline_audit.build_timeline_audit(
            list(sources),
            built.hops,
            built.manifest.payload,
            expected_timeline_sha256=built.manifest.sha256,
        )


def test_timeline_audit_exact_file_field_detail(timeline, timeline_audit, evidence):
    entries = list(evidence.selected.inventory)
    index = next(i for i, entry in enumerate(entries) if entry.path == "target.bundle")
    entries[index] = replace(entries[index], size=entries[index].size + 1)
    modified = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    sources = (evidence, modified, evidence)
    built, report = _audit_build(timeline, timeline_audit, sources)
    verified = _audit_verify(timeline, timeline_audit, sources, built, report)
    assert verified.net_changed is False
    assert verified.revisited_snapshots == ((2, 0),)
    assert verified.hops[0].modified_entries == (("target.bundle", ("size",)),)
    assert verified.hops[1].modified_entries == (("target.bundle", ("size",)),)
    assert verified.hops[0].added_paths == verified.hops[0].removed_paths == ()
    assert not verified.hops[0].marker_changed


def test_timeline_audit_rejects_extra_fields_and_wrong_digest(
    timeline, timeline_audit, timeline_sources
):
    import hashlib

    built, report = _audit_build(timeline, timeline_audit, timeline_sources)
    extra = json.loads(report.payload)
    extra["untrusted"] = True
    raw = json.dumps(extra, separators=(",", ":"), sort_keys=True).encode("ascii")
    with pytest.raises(timeline_audit.AuditError):
        timeline_audit.verify_timeline_audit(
            timeline_sources,
            built.hops,
            built.manifest.payload,
            raw,
            expected_timeline_sha256=built.manifest.sha256,
            expected_audit_sha256=hashlib.sha256(raw).hexdigest(),
        )
    with pytest.raises(timeline_audit.AuditError):
        timeline_audit.verify_timeline_audit(
            timeline_sources,
            built.hops,
            built.manifest.payload,
            report.payload,
            expected_timeline_sha256=built.manifest.sha256,
            expected_audit_sha256=report.sha256.upper(),
        )
    with pytest.raises(timeline_audit.AuditError):
        timeline_audit.verify_timeline_audit(
            timeline_sources,
            built.hops,
            built.manifest.payload,
            report.payload,
            expected_timeline_sha256="0" * 64,
            expected_audit_sha256=report.sha256,
        )


def test_timeline_audit_offline_only_and_cold_cache(
    timeline, timeline_audit, timeline_sources, modules, monkeypatch
):
    p, _projector = modules
    built, report = _audit_build(timeline, timeline_audit, timeline_sources)

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline timeline audit attempted host I/O or dynamic inventory loading")

    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "fork", "kill", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        assert (
            _audit_verify(timeline, timeline_audit, timeline_sources, built, report).audit_sha256
            == report.sha256
        )

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(timeline_audit.AuditError):
            timeline_audit.build_timeline_audit(
                timeline_sources,
                built.hops,
                built.manifest.payload,
                expected_timeline_sha256=built.manifest.sha256,
            )


def test_timeline_audit_extreme_signed_metadata_without_global_guard_change(
    timeline, timeline_audit, timeline_sources, monkeypatch
):
    import sys

    baseline = sys.get_int_max_str_digits()
    source = timeline_sources[1]
    source = replace(source, marker_metadata=replace(source.marker_metadata, mtime_ns=-(10**5000)))

    def forbidden(*_args):
        pytest.fail("audit modified process-wide integer conversion guard")

    monkeypatch.setattr(sys, "set_int_max_str_digits", forbidden)
    sources = (timeline_sources[0], source, timeline_sources[2])
    built, report = _audit_build(timeline, timeline_audit, sources)
    verified = _audit_verify(timeline, timeline_audit, sources, built, report)
    assert verified.changed_hops == (0, 1)
    assert sys.get_int_max_str_digits() == baseline


@pytest.fixture
def timeline_casefiles(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_timeline_casefiles")


def test_casefiles_end_to_end_public_and_private(timeline_casefiles, timeline_sources):
    case = timeline_casefiles
    public = case.build_public_casefile(timeline_sources)
    private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
    outer = json.loads(public.payload)
    assert outer["schema_version"] == 1 and outer["audience"] == "public"
    assert outer["timeline"]["schema_version"] == 1
    assert outer["summary"]["schema_version"] == 1
    assert outer["summary"]["changed_hops"] == [0, 1]
    assert outer["timeline_sha256"] == outer["summary"]["timeline_sha256"]
    assert len(public.payload) <= case.MAX_PUBLIC_CASEFILE_BYTES
    assert b"target.bundle" not in public.payload
    assert b"mtime_ns" not in public.payload
    assert b"payload-content" not in public.payload
    private_doc = json.loads(private.payload)
    assert private_doc["audience"] == "private"
    assert private_doc["public_casefile_sha256"] == public.sha256
    assert private_doc["audit"]["changed_hops"] == [0, 1]
    checked_public = case.verify_public_casefile(
        timeline_sources, public.payload, expected_sha256=public.sha256
    )
    checked_private = case.verify_private_casefile(
        timeline_sources,
        public.payload,
        private.payload,
        expected_public_sha256=public.sha256,
        expected_private_sha256=private.sha256,
        allow_sensitive_paths=True,
    )
    assert checked_public.changed_hops == (0, 1)
    assert checked_public.public_sha256 == public.sha256
    assert checked_private.public == checked_public
    assert checked_private.audit.audit_sha256 == private_doc["audit_sha256"]
    assert case.build_public_casefile(timeline_sources) == public
    assert case.build_private_casefile(timeline_sources, allow_sensitive_paths=True) == private
    assert "mtime_ns" not in repr(private)


def test_casefiles_private_contains_exact_sensitive_path(timeline_casefiles, evidence):
    case = timeline_casefiles
    entries = list(evidence.selected.inventory)
    i = next(i for i, entry in enumerate(entries) if entry.path == "target.bundle")
    entries[i] = replace(entries[i], size=entries[i].size + 8)
    modified = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    sources = (evidence, modified, evidence)
    public = case.build_public_casefile(sources)
    private = case.build_private_casefile(sources, allow_sensitive_paths=True)
    assert b"target.bundle" not in public.payload
    assert b"target.bundle" in private.payload
    assert b"size" in private.payload
    assert (
        case.verify_private_casefile(
            sources,
            public.payload,
            private.payload,
            expected_public_sha256=public.sha256,
            expected_private_sha256=private.sha256,
            allow_sensitive_paths=True,
        ).audit.net_changed
        is False
    )


@pytest.mark.parametrize("permission", [False, 1, None, "", "yes"])
def test_casefiles_explicit_sensitive_opt_in(timeline_casefiles, timeline_sources, permission):
    with pytest.raises(
        timeline_casefiles.CasefileError, match="^staging timeline casefile rejected$"
    ):
        timeline_casefiles.build_private_casefile(
            timeline_sources, allow_sensitive_paths=permission
        )
    public = timeline_casefiles.build_public_casefile(timeline_sources)
    with pytest.raises(
        timeline_casefiles.CasefileError, match="^staging timeline casefile rejected$"
    ):
        timeline_casefiles.verify_private_casefile(
            timeline_sources,
            public.payload,
            b"{}",
            expected_public_sha256=public.sha256,
            expected_private_sha256="0" * 64,
            allow_sensitive_paths=permission,
        )


@pytest.mark.parametrize("kind", ["summary", "timeline", "timeline_sha256", "audience"])
def test_casefiles_reject_forged_public_even_with_new_hash(
    timeline_casefiles, timeline_sources, kind
):
    case = timeline_casefiles
    original = case.build_public_casefile(timeline_sources)
    document = json.loads(original.payload)
    if kind == "summary":
        document["summary"]["hops"][0]["added_count"] += 1
    elif kind == "timeline":
        document["timeline"]["snapshot_sha256s"][1] = "f" * 64
    elif kind == "timeline_sha256":
        document["timeline_sha256"] = "f" * 64
    else:
        document["audience"] = "private"
    forged = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$") as error:
        case.verify_public_casefile(
            timeline_sources, forged, expected_sha256=hashlib.sha256(forged).hexdigest()
        )
    assert error.value.__cause__ is None


def test_casefiles_reject_private_audit_or_link_forgery(timeline_casefiles, timeline_sources):
    case = timeline_casefiles
    public = case.build_public_casefile(timeline_sources)
    private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
    for change in ("audit", "link", "digest"):
        document = json.loads(private.payload)
        if change == "audit":
            document["audit"]["net_changed"] = not document["audit"]["net_changed"]
        elif change == "link":
            document["public_casefile_sha256"] = "a" * 64
        else:
            document["audit_sha256"] = "b" * 64
        forged = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_private_casefile(
                timeline_sources,
                public.payload,
                forged,
                expected_public_sha256=public.sha256,
                expected_private_sha256=hashlib.sha256(forged).hexdigest(),
                allow_sensitive_paths=True,
            )


def test_casefiles_reject_source_splice_and_reordering(timeline_casefiles, timeline_sources):
    case = timeline_casefiles
    public = case.build_public_casefile(timeline_sources)
    private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
    changed = list(timeline_sources)
    changed[1] = replace(
        changed[1], marker_metadata=replace(changed[1].marker_metadata, ctime_ns=123)
    )
    for sources in (tuple(changed), tuple(reversed(timeline_sources))):
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_public_casefile(sources, public.payload, expected_sha256=public.sha256)
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_private_casefile(
                sources,
                public.payload,
                private.payload,
                expected_public_sha256=public.sha256,
                expected_private_sha256=private.sha256,
                allow_sensitive_paths=True,
            )


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"null",
        b"[]",
        b"\\xff",
        b'{"a":1,"a":2}',
        b'{"audience":"public","audience":"public"}',
        b" " * 32769,
    ],
)
def test_casefiles_reject_malformed_public(timeline_casefiles, timeline_sources, raw):
    case = timeline_casefiles
    with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
        case.verify_public_casefile(
            timeline_sources, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_casefiles_reject_noncanonical_private_public_and_wrong_digest(
    timeline_casefiles, timeline_sources
):
    case = timeline_casefiles
    public = case.build_public_casefile(timeline_sources)
    private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
    for raw in (public.payload + b" ", json.dumps(json.loads(public.payload), indent=2).encode()):
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_public_casefile(
                timeline_sources, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
            )
    with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
        case.verify_public_casefile(timeline_sources, public.payload, expected_sha256="0" * 64)
    for raw in (private.payload + b" ", b'{"a":1,"a":2}', b" " * (160 * 1024 + 1)):
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_private_casefile(
                timeline_sources,
                public.payload,
                raw,
                expected_public_sha256=public.sha256,
                expected_private_sha256=hashlib.sha256(raw).hexdigest(),
                allow_sensitive_paths=True,
            )


def test_casefiles_max_sixteen_hops_and_revisits(timeline_casefiles, evidence):
    case = timeline_casefiles
    sources = (evidence,) * 17
    public = case.build_public_casefile(sources)
    private = case.build_private_casefile(sources, allow_sensitive_paths=True)
    assert len(json.loads(public.payload)["summary"]["hops"]) == 16
    assert len(json.loads(private.payload)["audit"]["stable_hops"]) == 16
    assert (
        case.verify_public_casefile(
            sources, public.payload, expected_sha256=public.sha256
        ).changed_hops
        == ()
    )
    with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
        case.build_public_casefile((evidence,) * 18)
    with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
        case.build_private_casefile((evidence,), allow_sensitive_paths=True)


def test_casefiles_no_host_io_and_cold_cache(
    timeline_casefiles, timeline_sources, modules, monkeypatch
):
    p, _ = modules
    case = timeline_casefiles

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline casefile touched host or dynamic inventory loader")

    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "fork", "kill", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        public = case.build_public_casefile(timeline_sources)
        private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
        assert (
            case.verify_public_casefile(
                timeline_sources, public.payload, expected_sha256=public.sha256
            ).public_sha256
            == public.sha256
        )
        assert (
            case.verify_private_casefile(
                timeline_sources,
                public.payload,
                private.payload,
                expected_public_sha256=public.sha256,
                expected_private_sha256=private.sha256,
                allow_sensitive_paths=True,
            ).audit.audit_sha256
            == json.loads(private.payload)["audit_sha256"]
        )
    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.build_public_casefile(timeline_sources)
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)


def test_casefiles_extreme_signed_timestamp(timeline_casefiles, timeline_sources):
    case = timeline_casefiles
    changed = replace(
        timeline_sources[1],
        marker_metadata=replace(timeline_sources[1].marker_metadata, mtime_ns=-(10**5000)),
    )
    sources = (timeline_sources[0], changed, timeline_sources[2])
    public = case.build_public_casefile(sources)
    private = case.build_private_casefile(sources, allow_sensitive_paths=True)
    assert case.verify_private_casefile(
        sources,
        public.payload,
        private.payload,
        expected_public_sha256=public.sha256,
        expected_private_sha256=private.sha256,
        allow_sensitive_paths=True,
    ).audit.changed_hops == (0, 1)


def test_casefiles_reject_genuine_private_public_cross_pair(timeline_casefiles, timeline_sources):
    case = timeline_casefiles
    first_public = case.build_public_casefile(timeline_sources)
    first_private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
    changed = list(timeline_sources)
    changed[1] = replace(
        changed[1],
        marker_metadata=replace(changed[1].marker_metadata, mtime_ns=117),
    )
    second_sources = tuple(changed)
    second_public = case.build_public_casefile(second_sources)
    second_private = case.build_private_casefile(second_sources, allow_sensitive_paths=True)
    assert first_public.sha256 != second_public.sha256
    assert first_private.sha256 != second_private.sha256
    for public, private in (
        (first_public, second_private),
        (second_public, first_private),
    ):
        with pytest.raises(
            case.CasefileError, match="^staging timeline casefile rejected$"
        ) as error:
            case.verify_private_casefile(
                timeline_sources,
                public.payload,
                private.payload,
                expected_public_sha256=public.sha256,
                expected_private_sha256=private.sha256,
                allow_sensitive_paths=True,
            )
        assert error.value.__cause__ is None


def test_casefiles_reject_nonbyte_and_nondigest_inputs(timeline_casefiles, timeline_sources):
    case = timeline_casefiles
    public = case.build_public_casefile(timeline_sources)
    private = case.build_private_casefile(timeline_sources, allow_sensitive_paths=True)
    for raw in (None, "{}", bytearray(public.payload), True):
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_public_casefile(timeline_sources, raw, expected_sha256=public.sha256)
    for digest in (None, b"0" * 64, "Z" * 64, "0" * 63, True):
        with pytest.raises(case.CasefileError, match="^staging timeline casefile rejected$"):
            case.verify_private_casefile(
                timeline_sources,
                public.payload,
                private.payload,
                expected_public_sha256=public.sha256,
                expected_private_sha256=digest,
                allow_sensitive_paths=True,
            )


def test_casefile_public_never_invokes_path_bearing_audit(
    timeline_casefiles, timeline_sources, monkeypatch
):
    case = timeline_casefiles

    def forbidden(*_args, **_kwargs):
        pytest.fail("public casefile built private path audit")

    with monkeypatch.context() as patch:
        patch.setattr(case, "build_timeline_audit", forbidden)
        patch.setattr(case, "verify_timeline_audit", forbidden)
        public = case.build_public_casefile(timeline_sources)
        assert b"target.bundle" not in public.payload
        assert case.verify_public_casefile(
            timeline_sources, public.payload, expected_sha256=public.sha256
        ).changed_hops == (0, 1)


@pytest.fixture
def casefile_series(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_casefile_series")


@pytest.fixture
def series_sources(timeline_sources):
    a, b, c = timeline_sources
    return ((a, b, c), (c, c, a), (a, b, c))


def test_series_full_multisegment_roundtrip_and_revisits(casefile_series, series_sources):
    series = casefile_series
    record = series.build_public_casefile_series(series_sources)
    report = json.loads(record.payload)
    assert report["audience"] == "public"
    assert report["schema_version"] == 1
    assert report["incident"] == "stale-target"
    assert report["segment_count"] == 3
    assert report["hop_count"] == 6
    assert report["changed_hops"] == [0, 1, 3, 4, 5]
    assert report["stable_hops"] == [2]
    assert report["net_changed"]
    assert report["revisited_snapshots"] == [
        {"snapshot_index": 4, "first_matching_index": 0},
        {"snapshot_index": 5, "first_matching_index": 1},
        {"snapshot_index": 6, "first_matching_index": 2},
    ]
    assert len(report["snapshot_sha256s"]) == 7
    assert len(report["segments"]) == 3
    assert all(s["public_casefile_sha256"] for s in report["segments"])
    assert sum(s["hop_count"] for s in report["segments"]) == 6
    assert b"target.bundle" not in record.payload
    assert b"mtime_ns" not in record.payload
    verified = series.verify_public_casefile_series(
        series_sources, record.payload, expected_sha256=record.sha256
    )
    assert verified.hop_count == 6
    assert verified.changed_hops == (0, 1, 3, 4, 5)
    assert verified.revisited_snapshots == ((4, 0), (5, 1), (6, 2))
    assert verified.series_sha256 == record.sha256
    assert series.build_public_casefile_series(series_sources) == record
    with pytest.raises(FrozenInstanceError):
        verified.hop_count = 42


def test_series_rejects_gap_between_individually_valid_casefiles(casefile_series, timeline_sources):
    a, b, c = timeline_sources
    # Each segment is valid, but its shared boundary differs.
    for gaps in (((a, b), (c, a)), ((a, b), (a, b))):
        with pytest.raises(
            casefile_series.SeriesError, match="^staging casefile series rejected$"
        ) as failure:
            casefile_series.build_public_casefile_series(gaps)
        assert failure.value.__cause__ is None


def test_series_rejects_source_splice_or_segment_reorder(casefile_series, series_sources):
    series = casefile_series
    built = series.build_public_casefile_series(series_sources)
    left = list(series_sources)
    left[0] = (
        left[0][0],
        replace(left[0][1], marker_metadata=replace(left[0][1].marker_metadata, mtime_ns=7)),
        left[0][2],
    )
    for sources in (tuple(left), (series_sources[1], series_sources[0], series_sources[2])):
        with pytest.raises(series.SeriesError, match="^staging casefile series rejected$"):
            series.verify_public_casefile_series(
                sources, built.payload, expected_sha256=built.sha256
            )


@pytest.mark.parametrize(
    "field",
    [
        "changed_hops",
        "stable_hops",
        "snapshot_sha256s",
        "segments",
        "aggregate",
        "incident",
        "revisited_snapshots",
    ],
)
def test_series_rejects_forged_canonical_report_with_recomputed_hash(
    casefile_series, series_sources, field
):
    series = casefile_series
    built = series.build_public_casefile_series(series_sources)
    content = json.loads(built.payload)
    if field == "changed_hops":
        content[field].pop()
    elif field == "stable_hops":
        content[field].append(0)
    elif field == "snapshot_sha256s":
        content[field][1] = "f" * 64
    elif field == "segments":
        content[field][0]["public_casefile_sha256"] = "0" * 64
    elif field == "aggregate":
        content[field]["modified_count"] += 1
    elif field == "incident":
        content[field] = "forged"
    else:
        content[field].clear()
    raw = json.dumps(content, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(series.SeriesError, match="^staging casefile series rejected$"):
        series.verify_public_casefile_series(
            series_sources, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}",
        b"null",
        b"[]",
        b"\xff",
        b'{"a":1,"a":2}',
        b" " * (64 * 1024 + 1),
    ],
)
def test_series_rejects_noncanonical_malformed_oversize(casefile_series, series_sources, raw):
    with pytest.raises(casefile_series.SeriesError, match="^staging casefile series rejected$"):
        casefile_series.verify_public_casefile_series(
            series_sources, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_series_refuses_wrong_inputs_and_wrong_digest(casefile_series, series_sources):
    series = casefile_series
    for source in ([], {}, None, (), (series_sources[0],), (series_sources[0],) * 9):
        with pytest.raises(series.SeriesError, match="^staging casefile series rejected$"):
            series.build_public_casefile_series(source)
    built = series.build_public_casefile_series(series_sources)
    for digest in (True, None, b"0" * 64, "Z" * 64, "0" * 63):
        with pytest.raises(series.SeriesError, match="^staging casefile series rejected$"):
            series.verify_public_casefile_series(
                series_sources, built.payload, expected_sha256=digest
            )


def test_series_max_eight_segments_128_hops(casefile_series, evidence):
    segment = (evidence,) * 17
    sources = (segment,) * 8
    built = casefile_series.build_public_casefile_series(sources)
    content = json.loads(built.payload)
    assert content["segment_count"] == 8
    assert content["hop_count"] == 128
    assert content["changed_hops"] == []
    assert len(content["snapshot_sha256s"]) == 129
    assert len(built.payload) <= casefile_series.MAX_SERIES_BYTES
    checked = casefile_series.verify_public_casefile_series(
        sources, built.payload, expected_sha256=built.sha256
    )
    assert checked.hop_count == 128
    with pytest.raises(casefile_series.SeriesError):
        casefile_series.build_public_casefile_series(sources + (segment,))


def test_series_no_host_io_and_never_constructs_private_report(
    casefile_series, series_sources, modules, monkeypatch
):
    p, _ = modules
    case = importlib.import_module("staging_timeline_casefiles")

    def forbidden(*_args, **_kwargs):
        pytest.fail("series reached host, loader or private auditor")

    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "fork", "kill", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        patch.setattr(case, "build_private_casefile", forbidden)
        patch.setattr(case, "build_timeline_audit", forbidden)
        built = casefile_series.build_public_casefile_series(series_sources)
        assert (
            casefile_series.verify_public_casefile_series(
                series_sources, built.payload, expected_sha256=built.sha256
            ).hop_count
            == 6
        )

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(casefile_series.SeriesError):
            casefile_series.build_public_casefile_series(series_sources)


def test_series_huge_negative_timestamp_and_unchanged_global_digit_guard(
    casefile_series, timeline_sources
):
    import sys

    before = sys.get_int_max_str_digits()
    a, b, c = timeline_sources
    long = replace(b, marker_metadata=replace(b.marker_metadata, ctime_ns=-(10**5000)))
    sources = ((a, long), (long, c))
    built = casefile_series.build_public_casefile_series(sources)
    checked = casefile_series.verify_public_casefile_series(
        sources, built.payload, expected_sha256=built.sha256
    )
    assert checked.hop_count == 2
    assert sys.get_int_max_str_digits() == before


def test_series_rejects_correct_hash_noncanonical_json(casefile_series, series_sources):
    built = casefile_series.build_public_casefile_series(series_sources)
    raw = json.dumps(json.loads(built.payload), indent=2).encode("ascii")
    assert raw != built.payload
    with pytest.raises(casefile_series.SeriesError, match="^staging casefile series rejected$"):
        casefile_series.verify_public_casefile_series(
            series_sources, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_series_rejects_overbound_valid_json_before_parsing(
    casefile_series, series_sources, monkeypatch
):
    raw = b'{"padding":"' + b"x" * (casefile_series.MAX_SERIES_BYTES) + b'"}'
    assert len(raw) > casefile_series.MAX_SERIES_BYTES

    def fail(*_args, **_kwargs):
        pytest.fail("oversized series reached JSON parser")

    with monkeypatch.context() as patch:
        patch.setattr(casefile_series.json, "loads", fail)
        with pytest.raises(casefile_series.SeriesError, match="^staging casefile series rejected$"):
            casefile_series.verify_public_casefile_series(
                series_sources, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
            )


@pytest.fixture
def private_casefile_series(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_private_casefile_series")


def test_private_series_complete_build_verify_with_public_binding(
    private_casefile_series, series_sources
):
    case = private_casefile_series
    pub, private = case.build_private_casefile_series(series_sources, allow_sensitive_paths=True)
    outer = json.loads(private.payload)
    public = json.loads(pub.payload)
    assert outer["schema_version"] == 1
    assert outer["audience"] == "private"
    assert outer["public_series_sha256"] == pub.sha256
    assert outer["segment_count"] == 3
    assert outer["hop_count"] == public["hop_count"] == 6
    assert outer["changed_hops"] == public["changed_hops"]
    assert len(outer["segments"]) == 3
    assert all(item["private_casefile_sha256"] for item in outer["segments"])
    assert tuple(item["hop_offset"] for item in outer["segments"]) == (0, 2, 4)
    assert b"target.bundle" not in pub.payload
    assert len(private.payload) <= case.MAX_PRIVATE_SERIES_BYTES
    checked = case.verify_private_casefile_series(
        series_sources,
        pub.payload,
        private.payload,
        expected_public_sha256=pub.sha256,
        expected_private_sha256=private.sha256,
        allow_sensitive_paths=True,
    )
    assert checked.public.series_sha256 == pub.sha256
    assert checked.private_series_sha256 == private.sha256
    assert len(checked.private_segment_sha256s) == 3
    assert "private_series_sha256" not in repr(private)
    assert "audit" not in repr(checked)
    assert case.build_private_casefile_series(series_sources, allow_sensitive_paths=True) == (
        pub,
        private,
    )
    with pytest.raises(FrozenInstanceError):
        private.payload = b"altered"


def test_private_series_includes_paths_only_in_private(private_casefile_series, evidence):
    entries = list(evidence.selected.inventory)
    index = next(i for i, row in enumerate(entries) if row.path == "target.bundle")
    entries[index] = replace(entries[index], size=entries[index].size + 1)
    changed = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    sources = ((evidence, changed), (changed, evidence))
    pub, private = private_casefile_series.build_private_casefile_series(
        sources, allow_sensitive_paths=True
    )
    assert b"target.bundle" not in pub.payload
    assert b"target.bundle" in private.payload
    assert b"size" in private.payload
    assert (
        private_casefile_series.verify_private_casefile_series(
            sources,
            pub.payload,
            private.payload,
            expected_public_sha256=pub.sha256,
            expected_private_sha256=private.sha256,
            allow_sensitive_paths=True,
        ).public.net_changed
        is False
    )
    assert "target.bundle" not in repr(private)


@pytest.mark.parametrize("flag", [None, False, 0, 1, "true", [], {}])
def test_private_series_requires_exact_true(private_casefile_series, series_sources, flag):
    case = private_casefile_series
    with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
        case.build_private_casefile_series(series_sources, allow_sensitive_paths=flag)
    with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
        case.verify_private_casefile_series(
            series_sources,
            b"{}",
            b"{}",
            expected_public_sha256="0" * 64,
            expected_private_sha256="0" * 64,
            allow_sensitive_paths=flag,
        )


@pytest.mark.parametrize(
    "field",
    [
        "public_series_sha256",
        "segment_count",
        "hop_count",
        "changed_hops",
        "net_changed",
        "segments",
        "private_casefile_sha256",
        "audit",
    ],
)
def test_private_series_rejects_rehashed_forged_content(
    private_casefile_series, series_sources, field
):
    case = private_casefile_series
    pub, private = case.build_private_casefile_series(series_sources, allow_sensitive_paths=True)
    parsed = json.loads(private.payload)
    if field == "public_series_sha256":
        parsed[field] = "f" * 64
    elif field == "segment_count" or field == "hop_count":
        parsed[field] += 1
    elif field == "changed_hops":
        parsed[field].clear()
    elif field == "net_changed":
        parsed[field] = not parsed[field]
    elif field == "segments":
        parsed[field][0]["hop_offset"] += 1
    elif field == "private_casefile_sha256":
        parsed["segments"][0][field] = "f" * 64
    else:
        parsed["segments"][0]["audit"]["net_changed"] = not parsed["segments"][0]["audit"][
            "net_changed"
        ]
    raw = json.dumps(parsed, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$") as exc:
        case.verify_private_casefile_series(
            series_sources,
            pub.payload,
            raw,
            expected_public_sha256=pub.sha256,
            expected_private_sha256=hashlib.sha256(raw).hexdigest(),
            allow_sensitive_paths=True,
        )
    assert exc.value.__cause__ is None


def test_private_series_rejects_genuine_mismatched_public_private(
    private_casefile_series, series_sources
):
    case = private_casefile_series
    left_pub, left_priv = case.build_private_casefile_series(
        series_sources, allow_sensitive_paths=True
    )
    changed = list(series_sources)
    src = list(changed[1])
    src[1] = replace(src[1], marker_metadata=replace(src[1].marker_metadata, ctime_ns=156))
    changed[1] = tuple(src)
    # The new tuple is internally valid and has unchanged cross-segment endpoints.
    right_pub, right_priv = case.build_private_casefile_series(
        tuple(changed), allow_sensitive_paths=True
    )
    assert left_pub.sha256 != right_pub.sha256
    for pub, priv in ((left_pub, right_priv), (right_pub, left_priv)):
        with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
            case.verify_private_casefile_series(
                series_sources,
                pub.payload,
                priv.payload,
                expected_public_sha256=pub.sha256,
                expected_private_sha256=priv.sha256,
                allow_sensitive_paths=True,
            )


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        True,
        "{}",
        bytearray(b"{}"),
        b"{}",
        b"null",
        b"[]",
        bytes([255]),
        b'{"a":1,"a":2}',
        b" " * ((2 * 1024 * 1024) + 1),
    ],
)
def test_private_series_rejects_invalid_wire_before_source(
    private_casefile_series, series_sources, raw
):
    case = private_casefile_series
    pub = importlib.import_module("staging_casefile_series").build_public_casefile_series(
        series_sources
    )
    digest = hashlib.sha256(raw).hexdigest() if type(raw) is bytes else "0" * 64
    with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
        case.verify_private_casefile_series(
            series_sources,
            pub.payload,
            raw,
            expected_public_sha256=pub.sha256,
            expected_private_sha256=digest,
            allow_sensitive_paths=True,
        )


def test_private_series_rejects_source_splice_or_segment_reorder(
    private_casefile_series, series_sources
):
    case = private_casefile_series
    pub, private = case.build_private_casefile_series(series_sources, allow_sensitive_paths=True)
    changed = list(series_sources)
    src = list(changed[0])
    src[1] = replace(src[1], marker_metadata=replace(src[1].marker_metadata, mtime_ns=1001))
    changed[0] = tuple(src)
    for sources in (tuple(changed), (series_sources[1], series_sources[0], series_sources[2])):
        with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
            case.verify_private_casefile_series(
                sources,
                pub.payload,
                private.payload,
                expected_public_sha256=pub.sha256,
                expected_private_sha256=private.sha256,
                allow_sensitive_paths=True,
            )


def test_private_series_max_eight_segments_and_128_hops(private_casefile_series, evidence):
    sources = ((evidence,) * 17,) * 8
    pub, private = private_casefile_series.build_private_casefile_series(
        sources, allow_sensitive_paths=True
    )
    parsed = json.loads(private.payload)
    assert parsed["segment_count"] == 8
    assert parsed["hop_count"] == 128
    assert len(private.payload) <= private_casefile_series.MAX_PRIVATE_SERIES_BYTES
    assert (
        private_casefile_series.verify_private_casefile_series(
            sources,
            pub.payload,
            private.payload,
            expected_public_sha256=pub.sha256,
            expected_private_sha256=private.sha256,
            allow_sensitive_paths=True,
        ).public.hop_count
        == 128
    )
    with pytest.raises(private_casefile_series.PrivateSeriesError):
        private_casefile_series.build_private_casefile_series(
            sources + (sources[0],), allow_sensitive_paths=True
        )


def test_private_series_no_host_io_and_cold_cache(
    private_casefile_series, series_sources, modules, monkeypatch
):
    p, _projection = modules
    case = private_casefile_series

    def forbidden(*_args, **_kwargs):
        pytest.fail("private series triggered live inspection, process or loader")

    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "fork", "kill", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, forbidden)
        patch.setattr(p, "_observe_detached_joint_preflight", forbidden)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        pub, private = case.build_private_casefile_series(
            series_sources, allow_sensitive_paths=True
        )
        assert (
            case.verify_private_casefile_series(
                series_sources,
                pub.payload,
                private.payload,
                expected_public_sha256=pub.sha256,
                expected_private_sha256=private.sha256,
                allow_sensitive_paths=True,
            ).private_series_sha256
            == private.sha256
        )

    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", forbidden)
        with pytest.raises(case.PrivateSeriesError):
            case.build_private_casefile_series(series_sources, allow_sensitive_paths=True)


def test_private_series_rejects_overbound_valid_json_before_parsing(
    private_casefile_series, series_sources, monkeypatch
):
    case = private_casefile_series
    raw = b'{"padding":"' + b"x" * case.MAX_PRIVATE_SERIES_BYTES + b'"}'
    assert len(raw) > case.MAX_PRIVATE_SERIES_BYTES

    def forbidden(*_args, **_kwargs):
        pytest.fail("oversized private series entered JSON parser")

    with monkeypatch.context() as patch:
        patch.setattr(case.json, "loads", forbidden)
        with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
            case._validate(
                raw,
                hashlib.sha256(raw).hexdigest(),
                max_bytes=case.MAX_PRIVATE_SERIES_BYTES,
            )


def test_private_series_rejects_noncanonical_with_correct_hash(
    private_casefile_series, series_sources
):
    case = private_casefile_series
    public, private = case.build_private_casefile_series(series_sources, allow_sensitive_paths=True)
    raw = json.dumps(json.loads(private.payload), ensure_ascii=True, indent=2).encode("ascii")
    assert raw != private.payload
    with pytest.raises(case.PrivateSeriesError, match="^staging private series rejected$"):
        case.verify_private_casefile_series(
            series_sources,
            public.payload,
            raw,
            expected_public_sha256=public.sha256,
            expected_private_sha256=hashlib.sha256(raw).hexdigest(),
            allow_sensitive_paths=True,
        )


def test_private_series_extreme_negative_nonwire_metadata(
    private_casefile_series, timeline_sources
):
    import sys

    initial_digit_guard = sys.get_int_max_str_digits()
    a, b, c = timeline_sources
    large = replace(b, marker_metadata=replace(b.marker_metadata, ctime_ns=-(10**5000)))
    sources = ((a, large), (large, c))
    public, private = private_casefile_series.build_private_casefile_series(
        sources, allow_sensitive_paths=True
    )
    checked = private_casefile_series.verify_private_casefile_series(
        sources,
        public.payload,
        private.payload,
        expected_public_sha256=public.sha256,
        expected_private_sha256=private.sha256,
        allow_sensitive_paths=True,
    )
    assert checked.public.hop_count == 2
    assert sys.get_int_max_str_digits() == initial_digit_guard


@pytest.fixture
def comparison_dossier(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "ops/live-e2e"))
    return importlib.import_module("staging_comparison_dossier")


@pytest.fixture
def dossier_sources(series_sources):
    left = series_sources
    right = list(left)
    altered = list(right[1])
    altered[1] = replace(
        altered[1],
        marker_metadata=replace(altered[1].marker_metadata, ctime_ns=818),
    )
    right[1] = tuple(altered)
    return left, tuple(right)


def test_dossier_complete_public_and_private_comparison(comparison_dossier, dossier_sources):
    dossier = comparison_dossier
    left, right = dossier_sources
    public = dossier.build_public_comparison(left, right)
    report = json.loads(public.payload)
    assert report["schema_version"] == 1
    assert report["audience"] == "public"
    assert report["incident"] == "stale-target"
    assert report["left_series_sha256"] != report["right_series_sha256"]
    assert report["left_hop_count"] == report["right_hop_count"] == 6
    assert report["shared_prefix_snapshots"] == 3
    assert report["different_snapshot_indices"] == [3]
    assert report["identical_hops"] == [0, 1, 4, 5]
    assert report["different_hops"] == [2, 3]
    assert report["left_only_hops"] == report["right_only_hops"] == []
    assert len(report["hops"]) == 6
    assert b"target.bundle" not in public.payload
    assert b"mtime_ns" not in public.payload
    assert len(public.payload) <= dossier.MAX_PUBLIC_COMPARISON_BYTES
    checked = dossier.verify_public_comparison(
        left, right, public.payload, expected_sha256=public.sha256
    )
    assert checked.different_hops == (2, 3)
    assert checked.public_sha256 == public.sha256
    assert dossier.build_public_comparison(left, right) == public

    paired_public, private = dossier.build_private_comparison(
        left, right, allow_sensitive_paths=True
    )
    assert paired_public == public
    private_doc = json.loads(private.payload)
    assert private_doc["audience"] == "private"
    assert private_doc["public_comparison_sha256"] == public.sha256
    assert private_doc["left_private_series_sha256"] != private_doc["right_private_series_sha256"]
    assert len(private_doc["hops"]) == 6
    private_checked = dossier.verify_private_comparison(
        left,
        right,
        public.payload,
        private.payload,
        expected_public_sha256=public.sha256,
        expected_private_sha256=private.sha256,
        allow_sensitive_paths=True,
    )
    assert private_checked.public == checked
    assert private_checked.private_sha256 == private.sha256
    assert "audit" not in repr(private)
    assert "audit" not in repr(private_checked)


def test_dossier_identical_runs_and_changed_path_separation(comparison_dossier, evidence):
    entries = list(evidence.selected.inventory)
    index = next(i for i, item in enumerate(entries) if item.path == "target.bundle")
    entries[index] = replace(entries[index], size=entries[index].size + 9)
    changed = replace(evidence, selected=replace(evidence.selected, inventory=tuple(entries)))
    left = ((evidence, changed), (changed, evidence))
    right = ((evidence, evidence), (evidence, evidence))
    pub = comparison_dossier.build_public_comparison(left, right)
    priv_pub, private = comparison_dossier.build_private_comparison(
        left, right, allow_sensitive_paths=True
    )
    assert priv_pub == pub
    raw = json.loads(private.payload)
    assert b"target.bundle" not in pub.payload
    assert b"target.bundle" in private.payload
    assert raw["hops"][0]["left_only_effects"] == [
        {"effect": "modified", "path": "target.bundle", "fields": ["size"]}
    ]
    assert raw["hops"][0]["right_only_effects"] == []
    same = comparison_dossier.build_public_comparison(left, left)
    assert json.loads(same.payload)["different_hops"] == []
    assert len(json.loads(same.payload)["identical_hops"]) == 2


def test_dossier_handles_different_hop_lengths(comparison_dossier, series_sources):
    a, b, c = series_sources[0]
    left = series_sources
    right = ((a, b), (b, c))
    pub = comparison_dossier.build_public_comparison(left, right)
    raw = json.loads(pub.payload)
    assert raw["left_hop_count"] == 6
    assert raw["right_hop_count"] == 2
    assert raw["left_only_hops"] == [2, 3, 4, 5]
    assert raw["right_only_hops"] == []
    assert raw["identical_hops"] == [0, 1]
    assert comparison_dossier.verify_public_comparison(
        left, right, pub.payload, expected_sha256=pub.sha256
    ).left_only_hops == (2, 3, 4, 5)


@pytest.mark.parametrize(
    "field",
    [
        "left_series_sha256",
        "right_series_sha256",
        "different_snapshot_indices",
        "different_hops",
        "identical_hops",
        "shared_prefix_snapshots",
        "counts_delta",
        "hops",
        "incident",
    ],
)
def test_dossier_refuses_public_rehashed_forgery(comparison_dossier, dossier_sources, field):
    left, right = dossier_sources
    built = comparison_dossier.build_public_comparison(left, right)
    doc = json.loads(built.payload)
    if field.endswith("sha256"):
        doc[field] = "f" * 64
    elif field in ("different_snapshot_indices", "different_hops", "identical_hops"):
        doc[field].clear()
    elif field == "shared_prefix_snapshots":
        doc[field] += 1
    elif field == "counts_delta":
        doc[field]["modified_count"] += 1
    elif field == "hops":
        doc[field][0]["classification"] = "different"
    else:
        doc[field] = "forged"
    forged = json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(comparison_dossier.ComparisonError, match="^staging comparison rejected$"):
        comparison_dossier.verify_public_comparison(
            left, right, forged, expected_sha256=hashlib.sha256(forged).hexdigest()
        )


@pytest.mark.parametrize(
    "field",
    [
        "public_comparison_sha256",
        "left_private_series_sha256",
        "right_private_series_sha256",
        "hops",
        "left_only_effects",
        "right_only_effects",
    ],
)
def test_dossier_refuses_private_rehashed_forgery(comparison_dossier, dossier_sources, field):
    left, right = dossier_sources
    public, private = comparison_dossier.build_private_comparison(
        left, right, allow_sensitive_paths=True
    )
    doc = json.loads(private.payload)
    if field.endswith("sha256"):
        doc[field] = "f" * 64
    elif field == "hops":
        doc[field][0]["index"] += 1
    else:
        doc["hops"][0][field].append({"effect": "added", "path": "forged", "fields": []})
    forged = json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(comparison_dossier.ComparisonError, match="^staging comparison rejected$"):
        comparison_dossier.verify_private_comparison(
            left,
            right,
            public.payload,
            forged,
            expected_public_sha256=public.sha256,
            expected_private_sha256=hashlib.sha256(forged).hexdigest(),
            allow_sensitive_paths=True,
        )


@pytest.mark.parametrize("opt_in", [False, None, 0, 1, "yes", (), {}])
def test_dossier_requires_exact_opt_in(comparison_dossier, dossier_sources, opt_in):
    left, right = dossier_sources
    with pytest.raises(comparison_dossier.ComparisonError, match="^staging comparison rejected$"):
        comparison_dossier.build_private_comparison(left, right, allow_sensitive_paths=opt_in)
    with pytest.raises(comparison_dossier.ComparisonError, match="^staging comparison rejected$"):
        comparison_dossier.verify_private_comparison(
            left,
            right,
            b"{}",
            b"{}",
            expected_public_sha256="0" * 64,
            expected_private_sha256="0" * 64,
            allow_sensitive_paths=opt_in,
        )


def test_dossier_rejects_genuine_mismatched_pair_and_source_splice(
    comparison_dossier, dossier_sources
):
    left, right = dossier_sources
    public, private = comparison_dossier.build_private_comparison(
        left, right, allow_sensitive_paths=True
    )
    different = list(right)
    middle = list(different[1])
    middle[1] = replace(middle[1], marker_metadata=replace(middle[1].marker_metadata, ctime_ns=916))
    different[1] = tuple(middle)
    other_public, other_private = comparison_dossier.build_private_comparison(
        left, tuple(different), allow_sensitive_paths=True
    )
    assert public.sha256 != other_public.sha256
    for p, q in ((public, other_private), (other_public, private)):
        with pytest.raises(comparison_dossier.ComparisonError):
            comparison_dossier.verify_private_comparison(
                left,
                right,
                p.payload,
                q.payload,
                expected_public_sha256=p.sha256,
                expected_private_sha256=q.sha256,
                allow_sensitive_paths=True,
            )
    with pytest.raises(comparison_dossier.ComparisonError):
        comparison_dossier.verify_public_comparison(
            left, tuple(different), public.payload, expected_sha256=public.sha256
        )


@pytest.mark.parametrize(
    "raw", [b"{}", b"null", b"[]", bytes([255]), b'{"x":1,"x":2}', b" " * (128 * 1024 + 1)]
)
def test_dossier_refuses_invalid_public_wire(comparison_dossier, dossier_sources, raw):
    left, right = dossier_sources
    with pytest.raises(comparison_dossier.ComparisonError, match="^staging comparison rejected$"):
        comparison_dossier.verify_public_comparison(
            left, right, raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_dossier_no_host_io_private_never_called_in_public(
    comparison_dossier, dossier_sources, modules, monkeypatch
):
    p, _ = modules
    comp = comparison_dossier
    private_module = importlib.import_module("staging_private_casefile_series")

    def fail(*_args, **_kwargs):
        pytest.fail("comparison acquired host I/O or constructed private audit")

    with monkeypatch.context() as patch:
        for name in ("open", "stat", "scandir", "listdir", "kill", "fork", "system"):
            if hasattr(os, name):
                patch.setattr(os, name, fail)
        patch.setattr(p, "_observe_detached_joint_preflight", fail)
        patch.setattr(p, "_fixed_inventory_module", fail)
        patch.setattr(private_module, "build_private_casefile_series", fail)
        left, right = dossier_sources
        public = comp.build_public_comparison(left, right)
        assert comp.verify_public_comparison(
            left, right, public.payload, expected_sha256=public.sha256
        ).different_hops == (2, 3)
    with monkeypatch.context() as patch:
        patch.setattr(p, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(p, "_fixed_inventory_module", fail)
        with pytest.raises(comp.ComparisonError):
            comp.build_public_comparison(*dossier_sources)


def test_dossier_public_maximum_8x16_on_both_sides(comparison_dossier, evidence):
    maximal = ((evidence,) * 17,) * 8
    public = comparison_dossier.build_public_comparison(maximal, maximal)
    report = json.loads(public.payload)
    assert report["left_hop_count"] == report["right_hop_count"] == 128
    assert report["identical_hops"] == list(range(128))
    assert not report["different_hops"]
    assert len(public.payload) <= comparison_dossier.MAX_PUBLIC_COMPARISON_BYTES
    # The 128-hop build already independently rebuilds and verifies both
    # source-bound series. Byte-exact dossier verification is exercised by
    # separate adversarial fixtures; repeating maximal reconstruction here
    # more than doubles runtime and exceeds the hardened 20-minute CI job.
    with pytest.raises(comparison_dossier.ComparisonError):
        comparison_dossier.build_public_comparison(maximal + (maximal[0],), maximal)


def test_dossier_extreme_negative_metadata_preserves_global_guard(
    comparison_dossier, timeline_sources
):
    import sys

    guard = sys.get_int_max_str_digits()
    a, b, c = timeline_sources
    enormous = replace(b, marker_metadata=replace(b.marker_metadata, ctime_ns=-(10**5000)))
    left = ((a, enormous), (enormous, c))
    right = ((a, b), (b, c))
    public = comparison_dossier.build_public_comparison(left, right)
    assert comparison_dossier.verify_public_comparison(
        left, right, public.payload, expected_sha256=public.sha256
    ).different_hops == (0, 1)
    assert sys.get_int_max_str_digits() == guard


def test_dossier_private_cold_cache_fail_closed(
    comparison_dossier, dossier_sources, modules, monkeypatch
):
    preflight, _ = modules

    def fail(*_args, **_kwargs):
        pytest.fail("private comparison used cold-cache loader")

    with monkeypatch.context() as patch:
        patch.setattr(preflight, "_FIXED_INVENTORY_MODULE", None)
        patch.setattr(preflight, "_fixed_inventory_module", fail)
        with pytest.raises(
            comparison_dossier.ComparisonError,
            match="^staging comparison rejected$",
        ) as error:
            comparison_dossier.build_private_comparison(
                *dossier_sources, allow_sensitive_paths=True
            )
        assert error.value.__cause__ is None


def test_dossier_invalid_digest_and_noncanonical_private(comparison_dossier, dossier_sources):
    left, right = dossier_sources
    public, private = comparison_dossier.build_private_comparison(
        left, right, allow_sensitive_paths=True
    )
    for digest in (None, True, b"0" * 64, "f" * 63, "F" * 64):
        with pytest.raises(comparison_dossier.ComparisonError):
            comparison_dossier.verify_public_comparison(
                left, right, public.payload, expected_sha256=digest
            )
    raw = json.dumps(json.loads(private.payload), indent=2, ensure_ascii=True).encode("ascii")
    assert raw != private.payload
    with pytest.raises(comparison_dossier.ComparisonError):
        comparison_dossier.verify_private_comparison(
            left,
            right,
            public.payload,
            raw,
            expected_public_sha256=public.sha256,
            expected_private_sha256=hashlib.sha256(raw).hexdigest(),
            allow_sensitive_paths=True,
        )
