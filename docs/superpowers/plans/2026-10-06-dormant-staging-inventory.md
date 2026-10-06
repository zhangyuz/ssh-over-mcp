# Dormant staging inventory implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task if the proposed native execution method is accepted. Steps use checkbox (`- [ ]`) syntax for tracking. Obtain written plan review before implementation.

**Goal:** Add one dormant, bounded, read-only metadata collector for the standard staging layout, with real-filesystem adversarial tests.

**Architecture:** A stdlib helper receives an already-open directory descriptor and inventories the eleven fixed staging entries. It has no CLI or workflow caller. Incident selection, provider-marker loading, process quiescence, authority/run envelopes and trusted-main workflow activation belong to a subsequent inspection slice; deletion belongs to a separately reviewed apply contract.

**Tech stack:** Python 3.13/3.14, stdlib descriptor-relative filesystem APIs, pytest, Ruff, existing self-hosted Linux CI; disposable local macOS fixtures.

**Spec:** `docs/decisions/0011-incident-bound-e2e-staging-recovery.md`, especially Inspect steps 4–6. Baseline: `cc73b4a70649e4aa2389b7f5fb0da791b7325ccd`.

## Global constraints

- Dormant only: no CLI, workflow integration, operator-state access or persistent-host invocation.
- Read no file contents; no application/Git/package execution, mutation, links followed or recursive cleanup.
- Same device/UID; regular files or directories only; no group/world-writable entries or unexpected inode reuse. Regular-file link count must equal one; ordinary directory link counts are not interpreted as regular-file hardlinks.
- Exact top-level directories: `bootstrap-wheels`, `payload-content`, `payload-iso`, `seed`, `target.git`, `wheels`. Exact regular files: `git-askpass`, `overlay.qcow2`, `payload.iso`, `seed.iso`, `target.bundle`.
- Maximum 4096 total entries including the root record, depth 12 below root, 4096-byte relative paths, 2 MiB canonical inventory JSON, and a 60-second monotonic inspection deadline. Enforce before retaining another entry; equality at a bound is accepted.
- This helper's inventory-size bound does not certify the future complete inspection envelope's 2 MiB bound. The activating slice must check the final envelope independently.
- Preserve generic bounded failures, borrowed-descriptor ownership, fail-closed behavior and all existing recovery/Level-3 authority.
- Self-hosted CI only; no provider-state clearance, deletion approval, Level-3 or A1 closure credit.

## Review focus

1. Replacement while walking: a directory swapped for a symlink or different inode must refuse, even if metadata superficially matches.
2. Special files: FIFO/socket/device entries must refuse promptly without data-capable opens, reads or blocking.
3. Resource exhaustion: wide/deep trees, large metadata paths, serialization growth and deadline expiry must refuse without leaking descriptors or returning a partial success.
4. Names and hardlinks: escaped/non-ASCII names remain exact, path bounds use filesystem bytes, repeated inodes refuse, and ordinary directory link counts remain valid.
5. Concurrent metadata/layout drift: removals, additions or changed directory metadata must invalidate the result; inode/metadata checks do not claim immunity to a compromised same-account writer.

## Files and interfaces

- Create `ops/live-e2e/staging_inventory.py`: collector and canonical inventory encoding only.
- Create `tests/ops/test_live_e2e_staging_inventory.py`: dynamically load the helper using the established ops test pattern; build disposable eleven-entry fixtures.
- Update `tests/live/README.md`: record dormant scope and the future activation boundary.
- Existing CI already lints and compiles all of `ops/live-e2e`; no CI/workflow change is required.

**Produces:**

```python
class InventoryError(RuntimeError): ...

@dataclass(frozen=True, slots=True)
class InventoryEntry:
    path: str
    kind: str  # exactly "directory" or "regular"
    device: int
    inode: int
    uid: int
    gid: int
    mode: int  # permission bits only
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int

def collect_staging_inventory(root_fd: int, *, uid: int) -> tuple[InventoryEntry, ...]: ...
def encode_inventory(entries: tuple[InventoryEntry, ...]) -> bytes: ...
```

Root path is `.`; descendant paths are relative without traversal components. Sort records by filesystem-encoded path bytes. Canonical JSON is UTF-8, `ensure_ascii=True`, sorted object keys and compact separators, with no final newline. Use fixed schema version 1 with exactly `schema_version` and `entries` keys. Never include atime, fresh workflow provenance or inspection-envelope fields in inventory equality.

## Task 1: Read-only descriptor collector and adversarial proof

**Consumes:** an already-open root descriptor owned by the caller, plus the expected UID. This is an internal testable interface, not an operator-selected path API.

- [x] **Step 1 — Establish clean baseline.** Run existing recovery/CI contracts on the new worktree. Expected: 30 PASS. Record supported-platform CI separately from macOS-only limitations.
- [x] **Step 2 — Write focused RED.** Add `test_inventory_records_exact_layout_without_reading_contents`: real fixture with nested directory and regular file; assert root/eleven names, complete metadata, deterministic canonical schema, borrowed root still open, unchanged file contents and no reads/processes/mutations by the helper. Missing helper/API must be the only RED cause.
- [x] **Step 3 — Verify RED.** Run `env PYTHONPATH=src python -m pytest tests/ops/test_live_e2e_staging_inventory.py::test_inventory_records_exact_layout_without_reading_contents -o addopts=--import-mode=importlib`. Expected: intended missing helper/API failure; no dependency/import-environment failure accepted as RED.
- [x] **Step 4 — Minimal GREEN.** Implement the interfaces above using descriptor-relative `stat(..., follow_symlinks=False)`, directory-only `open` with `O_DIRECTORY | O_NOFOLLOW`, and `fstat` identity checks. Keep the borrowed root open and close every owned descriptor on success or failure. Never open regular files for data access. Carry a root device/UID constraint, reject repeated device/inode identities, validate exact top-level layout, and compare directory metadata/listings before and after traversal.
- [x] **Step 5 — Targeted GREEN.** Run the focused test. Expected: PASS; inspect actual records rather than assuming canonical equality from ordering alone.
- [x] **Step 6 — Adversarial RED → minimal GREEN, one failure class at a time.** Add parameterized tests for missing/extra/mistyped top-level entries; root/child symlinks; a real FIFO and Unix socket; regular-file hardlinks; wrong UID/device and writable permissions; inode replacement between stat/open; insertion/removal during traversal; and changed mtime/ctime. Use real objects where feasible, with injection only for unavailable privilege/device transitions. Assert failure produces no inventory and leaves the fixture and borrowed root unchanged. The FIFO test uses a bounded subprocess and kills/reaps only that disposable test child on timeout.
- [x] **Step 7 — Resource/name RED → minimal GREEN.** Test exact and over-limit entry count, depth, filesystem-byte path length and canonical JSON size; injectable monotonic deadline expiry; escaped control characters and non-ASCII names; normal directories with link count greater than one. Use synthetic enumeration/metadata only when independent filesystem limits make the particular bound unreachable in a real fixture; record that distinction. Track all opened owned descriptors and verify closure on every induced failure. Bound retention during collection and encoding; never return partial success.
- [x] **Step 8 — Document dormant scope.** Update `tests/live/README.md` to state no workflow invocation, no incident/marker/process certification and no deletion permission. Record the canonical payload interface for the later inspection envelope.
- [x] **Step 9 — Verification.** Run `env PYTHONPATH=src python -m pytest tests/ops/test_live_e2e_staging_inventory.py tests/ops/test_live_e2e_recovery.py tests/ops/test_ci_workflow.py -o addopts=--import-mode=importlib`, then `python -m ruff check ops/live-e2e tests/ops` and `git diff --check`. Expected: all PASS. Real macOS disposable fixture tests are required; they give no live runner-state or hardware-durability credit.
- [ ] **Step 10 — Review and ship this single slice.** Fresh independent adversarial review; fix every blocking finding with focused RED/GREEN. Commit only the three scoped files, open a small PR, require exact-head self-hosted full 3.13/3.14 CI and a fresh final review, then merge with expected head SHA. No target code runs on the persistent orchestrator.
- [ ] **Step 11 — Verify merge-main and record the actual boundary.** Require exact merge-main ordinary CI PASS. Automatic Level-3 may still refuse the pre-existing provider marker; record the actual result and keep A1 open. Do not clear state or clean incident worktrees to make that gate pass. Preserve evidence and clean this slice's clean worktree only under the applicable recovery cleanup ruling.

## Completion and next slice

Completion means the dormant collector has current tests, exact-head/main ordinary CI and clean review evidence. It does not mean staging is eligible for deletion or that live inspection has occurred.

Next write/review the separate activating inspection contract: fixed incident selection and identities, hardened marker reads, bounded fresh process inventory/quiescence, immutable authority/run envelope, final envelope bound, trusted-main-only manual workflow and successful live read-only evidence. Only after that evidence may apply ceilings, authenticated receipt retrieval, compatibility mapping, cache provisioning and failure-tested journal durability be specified. Unknown `recover.cc8Del` remains excluded throughout.

## Plan review status

The user approved this written plan and native execution on 2026-10-06. Implementation is in progress, with an independent final reviewer: this is one tightly connected helper, so splitting implementation across agents would add coordination without an independent deliverable. No destructive operation is authorized by this plan.
