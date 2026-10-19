# C0 Directory Namespace Drift Refusal Implementation Plan

> For agentic workers: use Superpowers test-driven-development and verification-before-completion, first RED then minimal GREEN.

**Goal:** A bounded C0 directory audit refuses if its opened directory changes during scan/read.
**Architecture:** Reuse existing directory fd in inspect_directory; compare before/after fstat excluding atime; clear partial results and inventory on observed change. Comparison callers already suppress semantic diffs on refused baseline.
**Spec:** docs/superpowers/specs/2026-10-19-t5b0-c0-directory-race-design.md
**Tech Stack:** Python stdlib 3.13/3.14, unittest, hosted pytest bridge.

## Constraints
- At most 64 total directory entries, 16 JSON entries, 16 KiB/file, no-follow files and directory; no new options.
- Deterministic diagnostics, no leakage of URLs or digests, no partial accepted digest/inventory.
- No network, collection, material/root admission, privileged Mac/UID502/APFS or Linux C.

## Review Focus
1. Modify namespace after enumeration while a valid manifest is being read => refuse.
2. Only ctime_ns drift with same mtime_ns => refuse.
3. Only atime_ns drift => stable result, no false refusal.
4. Default and --require-json-only retain all existing entry caps; refused aggregate suppresses semantic diff.
5. Directory unavailable, special/symlink entries, and file drift remain fail-closed.

### Task 1: RED test
**Files:** ops/t5b0/test_c0_manifest_preflight.py
- [ ] Add direct, compare and stream-to-directory checks for detected namespace drift; verify no partial results.
- [ ] Add deterministic synthetic stat ctime-only and atime-only probes.
- [ ] Run focused tests and record expected failure on old code.
- [ ] Commit test-only RED.

### Task 2: Minimal GREEN and evidence
**Files:** ops/t5b0/c0_manifest_preflight.py; docs/evidence/2026-10-17-adr19-t5b0-c0-offline-structure-preflight.md; docs/development-plan.md
- [ ] Add pre/post fstat check using the same already-open FD; refuse and clear results/inventory on drift.
- [ ] Run focused GREEN, full C0 unittest, hosted pytest bridge, Ruff, both-version compile, diff-check.
- [ ] Document limitations and behavior; commit, push Draft PR, exact HEAD hosted CI and independent security review.
