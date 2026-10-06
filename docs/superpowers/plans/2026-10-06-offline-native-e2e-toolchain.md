# Offline native E2E toolchain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Certify a provenance-bound, offline, non-root native toolchain in the
existing pinned guest, then resume Phase 7B1 Task 3.

**Architecture:** Establish the guest no-core guard independently; derive one
closed manifest from authenticated Ubuntu snapshot inputs; land dormant bounded
materialization and fixed non-root feasibility; activate only already-main
authority. Each slice ships separately and preserves all five legacy fixtures.

**Tech Stack:** Trusted stdlib Python, operator-provisioned GPG verifier, Ubuntu
archive metadata/deb data, GCC 15, existing QEMU/HVF and self-hosted Python CI.

**Spec:** [Written native toolchain proposal](../specs/2026-10-06-offline-native-e2e-toolchain-design.md),
[proposed ADR 0010](../../decisions/0010-offline-native-e2e-toolchain.md).

**Status:** Draft for written review; no implementation authorized by this file.
The user approved preparing design/planning artifacts, not activating authority.
Execution method proposed: inline executing-plans, independent review per slice.

## Global Constraints

- 小步快跑，持续迭代，关注质量、安全、一致性。 G1/N1/N2/N3 are separate PRs.
- Self-hosted runners only; ordinary CI and persistent Mac gain no privilege.
- Keep QEMU 11.1.2/HVF, the exact ADR 0008 image, no NIC/shares/credentials.
- Ubuntu archive fingerprint: F6ECB3762474EDA9D21B7022871920D1991BC93C.
- Snapshot: https://snapshot.ubuntu.com/ubuntu/20261005T000000Z/; resolute,
  resolute-updates and resolute-security main binary-amd64. No fallback.
- Only already-main trusted inputs/code judge a target. No target code as root.
- Existing Python build.in/build.lock/e2e-bootstrap.lock remain unchanged.
- Compiler/native helper UID/GID 2204, no supplementary groups, zero
  capabilities, NoNewPrivs=1, core limits (0, 0), attach-before-exec.
- Limits: 64 packages, 256 MiB compressed, 768 MiB expanded, 32,768 entries,
  4,096-byte paths, 128 MiB per file and 40 link hops.
- No apt install, maintainer scripts, root compiler, target flags or generic RPC.
- Keep fixed SSH → MCP → filesystem/profile → Task 6 → Task 7; STOP_MANAGER last.
- No automatic stale-state deletion, casual E2E cancellation or blind recovery.
- Tool proof is not Phase 7B1 acceptance or closure.

## Review Focus

1. Authentic packages but omitted helpers/libraries or image drift: refuse an
   incomplete composition, including after an apparently successful compile.
2. Snapshot/key substitution or stale refresh policy: reject rather than fall
   back to a reachable mirror or infer freshness from download time.
3. Archive collisions/link chains/size expansion: refuse before unsafe writes
   or allocation, preserve unknown pre-existing state.
4. Compiler hooks, surviving writers or substituted output: stop before exec
   and never credit unsealed or unbound artifacts.
5. Old-authority legacy PASS presented as native compatibility: require the
   post-activation main proof with actual compile/link/run and cleanup.

## Files, interfaces and common delivery gate

Use focused modules under ops/live-e2e; no target-facing configuration surface.
All errors expose fixed non-secret text. Tests may inject private fakes; those
are never public root APIs. No module below exists merely because it is named.

For every slice: clean supported baseline → focused intended RED → smallest
GREEN → relevant adversarial/full regression → independent review → pinned
head ordinary CI (Python 3.13/3.14, Ruff/compile) and trusted-main legacy Level-3
→ fresh final review → merge → exact merge-main CI/Level-3 → cleanup. Include
new Python modules in normal lint/compile. Pin actual authority and target SHA;
head changes invalidate evidence. Read trusted run output and provider/guest/
whole-VM/media/bundle cleanup, not just the workflow conclusion.

N3's pre-merge legacy result cannot establish new native behavior; its mandatory
post-merge native preflight is the additional completion gate. No further slice
starts while its merge-main gates remain failed/pending. Docs-only proposal
review does not require activating an E2E authority.

### G1: Establish the guest-only core guard before any target execution

**Files:** Create ops/live-e2e/ledger_guest_preflight.py and
tests/ops/test_ledger_guest_preflight.py; modify the trusted gate, orchestrator
payload list, their contract tests and ops/live-e2e/README.md. This extracts the
already-approved no-core part of parent Task 3; the profile remains separate.

**Interfaces:** GuestPreflightError; establish_guest_no_core() -> None;
require_no_core() -> None. No dependency on ledger_systemd_contract.py.

- [ ] Write RED for pipe/unreadable core pattern, failed write/readback, nonzero
  hard/soft limits and first target exec preceding the guard. Check every
  existing manager/probe direct spawn, inheritance and an unprivileged
  descendant's inability to raise the hard limit; no root test on the Mac.
- [ ] Run python -m pytest tests/ops/test_ledger_guest_preflight.py
  tests/ops/test_live_e2e_gate_contract.py
  tests/ops/test_live_e2e_orchestrator_contract.py -q; record intended RED.
- [ ] Implement fixed fresh-guest-only establishment of pattern "core" and
  limits (0, 0), before first target exec. Child-side verify-before-exec is
  mandatory. No caller path/value, production mutator or target imports.
- [ ] Reach targeted GREEN; review startup failure/cleanup and compile/lint.
  Ship with common gates. Verify the new guard from trusted main in merge-main
  E2E before N2 can execute any compiler/helper.

### N1: Authenticate and derive the complete native input manifest

**Files:** Create ops/live-e2e/native_inputs.py, native-toolchain-inputs.json,
ubuntu-archive-2018.gpg and tests/ops/test_native_inputs.py; update
docs/self-hosted-runner.md and ops/live-e2e/README.md. Archive exact signed
metadata and package receipts in operator-controlled evidence storage.

**Interfaces:** NativeInputError; verify_native_inputs(root: Path) ->
NativeInputs (immutable result); derive_native_manifest(metadata: VerifiedMetadata,
image_inventory: VerifiedImageInventory) -> bytes. These are trusted internal
interfaces; root paths are supplied by fixed orchestration constants.

- [ ] RED: signer/keyring drift, malformed/expired/ambiguous signature, wrong
  date/suite/hash/size, redirect escape, truncated downloads, malformed package
  record, missing dependency/provider, bad Debian version relation, omitted
  transitive edge and image-version mismatch. Distinguish signature validity
  from derivation consistency with a mutated manifest negative test.
- [ ] Run python -m pytest tests/ops/test_native_inputs.py -q for intended RED.
- [ ] Implement bounded authenticated data parsing and explicit provider/version
  selection. Reject unsupported dependency syntax. Generate the complete roots/
  transitive package and file-layout manifest from the frozen signed snapshot;
  published image inventory is only a candidate until pinned guest measurement.
- [ ] Record verifier version/provisioning, public key digest and independent
  fingerprint source. Test clean isolated verifier operation with valid signed
  metadata plus corrupted controls. Do not execute package scripts/compilers.
- [ ] Review the generated complete manifest and proposed command/layout recipe;
  ordinary tests regenerate it and reject drift. An unclosed composition blocks
  this deliverable. Ship with common legacy gates; no native activation yet.

### N2: Materialize a dormant read-only tree and fixed low-privilege helper

**Files:** Create ops/live-e2e/native_materialize.py, native_probe.py,
native_toolchain_probe.c; tests/ops/test_native_materialize.py and
test_native_probe.py. Modify trusted orchestrator packaging of these already-
reviewed inputs and document their dormant status. No automatic guest launch.

**Interfaces:** materialize_native_tree(inputs: NativeInputs) -> NativeTree;
run_native_feasibility(tree: NativeTree) -> NativeEvidence. Fixed paths/UID/
commands belong to trusted constants and the reviewed manifest. NativeEvidence
contains the exact receipt fields in design section 6, not a bare boolean.

- [ ] RED: duplicate/colliding entries, directory metadata conflict, traversal,
  link escape/cycle, special/hardlinked/set-ID/capability entries, expansion
  limits, replaced descriptors/ancestors and unknown pre-existing state.
- [ ] RED: root/extra-group/capability/helper-before-core execution; inherited
  compiler/loader hooks; unexpected specs/plugin/response/search input; cgroup
  attach after exec; mutable tree; missing component; escaped writer; replaced
  ELF; wrong ABI/interpreter/source/authority/image binding. Include real
  non-root compile/link/run controls on supported Linux, without calling that
  pinned-guest proof. Fixed C source has no secrets or enforcement claims.
- [ ] Run python -m pytest tests/ops/test_native_materialize.py
  tests/ops/test_native_probe.py -q and record each intended RED.
- [ ] Implement data-only extraction/materialization, full recipe/closure checks,
  writer quiescence, readonly bind verification, fixed child drop/core/cgroup
  checks and sealed output. Bound output/time; fail with safe codes. Never use
  root ldd or execute target/package/native code as root.
- [ ] Reach targeted GREEN and review the full actual compiler composition and
  command recipe against N1. If relocation/search requires a new layout, revise
  and review the manifest first; no silent fallback. Ship dormant with common
  gates. This proves implementation/regression, not pinned-guest feasibility.

### N3: Activate already-main native preflight and prove pinned-guest behavior

**Files:** Modify trusted gate/orchestrator fixed payload and sequencing,
tests/ops/test_live_e2e_gate_contract.py,
test_live_e2e_orchestrator_contract.py, ops/live-e2e/README.md and parent plan.
All verifier/materializer/helper/source inputs must already be on main.

**Interfaces:** Fixed native preflight runs before the existing five-fixture
probe. The existing commit_sha dispatch remains; no target-controlled mode,
paths or source. Failure produces a bounded trusted error and cleanup.

- [ ] RED: missing/mismatched native input, preflight after target exec, skipped
  guard/fixture, compile/link/run failure reported as success, missing receipt
  binding or guest/provider/whole-VM cleanup. Existing fixture order is intact.
- [ ] Run gate/orchestrator contracts for intended RED. Wire only the N1/N2
  already-main inputs and fixed helper; no new compiler algorithm in activation.
- [ ] Reach GREEN; ship using previously trusted main's complete legacy gates.
  Clearly record that pre-merge proof does not certify the new preflight.
- [ ] After merge, require ordinary CI and trusted-main exact merge-SHA Level-3
  with actual native compile/link/run, measured guest/image composition, bound
  receipt and all five legacy fixtures. Missing evidence blocks completion;
  diagnose a real failure with RED/minimal fix, never sleeps/skips/OS repair.
- [ ] Verify all cleanup, retain non-secret exact run/receipt evidence and remove
  only clean obsolete worktrees/branches. Resume remaining parent Task 3, which
  consumes GuestPreflightError via its ProfileError boundary rather than copying
  the guard. Later Task 7 still proves actual syscall enforcement separately.

## Completion and deviations

Complete only after N3's exact merge-main gates prove native feasibility and
legacy regression with full cleanup. Record this as a prerequisite, not Phase
7B1 implementation complete or closed. No new security acceptance criterion.
Any required image change, package repair, new endpoint, privileged interface
or incompatible composition stops for renewed design review. Task 10's finite
C/H/M plus external E closure boundary remains unchanged.
