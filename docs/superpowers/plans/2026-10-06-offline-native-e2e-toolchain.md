# Offline native E2E toolchain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Certify a provenance-bound, offline, non-root native toolchain in the
existing pinned guest, then resume Phase 7B1 Task 3.

**Architecture:** Establish the guest no-core guard independently; derive one
closed manifest from authenticated Ubuntu snapshot inputs; land dormant bounded
materialization and fixed non-root feasibility; prove a bounded already-main
candidate path before mandatory certification, retaining a scoped repair route. Each slice ships separately and preserves all five legacy fixtures.

**Tech Stack:** Trusted stdlib Python, operator-provisioned GPG verifier, Ubuntu
archive metadata/deb data, GCC 15, existing QEMU/HVF and self-hosted Python CI.

**Spec:** [Written native toolchain proposal](../specs/2026-10-06-offline-native-e2e-toolchain-design.md),
[proposed ADR 0010](../../decisions/0010-offline-native-e2e-toolchain.md).

**Status:** Draft for written review; no implementation authorized by this file.
The user approved preparing design/planning artifacts, not activating authority.
Execution method proposed: inline executing-plans, independent review per slice.

## Global Constraints

- 小步快跑，持续迭代，关注质量、安全、一致性。 G1/N1/N2/N3/N4 are separate PRs.
- Self-hosted runners only; ordinary CI and persistent Mac gain no privilege.
- Keep QEMU 11.1.2/HVF, the exact ADR 0008 image, no NIC/shares/credentials.
- Ubuntu archive fingerprint: F6ECB3762474EDA9D21B7022871920D1991BC93C.
- Snapshot: https://snapshot.ubuntu.com/ubuntu/20261005T000000Z/; resolute,
  resolute-updates and resolute-security main binary-amd64. No fallback.
- Only already-main trusted inputs/code judge a target. No target code as root.
- Existing Python build.in/build.lock/e2e-bootstrap.lock remain unchanged.
- Compiler/native helper UID 2204 / GID 3204, no supplementary groups, zero
  capabilities, NoNewPrivs=1, core limits (0, 0), attach-before-exec.
- Limits: 64 packages, 256 MiB compressed, 768 MiB expanded, 32,768 entries,
  4,096-byte paths, 128 MiB per file and 40 link hops.
- No apt install, maintainer scripts, root compiler, target flags or generic RPC.
- Keep fixed SSH → MCP → filesystem/profile → Task 6 → Task 7; STOP_MANAGER last.
- No automatic stale-state deletion, casual E2E cancellation or blind recovery.
- Metadata bounds/time limits are exactly design section 2, independent of
  package-data limits.
- Enabling fail-closed feasibility is distinct from authorizing later canary use.
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

N3's pre-merge legacy result cannot establish new native behavior; its post-merge
candidate proof is the additional completion gate. N4 cannot start before it
passes. Native-authority repair follows the scoped bootstrap cycle in design
section 6; it is completion work on the failed slice, not the next capability. Docs-only proposal
review does not require activating an E2E authority.

### G1: Establish the guest-only core guard before any target execution

**Status:** Complete as the independently approved parent Task 3 slice, PR #127,
merge `8bcdca85172a2b019b8163c39b047b3839574de5`. Exact-head CI
37482879047 / legacy Level-3 37483096793 and exact merge-main CI 37483866613 /
Level-3 37483909137 passed, including provider/guest/VM cleanup; fresh review
found 0 Critical/Important/Minor. This is G1 evidence only; N1–N4 remain pending.

**Files:** Consume already-main ops/live-e2e/ledger_guest_preflight.py,
tests/ops/test_ledger_guest_preflight.py and the trusted gate/orchestrator wiring.
This completed the already-approved no-core part of parent Task 3; the systemd
profile remains separate. Do not reimplement or rename the verified guard.

**Interfaces:** Existing ProfileError; establish_guest_no_core() -> None;
require_no_core() -> None. No dependency on ledger_systemd_contract.py.

- [x] Write RED for pipe/unreadable core pattern, failed write/readback, nonzero
  hard/soft limits and first target exec preceding the guard. Check every
  existing manager/probe direct spawn, inheritance and an unprivileged
  descendant's inability to raise the hard limit; no root test on the Mac.
- [x] Run python -m pytest tests/ops/test_ledger_guest_preflight.py
  tests/ops/test_live_e2e_gate_contract.py
  tests/ops/test_live_e2e_orchestrator_contract.py -q; record intended RED.
- [x] Implement fixed fresh-guest-only establishment of pattern "core" and
  limits (0, 0), before first target exec. Child-side verify-before-exec is
  mandatory. No caller path/value, production mutator or target imports.
- [x] Reach targeted GREEN; review startup failure/cleanup and compile/lint.
  Ship with common gates. Verify the new guard from trusted main in merge-main
  E2E before N2 can execute any compiler/helper.

### N1: Authenticate and derive the complete native input manifest

**Files:** Create ops/live-e2e/native_inputs.py, native-toolchain-inputs.json,
ubuntu-archive-2018.gpg, native_archive.py, tests/ops/test_native_inputs.py and
tests/ops/test_native_archive.py; update
docs/self-hosted-runner.md and ops/live-e2e/README.md. Archive exact signed
metadata and package receipts in operator-controlled evidence storage.

**Interfaces:** NativeInputError; verify_native_inputs(root: Path) ->
NativeInputs (immutable result); derive_native_manifest(metadata: VerifiedMetadata,
image_bindings: DeclaredImageBindings,
archives: Mapping[str, VerifiedArchive]) -> bytes. NativeInputs includes the
verified recipe and declared image roles; it does not claim fresh-guest measurement. These are trusted internal
interfaces; root paths are supplied by fixed orchestration constants.

- [ ] RED: signer/keyring drift, malformed/expired/ambiguous signature, wrong
  date/suite/hash/size, redirect escape, truncated downloads, malformed package
  record, missing dependency/provider, bad Debian version relation, omitted
  transitive edge, unsupported image binding and declared image-version mismatch.
  Add oversize InRelease/index/record, compressed expansion and time-limit
  controls, plus the package parser collision/link/type/expansion negatives
  listed in design section 4; N1 owns this host-side parser. Distinguish signature validity
  from derivation consistency with a mutated manifest negative test.
- [ ] Run python -m pytest tests/ops/test_native_inputs.py
  tests/ops/test_native_archive.py -q for intended RED.
- [ ] Implement bounded authenticated data parsing and explicit provider/version
  selection. Reject unsupported dependency syntax. Generate the complete roots/
  transitive package and file-layout manifest from the frozen signed snapshot,
  parsing authenticated package data as non-root. Complete all declared image
  roles/paths/providers under the pinned image binding; published inventory
  remains a candidate until N3 fresh-guest reconciliation. Per-file expected
  hashes need authenticated bytes, never version-based guesses.
- [ ] Record verifier version/provisioning, public key digest and independent
  fingerprint source. Test clean isolated verifier operation with valid signed
  metadata plus corrupted controls. Do not execute package scripts/compilers.
- [ ] Review the generated complete manifest and proposed command/layout recipe;
  ordinary tests regenerate it and reject drift. Any undeclared role/provider/search input blocks N1. Its complete declared
  composition is not N3 live composition or authorization for security canaries. Ship with common legacy gates; no native activation yet.

### N2: Materialize a dormant read-only tree and fixed low-privilege helper

**Files:** Create ops/live-e2e/native_materialize.py, native_probe.py,
native_toolchain_probe.c; tests/ops/test_native_materialize.py and
test_native_probe.py. Modify trusted orchestrator packaging of these already-
reviewed inputs and document their dormant status. No automatic guest launch.

**Interfaces:** materialize_native_tree(inputs: NativeInputs) -> NativeTree;
run_native_feasibility(tree: NativeTree) -> NativeEvidence. Fixed paths/UID/
commands belong to trusted constants and the reviewed manifest. NativeEvidence
contains the exact receipt fields in design section 7, not a bare boolean.

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
- [ ] Implement guest data-only copying/materialization of the N1 parser result,
  full recipe/declared-closure checks,
  writer quiescence, readonly bind verification, fixed child drop/core/cgroup
  checks and sealed output. Bound output/time; fail with safe codes. Never use
  root ldd or execute target/package/native code as root.
- [ ] Reach targeted GREEN and review the full actual compiler composition and
  command recipe against N1. If relocation/search requires a new layout, revise
  and review the manifest first; no silent fallback. Ship dormant with common
  gates. This proves implementation/regression, not pinned-guest feasibility.

### N3: Add bounded candidate feasibility while retaining legacy repair

**Files:** Create .github/workflows/live-native-toolchain-candidate.yml and
scripts/run-live-native-toolchain-candidate.py; modify trusted gate/orchestrator
fixed payload/profile/receipt handling; test ops workflow/gate/orchestrator
contracts; update ops/live-e2e/README.md and parent plan. Leave existing
live-local-e2e.yml legacy execution independent of all native acquisition/modules.
All materializer/helper/source inputs must already be on main.

**Interfaces:** Fixed profiles LEGACY_7A and NATIVE_CANDIDATE in trusted host
code. The candidate entrypoint selects only NATIVE_CANDIDATE, taking exact
commit_sha. The existing workflow selects only LEGACY_7A. Profile metadata is
trusted payload data; target inputs cannot choose it. Produce
require_native_repair_scope(changed_paths: tuple[str, ...]) -> None in trusted
host code, rejecting paths outside an exact trusted-main path allowlist for design
section-6 scope before every legacy bootstrap/repair invocation. Unknown/truncated diff or mixed product changes refuses.

- [ ] RED: failed/missing native acquisition or compiler in candidate profile
  incorrectly prevents legacy bootstrap from reaching all five fixtures.
  Candidate must still fail and clean up. Assert a repair target cannot replace
  candidate authority from main, and its legacy PASS gives no native credit.
- [ ] RED: target-selected profile/command, wrong workflow/SHA binding, missing
  native input, preflight after _start_manager/target exec, overlapping provider
  workflow, skipped fixture, failed compile/link/run reported as success, wrong
  evidence class or missing receipt/cleanup. Scope tests reject production src,
  target live probe/support changes and CI-policy changes in a legacy repair.
- [ ] Run python -m pytest tests/ops/test_live_e2e_gate_contract.py
  tests/ops/test_live_e2e_orchestrator_contract.py tests/ops/test_ci_workflow.py
  -q; record intended RED. Add workflow contract coverage to owning ops tests.
- [ ] Implement the fixed candidate entrypoint/workflow, isolated profile paths,
  trusted receipt/scope checks and shared provider concurrency without generic
  dispatch. All workflows use main, exact commit_sha and trusted-main helpers;
  no target source runs on the host or as root. Use bounded diff inspection.
- [ ] Ship using previously trusted main's full legacy gates. After merge, run
  exact merge-main ordinary CI, full legacy E2E, then the fixed candidate
  workflow. Require actual image reconciliation and native compile/link/run,
  complete legacy fixtures and all cleanup. This is first pinned-guest proof.
- [ ] If candidate fails, keep N3 open and use the documented native-only repair
  loop: focused RED/minimal fix/fresh review, exact repair-head ordinary/legacy
  PASS before merge, exact repair-merge ordinary/legacy PASS, then candidate
  native proof with newly-main authority. No failure converted to PASS, no mixed
  product merge and no automatic retry via legacy. N4 is blocked until GREEN.
- [ ] Record successful candidate target/authority/run/attempt, runtime input/
  helper/source digests and cleanup as N4's frozen baseline. Clean only obsolete
  clean branches/worktrees. No later security-canary or Phase 7B1 credit yet.

### N4: Require the already-proved native contract for native-dependent gates

**Files:** Create .github/workflows/live-native-toolchain-e2e.yml and
scripts/run-live-native-toolchain-e2e.py; modify trusted fixed profile/evidence
policy and ops contracts; update docs/self-hosted-runner.md,
ops/live-e2e/README.md and parent plan. No compiler/helper/source/input changes.

**Interfaces:** Fixed NATIVE_REQUIRED profile and native-required receipt class.
Retain LEGACY_7A/NATIVE_CANDIDATE only for their declared bootstrap/candidate
purposes. The new workflow takes exact commit_sha and selects NATIVE_REQUIRED
from trusted main; it shares the provider concurrency group. Every required
invocation rejects legacy/candidate evidence and missing native proof.

- [ ] RED: N4 selected before a successful N3 pinned-guest baseline; modified
  runtime digests hidden in activation; legacy/candidate receipt accepted as
  required proof; required failure falls back to legacy; mixed product repair
  uses legacy only; missing Task 6 or Task 7 ordering/cleanup evidence.
- [ ] Run focused workflow/gate/orchestrator/CI contracts to RED; implement only
  fixed routing and evidence requirements. Verify N3 runtime digests unchanged;
  any runtime change is its own prerequisite with fresh candidate proof.
- [ ] Reach GREEN and fresh independent review. Require exact N4 PR-head
  ordinary CI, full legacy E2E and candidate native/full-legacy E2E from trusted
  main before merge. Prior N3 proof alone is insufficient for the new target.
- [ ] After merge, require ordinary CI and the new native-required workflow for
  exactly the merge SHA: native preflight before any target, measured image/
  composition, compile/link/run, all five fixtures and complete cleanup.
- [ ] If native-required fails, preserve failure and keep the prerequisite open.
  Native-only authority repair may use trusted-main legacy scope-checked gates;
  after repair require candidate and native-required exact merge-main PASS
  before any native-dependent target resumes. Legacy PASS never closes N4.
- [ ] Retain exact receipts and verify cleanup; only now resume parent Task 3
  with native-required head/merge gates. Re-export G1’s existing ProfileError from the systemd contract; do not
  introduce a second exception, conversion or duplicate guard. Later Task 7 still proves actual
  syscall enforcement, and Task 8's mandatory Ledger mode cannot downgrade.

## Completion and deviations

Complete only after N4's exact merge-main native-required proof and full legacy
regression/cleanup. Record a prerequisite, not Phase 7B1 implementation complete
or closed. Native-authority repairs are bounded exceptions to bootstrap evidence,
not exceptions to native completion or product acceptance. No new criterion.
Any required image change, package repair, endpoint, privileged interface or
incompatible composition stops for renewed design review. Task 10's finite
C/H/M plus external E closure boundary remains unchanged.
