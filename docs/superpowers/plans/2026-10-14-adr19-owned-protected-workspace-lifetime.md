# ADR 0019 Dormant Owned-Workspace Primitives — Revised Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** **Proposed for operator review; implementation NOT approved.** Revision responds to independent PR #248 review 6172447419 (3 Important, 2 Minor). **Scope narrowed to dormant, unbound primitives; NOT a complete marker-bound live lifetime.**

**Goal:** Build testable original-FD-bound, no-follow protected-workspace creation/cleanup primitives that **cannot be activated by the current production caller**, without misrepresenting a re-read marker, Boolean or fixture as authorization to modify the real staging directory.

**Architecture:** The approved ADR 0019 spec requires a claimed original marker, clean protected/legacy/QEMU state, and confirmed guest reap. Existing `Orchestrator.create_bundle()` actually claims the fixed marker with `O_CREAT|O_EXCL`, closes that FD, and then creates a legacy temporary root; an unrelated zero-argument module **cannot prove it performed that claim** by re-reading marker JSON/UID/PID/inode. Deliver first a **non-mutating production entrypoint that refuses as UNBOUND** plus fixture-anchored, admission-guarded private creation/cleanup primitives. No production marker-capability issuer or real-guest reap-receipt issuer exists in this slice. There is **no production issuer** in 2A. A **separate reviewed marker/reap authority handoff** must occur before protected-placement activation. Tests exercise actual Darwin/APFS filesystem mechanics using isolated disposable roots, never the production fixed root.

**Tech Stack:** Python >=3.13, existing `protected_staging.py` pinned FD/ACL scanner, stdlib descriptor-relative POSIX APIs, pytest/Ruff, real Intel Mac UID 502/APFS fixture adapter, dual-Python hosted CI. No new product dependency or workflow change.

**Spec:** [approved ADR 0019 protected staging design](../specs/2026-10-13-protected-native-e2e-staging-design.md), [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md), [dormant inspection baseline](2026-10-13-protected-staging-health-inspection.md), [vNext rollout](2026-10-14-local-live-e2e-vnext-rollout.md). This is **Slice 2A only**; authority binding is separately reviewed **Slice 2B**, and actual placement/recovery/workflow activation remains **Slice 3**.

## Global Constraints

- Production namespace is **fixed**: `/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-e2e/staging-v1`, Intel Darwin, dedicated non-admin real/effective UID 502, fixed account/group/home, trusted-main workflow/repository/ref. No caller-provided root/UID, mode, nonce, marker or path selector in production.
- Existing original marker `active-run.json` is exactly two fields (`target`, `owner_pid`). Re-reading its contents/inode or comparing its PID with `os.getpid()` **is never proof of the current exclusive `O_EXCL` claim**. Current trusted orchestrator cannot transfer original claim evidence to this module; **do not define a production claim issuer or synthesize one** in Slice 2A.
- **Before any directory mutation** a *single guard* must have checked (in order) trusted context/selectors, original exclusive claim provenance, absence of QEMU, repeated protected/`/private/tmp`/dedicated native temp scans, fixed ancestor FD/identity/ACL and drift. The production issuer is absent, so production creation **always refuses before mkdir**. Both the top-level entrypoint and private effectful helper refuse without a matching guard/capability.
- Fixture-only permits come from a **disposable explicit `O_CREAT|O_EXCL` simulation** and are bound to the fixture's specific original claim+parent FD/run identity; a preexisting lookalike marker, arbitrary `claimed=True`, same-PID re-read, wrong fixture or stale permit refuses. Test injection is inside the test harness, not a runtime API/CLI. Python privacy/opaque objects do **not** themselves create a security boundary against malicious same-UID code; no live issuer/caller is installed.
- Protected missing-descendant allow-list is literal `Application Support`, `ssh-over-mcp-e2e`, `staging-v1`, one level at a time relative to a pinned parent. New dirs mode `0700`; existing account-owned private base/staging mode `0700` and no extended ACL; `Application Support` may be `0700`/`0755`. No arbitrary recursive mkdir, chmod/chown, ACL repair, symlink following, alias resolution or absolute-path deletion fallback.
- Every new run child: `ssh-over-mcp-e2e-` + **32 lowercase hexadecimal** nonce, exclusive dir_fd create, no collision adoption/retry, same device as staging, pinned original parent and run-root descriptors/device/inode/owner/group/full mode/ACL. Existing APFS system/data-volume transitions **between ancestors** remain valid.
- **Scanner phases are distinct:** PRE-CREATE staging must be empty using existing `_scan_parent(private=True)` unchanged; POST-CREATE allows **exactly one original held-owned child with matching name/inode/ACL**, rejecting all other entries; POST-DISPOSE staging must be empty using existing scanner. Do not call the pre-create empty scanner after creating the legitimate child.
- Creation as well as deletion assumes an **exclusive single-writer provider principal and no concurrent malicious same-UID actor**. Refreshing parent mtime_ns/ctime_ns after our mkdir does not prove attribution; require held-FD before/after snapshots, exact expected entry inventory, ACL/identity checks and deterministic foreign-interleave refusals; continue strict shared `/private/tmp` mtime/ctime drift. State the remaining POSIX race explicitly.
- **No Boolean `guest_reaped`.** No trusted guest completion/reap-receipt issuer can exist before the already-main orchestrator provides a run-bound post-`wait`/process-absence proof. Thus real-run `OwnedWorkspace.dispose(receipt: RunCompletionReceipt)` is reserved and MUST REFUSE (without unlink) in Slice 2A. No caller can invent a receipt via bool or JSON; later Slice 2B must bind a one-shot receipt to exact run/root/owned child identity, reject replay/wrong-run/stale/reap-failed and audit issuer provenance.
- Slice 2A may test **only never-launched disposable fixture cleanup** via a private fixture-held `NeverStartedEvidence` bound to the same newly created test workspace, issued while no QEMU ever launched. The fixture-owned cleanup primitive may remove nested test files/symlinks (without following them). It must NOT be exposed as a production generic delete API, runtime `dispose` or provider recovery method. A non-guest fixture is **not** evidence of real QEMU termination.
- FD-relative removal must verify held staging/run-root identities, ACL and original root entry before mutation; bounded scans, `O_NOFOLLOW|O_CLOEXEC`, anchored `os.unlink`/`os.rmdir` only. Replacement/symlink, missing original FD, unexpected disappearance, unknown close/unlink: refuse, preserve forensic marker and don't retry automatically. No finalizer deletion; destructor closes owned FDs only.
- Leave `scripts/run-live-local-e2e-orchestrator.py`, `ops/live-e2e/recover_provider.py`, both existing CI/native workflows, marker schema, ADRs 0011/0012/0018 and other agents' worktrees untouched. No actual protected-placement activation, no new Mac job permissions, no PR-native dispatch/commit status.
- Use ignored root/worktree `progress.md` and plan-owned SDD ledger; when **code, author self-review and focused GREEN** finish, **request independent review immediately**, regardless of full CI status. Full exact-head CI, independent review, appropriate OS-native evidence and exact-main gates still block merge.

## Review Focus — test-traced adversaries

1. **Preexisting lookalike marker, same PID/target/inode but no fresh exclusive claim:** `test_preexisting_marker_same_pid_never_grants_permit` and `test_unbound_entrypoint_and_helper_never_mkdir` (Task 1).
2. **Bool/wrong-run/replayed/stale/failed QEMU completion:** `test_bool_and_foreign_receipt_never_delete` (Task 3); real receipt issuance **deferred to Slice 2B**.
3. **Foreign mkdir/symlink or drift during creation:** `test_interleaved_foreign_mkdir_refuses` (Task 2); own timestamp observation never gives unconditional success.
4. **Foreign/nested entries after owned creation:** `test_postcreate_exact_original_child_only` (Task 2); baseline read-only empty scanner remains unchanged.
5. **Run-root swap, symlink external target, interrupted deletion/close or destructor retry:** `test_original_run_root_swap_refuses` (Task 3), `test_finalizer_closes_only_no_unlink` (Task 4).

---

## File and interface map

| File | Sole responsibility |
| --- | --- |
| `ops/live-e2e/staging_owned_lifetime.py` (new) | **Dormant** fail-closed `create_owned_workspace()` and `OwnedWorkspace.dispose(receipt)` production stubs; private controlled fixture-only admission/creation/disposal using original pinned FD; no CLI or marker issuer |
| `ops/live-e2e/protected_staging.py` (private extension) | Pure admission checks and strict **guard-required** fd-relative fixed-ancestor creation; separate postcreate exactly-one-owned-child scan; no unguarded `_PinnedNamespaces` mkdir |
| `ops/live-e2e/staging_namespace_types.py` (minimal extension if needed) | Frozen original root/parent identity only; do not change read-only `NamespaceSnapshot` semantics |
| `tests/ops/test_protected_staging_lifetime.py` (new) | RED→GREEN identity/admission/fixture-only mutation/phase-scan/uncertain-finalizer tests |
| `tests/ops/test_protected_staging_lifetime_native.py` (new) | Real Mac UID502/APFS disposable fixture evidence; **no** actual provider marker/production staging writes |
| `docs/evidence/2026-10-14-protected-staging-owned-lifetime.md`, `docs/development-plan.md` | Truthful **unbound primitive** status, real test limits, 2B handoff dependency and separate activation milestone |

**Interface rule:** `create_owned_workspace() -> OwnedWorkspace` remains a **zero-arg, fail-closed production entrypoint** returning no workspace until 2B. `OwnedWorkspace.dispose(receipt: RunCompletionReceipt) -> None` must refuse and not delete in 2A; **never** accept a bool. `OwnedWorkspace.close()` and `__del__` close descriptors only. Private `_FixtureClaimPermit` and `_NeverStartedEvidence` are created by the isolated test adapter *after demonstrable exclusive fixture claim*, and are bound to one `_FixtureOwnedWorkspace`/original parent FD/run inode. No public `create(..., path=..., claimed=True)`, static CLI, or generic orphan/deletion method. Real marker handoff/guest-reap receipt construction cannot be inferred from the existing marker JSON.

### Task 1: Refusal-before-first-mkdir and purely read-only admission

**Files:** Add `tests/ops/test_protected_staging_lifetime.py`; create `ops/live-e2e/staging_owned_lifetime.py` skeleton; privately extend `ops/live-e2e/protected_staging.py` **without creation helper yet**.

**Produces:** `_AdmissionObservation`: detached, read-only context/selector/marker-likeness/QEMU/two-scan/held-edge observations **not authorization**. Real issuer `_issue_live_creation_permit` is **absent**, so `create_owned_workspace()` rejects with safe `NamespaceError('unbound')`. No effectful method exists without a matching fixture permit.

- [ ] RED `test_preexisting_marker_same_pid_never_grants_permit` and `test_unbound_entrypoint_and_helper_never_mkdir`: even convincing live marker JSON/inode/current PID + pristine namespace yields zero `mkdir`; fabricated bool, missing/foreign marker, foreign QEMU, dirty protected/legacy and wrong trusted context all refuse.
- [ ] Run `python -m pytest -q tests/ops/test_protected_staging_lifetime.py -k 'preexisting_marker or unbound_entrypoint'`; expect RED (missing module/interface).
- [ ] GREEN implement zero-arg fail-closed stub and pure observation; no effectful helper exposed on `_PinnedNamespaces` without guard. The observation may not be cast into a permit and does not mutate.
- [ ] RED→GREEN `test_all_startup_blockers_precede_mkdir` with protected residual and each legacy parent, stale selectors, marker mismatch and unknown QEMU; validate no deletion, marker changes or permission repair.
- [ ] Run focused + existing `test_protected_staging_namespace.py`/`test_protected_staging_dormant.py`; commit & ledger.

### Task 2: Guard-bound disposable creation and phase-specific scanner

**Files:** Extend `ops/live-e2e/staging_owned_lifetime.py` and `ops/live-e2e/protected_staging.py`; tests `tests/ops/test_protected_staging_lifetime.py`.

**Produces:** Private `_create_for_fixture(permit: _FixtureClaimPermit) -> _FixtureOwnedWorkspace`, which verifies exact original fixture exclusive-claim provenance and held-FD context before calling a **permit-required** `_PinnedNamespaces._create_missing_protected_descendants(permit)`. A real host caller has no permit issuer.

- [ ] RED `test_fixture_exclusive_claim_required_before_first_descendant_mkdir`: test-owned disposable marker starts absent; fixture adapter executes actual `O_CREAT|O_EXCL` and holds its creation evidence; pre-existing same-PID marker, forged/foreign/stale/wrong-parent permit and direct helper call **never mkdir**.
- [ ] GREEN implement single guarded admission sequence: original disposable claim ownership -> trusted-equivalent fixture context -> QEMU/selector -> **two** fully clean observations + pinned ACL/edge validation -> first protected-descendant mkdir. Record all preconditions and their ordering; no caller bit/Boolean bypass.
- [ ] RED→GREEN `test_fixture_fixed_descendants_mode_acl_and_unique_run_child`: exactly permitted literal descendants, mode 0700/zero extended ACL, immediate `O_NOFOLLOW` open, exact original parent/run FDs and inode, fresh 32-hex nonce, collision refuses without retry/adoption, run child staging device equal. Existing ancestor APFS device transitions allowed.
- [ ] RED→GREEN `test_interleaved_foreign_mkdir_refuses`: interleave unrelated create/remove during claimed own mkdir, prove observed metadata/inventory changed; reject and preserve foreign entries rather than “attributing” timestamps to self. Single-writer assumption and impossible perfect POSIX race detection documented.
- [ ] RED→GREEN `test_postcreate_exact_original_child_only`: after creating run child, verify **only** original run name, held root inode/owner/mode/ACL; a second entry or replacement refuses; **do not invoke** `_scan_parent(private=True)` at this stage. Post-disposal must use original empty scanner unchanged.
- [ ] Run all focused/pinned-namespace tests and Ruff; commit, progress.

### Task 3: Fixture-only no-follow cleanup and non-forgeable live-reap boundary

**Files:** Extend `ops/live-e2e/staging_owned_lifetime.py`; tests `tests/ops/test_protected_staging_lifetime.py`.

**Produces:** Private `_dispose_never_started_fixture(workspace: _FixtureOwnedWorkspace, receipt: _NeverStartedEvidence) -> None`, only for a fixture never assigned a guest; production `OwnedWorkspace.dispose(receipt: RunCompletionReceipt)` remains **non-mutating refusal**.

- [ ] RED `test_bool_and_foreign_receipt_never_delete`: passing `True`, an arbitrary object, stale/other-run fixture receipt, consumed fixture receipt or “QEMU failed” report never removes anything; production `dispose(True)` must refuse.
- [ ] GREEN retain no live receipt issuer. Private fixture-created receipt must bind exact original run/root device+inode and a verified never-started fixture state; one shot. Explicit future 2B contract: issuer after owned QEMU `wait` + process absence and cleanup, receipt bound to run and used once, no replay. **Do not implement that issuer now**.
- [ ] RED→GREEN `test_fixture_original_root_only_cleanup` with nested test directories, files and external symlinks: bounded FD-relative `scandir/open(O_NOFOLLOW)/unlink/rmdir`; verify no external symlink traversal, original parent/root identities+ACL, check final staging empty using unchanged scanner; no absolute-path fallback.
- [ ] RED→GREEN `test_original_run_root_swap_refuses`, `test_nested_symlink_target_preserved`, `test_nested_swap_refuses`, `test_lost_root_fd_refuses`, `test_uncertain_unlink_never_clears_marker`. On partial/unknown mutation mark `cleanup_uncertain=True`, no blind retry.
- [ ] Run focused regression and commit. No actual QEMU guest is started by these tests. A disposable never-launched fixture is **not** evidence of guest termination or usable live cleanup.

### Task 4: One-shot resource lifecycle and close-only finalization

**Files:** Extend `ops/live-e2e/staging_owned_lifetime.py` and focused fixture tests.

- [ ] RED `test_finalizer_closes_only_no_unlink` under GC after injected partial cleanup; assert destructor causes zero unlink, rmdir, second cleanup, marker mutations or QEMU signals.
- [ ] GREEN implement explicit lifecycle states `new → disposing → disposed/uncertain` and close-only `close()`/`__del__`. No implicit context-manager cleanup, retry, second delete or “success” after uncertain close.
- [ ] RED→GREEN repeat disposal, unexpected root disappearance, close error, nested symlink mutation, and preservation of foreign objects. Use existing `NamespaceError(cleanup_uncertain=True)`.
- [ ] Run new + all existing protected native/selectors/dormant regression tests; commit and ledger.

### Task 5: Real Mac/APFS disposable evidence, documentation, immediate review

**Files:** Add `tests/ops/test_protected_staging_lifetime_native.py` and `docs/evidence/2026-10-14-protected-staging-owned-lifetime.md`; edit `docs/development-plan.md`.

- [ ] RED→GREEN real Intel Darwin UID502/APFS **disposable sandbox root** with fixture-only `O_EXCL` claim witness, exact FD/ACL/mode checks, valid empty→owned-one→empty phase, parent mutation interleavings, symlink replacement and interrupted fixture cleanup. No real marker or actual production staging writes, no real QEMU-guest receipt claimed. Linux test scope skips Mac-only assertions explicitly.
- [ ] Record actual run IDs/SHA, skipped cases and cleanup evidence without claiming an automatically provisioned native workspace. Test **production unbound entrypoint refuses before mkdir** on trusted UID502 context without touching provider state.
- [ ] Regress all protected staging tests, `python -m ruff check src tests ops/systemd ops/live-e2e`, `python -m compileall -q src tests ops/systemd ops/live-e2e`, `git diff --check`; unchanged orchestrator, recovery, CI/native workflows, marker schema and frozen ADRs. No opportunistic source refactor.
- [ ] **As soon as code, focused GREEN and author self-review finish, open PR and request independent security review immediately**, even while full hosted CI runs. Reviewer rechecks authorization/receipt separation, fixture isolation, race/refusal tests and docs.
- [ ] Final exact-head eight-shard/two-aggregate CI, independent clean review and applicable trusted-main manual Level-3 are **merge** gates. Post-merge main/native evidence required. No protected placement activation, real marker handoff or real-run disposal in this slice.

## Deferred implementation gates (not hidden “complete” work)

**Slice 2B — separately proposed and approved:** design a **trusted already-main handoff at the existing `O_CREAT|O_EXCL` marker claim point**, without making arbitrary marker re-reads an ownership proof; capture original exclusive claim result and run identity into a trusted, one-shot creation permit. Design a **run-bound guest completion receipt** issued only after owned QEMU wait/reap and independent process check; refuse wrong-run/replay. Wire private creation/disposal to these genuine authorities, including phase-scoped scanner logic. This may require narrowly scoped orchestrator changes; must NOT be backported silently into 2A.

**Slice 3 — separately proposed and approved:** switch actual trusted-main E2E placement, recovery scanner and always-run workflow namespace checks; obtain true post-merge UID502 protected-root/guest/cleanup evidence. Legacy Level-3 PASS does not prove new protected placement.

**Current PR approval gate:** This is a revised written plan, not authorization for code. The operator must approve **the revised limited 2A scope and implementation method** before coding. Recommend native inline TDD plus independent whole-branch review requested immediately upon code completion; CI and native evidence gate merge, not review request. No marker or filesystem mutation from reviewing this plan.
