# ADR 0019 Owned Protected Workspace Lifetime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Proposed for joint operator/security review. **No product implementation authority yet.**

**Goal:** Deliver a separately testable, **dormant** owned workspace lifetime: exclusively create one fixed protected run directory, retain original-parent and original-run FDs/identity, then explicitly delete only the owned tree, without destructor cleanup, unsafe fallback or any change to live E2E placement.

**Architecture:** Extend the existing `protected_staging.py` held-FD namespace inspection with strictly checked own-mutation bookkeeping and fixed-descendant creation; encapsulate ownership, unique run-root acquisition and no-follow descriptor-relative disposal in a small sibling module. Reuse the existing marker/schema and protected+legacy scanner as security gates. A real Mac UID-502 disposable fixture validates APFS ACL, race refusal and post-cleanup state. Existing trusted-main orchestrator/legacy placement remains byte-identical until a separately approved activation PR.

**Tech Stack:** Python >=3.13 stdlib (`os.open`, `dir_fd`, `stat`, `os.scandir(fd)`, `os.mkdir`, `os.unlink`, `os.rmdir`), pinned Darwin64 APFS ACL/`fstatfs` bindings, pytest, Ruff, dedicated Intel Mac UID502, dual-Python GitHub Actions.

**Spec:** [approved protected staging design](../specs/2026-10-13-protected-native-e2e-staging-design.md), [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md), [completed dormant inspection plan](2026-10-13-protected-staging-health-inspection.md), [vNext rollout](2026-10-14-local-live-e2e-vnext-rollout.md).

## Global Constraints

- Fixed protected root: `/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-e2e/staging-v1`. `Library` must preexist and validate; ONLY missing literal `Application Support`, `ssh-over-mcp-e2e` and `staging-v1` may be created, **one level per held parent**.
- Current non-admin account and real/effective UID **502**, fixed account name/home, retained trusted-main GitHub Actions/repository/ref, Intel Darwin and group restrictions. No production-callable arbitrary path, root/UID/mode selector or test seam in a CLI.
- New descendants/run root mode `0700` with immediate no-follow open and pinned device/inode/owner/group/mode/ACL evidence. Existing private provider-base/staging require `0700` and no extended ACL entries. Existing `Application Support` permits `0700` or `0755`, never unsafe ACL grants. No chmod/chown, ACL repair, recursive mkdir or alias resolution.
- A trusted current marker must be **exclusively claimed by existing trusted main authority before creating a child**. Keep marker at fixed cache path with only `target` and `owner_pid` and original owner/inode witness. Do not add a second marker claim, mark generic presence as “owned,” or allow deletion because a marker exists. No child with QEMU, protected residual, or either supported legacy residual.
- Reuse `_PinnedNamespaces`, two bounded scans, strict APFS ACL and all mtime_ns/ctime_ns drift checks (including `/private/tmp`). Own mkdir/rmdir may update only explicitly proven affected parent edge; **do not globally relax drift or automatically retry uncertain evidence**.
- Unique child basename `ssh-over-mcp-e2e-` plus one fresh 32-lowercase-hex nonce, exclusive fd-relative creation, no adoption of existing entries. Retain original parent FD, run-root FD, original dev/inode/uid/gid/full mode, device agreement with staging and ACL evidence.
- Disposal uses only the original handle and no-follow fd-relative operations; forbid `shutil.rmtree(path)`, absolute-path deletion fallback, symlink following, arbitrary residual deletion, orphan recovery or CLI cleanup path.
- Stop/reap the owned guest before removal in future activation; dormant tests must require a trusted internal completion witness and reject “not reaped.” A destructor closes **only** owned FDs; it must not unlink, rmdir, retry, clear marker or signal processes.
- Parent/run replacement, unexpected disappearance, lost FD, ACL drift, uncertain unlink or close: fail closed, preserve marker/evidence and never retry automatically. POSIX check→unlink is not atomic against a hostile same-UID writer; document the required exclusive-principal/single-writer assumption and test detectable substitution.
- Do not modify `scripts/run-live-local-e2e-orchestrator.py`, `ops/live-e2e/recover_provider.py`, existing workflows, incident-pinned ADR 0011/0012/0018 artifacts, marker wire format, Mac group privileges, or any other agent's worktree. No protected placement activation, automatic PR E2E, or required status.
- **Review timing rule:** once implementation, tests and author self-review are complete, request independent review on the PR **immediately**, even if GitHub CI is still running. CI/native proof remains a merge gate, not a review-request gate.
- Persist exact RED→GREEN, SHA, cleanup uncertainty and next actions to ignored root and owned-worktree `progress.md` and plan-owned SDD ledger.

## Review Focus

1. Run directory replaced with symlink/foreign inode before deletion → refuse and preserve target: `test_original_run_root_swap_refuses` (Task 3).
2. Destructor called after partial cleanup or ambiguous close → **zero** further deletion/retry: `test_finalizer_closes_only_no_unlink` (Task 4).
3. Concurrent creation or parent ACL/timestamp drift after planned own mkdir → refuse rather than adopt/repair: `test_foreign_create_never_becomes_owned` and `test_parent_drift_after_owned_mkdir_refuses` (Task 1).
4. Nested symlink to outside tree or nested directory substituted at unlink boundary → never traverse outside: `test_nested_symlink_target_preserved` and `test_nested_swap_refuses` (Task 3).
5. Missing/foreign/stale marker, visible protected or legacy residual, unknown QEMU → no mkdir before authoritative checks: `test_all_startup_blockers_precede_mkdir` (Task 2).

---

## File/interface map

| Path | Contract |
| --- | --- |
| `ops/live-e2e/protected_staging.py` (extend private internals) | Fixed held-parent creation with verified own-mutation evidence; same root/ACL/edge/drift rules |
| `ops/live-e2e/staging_owned_lifetime.py` (new) | No-CLI owned marker witness, exclusive run child, private owned descriptor handle, explicit single-use deletion |
| `ops/live-e2e/staging_namespace_types.py` (minimal extension) | Frozen original run/parent identity evidence; existing inspection result unchanged |
| `tests/ops/test_protected_staging_lifetime.py` (new) | Pure fixture RED→GREEN and adversarial FD/marker/ACL/double-delete tests |
| `tests/ops/test_protected_staging_lifetime_native.py` (new) | Real disposable Intel Darwin UID502/APFS no-follow/ACL/cleanup fixture; no production provider mutations |
| `docs/evidence/2026-10-14-protected-staging-owned-lifetime.md` (new) | Exact run IDs and honest OS evidence; **no activation claim** |
| `docs/development-plan.md` (edit) | Single completed dormant-lifetime milestone and pending activation gate |

**Interfaces fixed for implementation review:** `class OwnedWorkspace` with private original `root_fd`, `parent_fd` and pinned ancestor chain, immutable public `name`/`root_identity`/`parent_identity`, `dispose(*, guest_reaped: bool) -> None` (one-shot, no caller root), and `close() -> None` (descriptor close only). Private `_acquire_claimed_marker() -> OwnedMarkerWitness` validates only the **fixed** existing cache marker, exact current PID, lowercase 40-hex target, original inode/owner/mode; marker may not be created by this module. Fixed `create_owned_workspace() -> OwnedWorkspace` takes **no arguments**, uses the previously claimed marker and held namespace scanner, validates trusted context and returns the original pinned owner handle. If the existing marker contract cannot prove invocation ownership without activation code changes, **stop and revise plan**, do not add a permissive “claimed=True” input. Tests can inject OS boundaries inside fixtures, never via product CLI.

### Task 1: Held fixed chain and explicitly accounted own mkdir

**Files:** Modify `ops/live-e2e/protected_staging.py`; create `tests/ops/test_protected_staging_lifetime.py`.

**Interfaces:** Private `_PinnedNamespaces.create_missing_protected_descendants() -> int` returning held staging FD after revalidation of fixed edges and **only** allowed missing literals.

- [ ] Write `test_only_missing_fixed_descendants_created`: fixture initially lacks exactly three allowed descendants; assert per-level `os.mkdir(..., mode=0o700, dir_fd=held_parent)`, no chmod/chown/recursive mkdir and immediate no-follow open+ACL checks.
- [ ] Run `python -m pytest -q tests/ops/test_protected_staging_lifetime.py::test_only_missing_fixed_descendants_created`; expected **RED**, missing method.
- [ ] Implement minimal internal owned-creation logic with parent identity/ACL rechecks, no-follow child opens, same-device check only for run child vs staging; explicitly refresh the exact parent mtime/ctime resulting from **our verified own mutation**, never for shared foreign churn.
- [ ] Re-run exact test **GREEN**. Add and RED→GREEN `test_parent_drift_after_owned_mkdir_refuses`, `test_foreign_create_never_becomes_owned`, `test_existing_unsafe_acl_refuses`, `test_parent_symlink_swap_refuses`, `test_apfs_system_data_volume_transition_allowed`.
- [ ] Run new file and existing `tests/ops/test_protected_staging_namespace.py` + `test_protected_staging_native.py`; commit only task files and update ledger.

### Task 2: Existing-marker proof, precreation health and exclusive root

**Files:** Create `ops/live-e2e/staging_owned_lifetime.py`, minimally extend `ops/live-e2e/staging_namespace_types.py`; extend `tests/ops/test_protected_staging_lifetime.py`.

**Interfaces:** Private `OwnedMarkerWitness` from fixed owned marker; `create_owned_workspace()` zero-argument; handle stores original root+parent FDs and immutable identity.

- [ ] RED `test_all_startup_blockers_precede_mkdir`: absent/stale/foreign marker, QEMU, protected residual, either legacy parent residual, changing selector, ACL/edge drift all refuse **before any mkdir**.
- [ ] GREEN implement trusted UID502/main context and fixed marker inode/owner/current PID/canonical target checks; existing complete two-pass scanner must run **while namespace FDs remain held**. No second marker creation; reject unsafe/incomplete evidence.
- [ ] RED `test_unique_nonce_exclusive_root`: 32 lowercase hex, correct prefix, original staging FD, mode 0700/ACL empty, parent/root same device, pinned inode, existing-name collision refuses **without retry/adoption**.
- [ ] GREEN create run root and private owned handle; recheck context, marker, namespace and both legacy parents just before returning. No persistent Mac caller activation.
- [ ] Run focused tests, existing protected scanner tests, Ruff and compileall. Commit, record RED/GREEN.

### Task 3: No-follow descriptor-relative owned-only disposal

**Files:** Extend `ops/live-e2e/staging_owned_lifetime.py` and `tests/ops/test_protected_staging_lifetime.py`.

**Interfaces:** `OwnedWorkspace.dispose(*, guest_reaped: bool) -> None`, no arbitrary root argument; no broad deletion helper.

- [ ] RED `test_owned_fd_cleanup_removes_only_original_tree` with files, nested directory and symlink to foreign outside target; assert outside target unchanged, only original run entry absent via held staging parent FD.
- [ ] GREEN implement bounded fd-relative `os.scandir(fd)` traversal, `os.stat(..., follow_symlinks=False, dir_fd=fd)`, `os.open(..., O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC, dir_fd=fd)` for dirs, `os.unlink` for verified files/symlinks and `os.rmdir(..., dir_fd=fd)` for verified directories. Revalidate pinned edges/ACL/root identity; refuse on ambiguity; verify original root absent with original parent FD; no path-based fallback.
- [ ] RED→GREEN `test_original_run_root_swap_refuses`, `test_nested_symlink_target_preserved`, `test_nested_swap_refuses`, `test_lost_root_fd_refuses`, `test_guest_not_reaped_refuses`, `test_uncertain_unlink_never_clears_marker`.
- [ ] Prove what is and is not protected against POSIX concurrent same-UID mutations; don't falsely claim atomic check+delete. Run full focused regression and commit.

### Task 4: Single-use lifetime and close-only destructor

**Files:** Extend `ops/live-e2e/staging_owned_lifetime.py` and `tests/ops/test_protected_staging_lifetime.py`.

- [ ] RED `test_finalizer_closes_only_no_unlink` with injected failed cleanup and GC; ensure zero destructor unlink/rmdir/retry calls.
- [ ] GREEN implement explicit one-shot `new -> disposing -> disposed/uncertain` state. `close()`/destructor close only; no silent second cleanup on uncertainty, including context-manager exit.
- [ ] RED→GREEN double dispose, external disappearance, close failure, interrupted partial removal and no marker-clear tests; require `NamespaceError(cleanup_uncertain=True)` for ambiguous outcomes.
- [ ] Run all existing protected namespace/native/selectors/dormant tests with new tests; commit and ledger. Live orchestrator remains on its original temporary route.

### Task 5: Real Mac evidence, documentation and independent review

**Files:** Create `tests/ops/test_protected_staging_lifetime_native.py`, `docs/evidence/2026-10-14-protected-staging-owned-lifetime.md`; update `docs/development-plan.md`.

- [ ] RED→GREEN dedicated Intel Mac UID502/APFS disposable fixtures for valid original owned tree cleanup, deny/allow ACL, mode/owner mismatch, symlink replacement and interruption; Linux CI skips real-Mac-only assertions **honestly**. Never create or remove production cache/marker or foreign provider files as a fixture.
- [ ] Document actual observed Mac results, target SHA, exact host identity, unknown state and marker preservation; distinguish **dormant lifetime** from next protected-placement activation and previous legacy Level-3 evidence.
- [ ] Run focused tests, `python -m ruff check src tests ops/systemd ops/live-e2e`, `python -m compileall -q src tests ops/systemd ops/live-e2e`, `git diff --check`; verify old orchestrator/recovery/workflows/incident docs unchanged.
- [ ] **As soon as coding, tests and author self-review are complete, open feature PR and request an independent project-wide review immediately**. Do **not** wait for exact-head hosted CI before requesting review. Include five Review Focus classes and remaining evidence gaps.
- [ ] In parallel complete exact-head hosted 8 shards and both aggregate contexts, authorized old-path native E2E if required, and independent review fixes with RED→GREEN. Do not merge on self-review, CI alone or fake Mac tests.
- [ ] After all gates genuinely PASS, merge exact reviewed HEAD, verify exact-main hosted+native and owned-only cleanup. No protected staging activation or PR-native dispatch in this slice.

## Approval gate and execution mode

This plan proposes a new security-sensitive **lifetime** capability; the approved **design** is not approval of these implementation details. Review this plan before changing code. Recommended execution: **native inline**, with exact RED→GREEN at each task and fresh independent whole-branch review when coding ends; per-task subagents are not available in this harness. A later, separate plan must cover switching actual E2E placement, recovery and workflow health checks.
