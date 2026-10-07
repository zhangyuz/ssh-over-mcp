# Dormant Fixed Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve native execution: implement locally, then one fresh independent whole-branch review on the most capable reviewer. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build only the dormant fixed-command capture component of native inspection, with child-only FD isolation, exclusive wait ownership and bounded failure cleanup.

**Architecture:** Two argument-free internal APIs select literal `getconf`/`ps` commands. A private launch-resource builder excludes parent descriptors in child file actions; a per-invocation collector owns the returned PID and every wait/signal decision. No CLI, workflow caller, accepted inspection or receipt emission is added.

**Tech Stack:** Python 3.13/3.14 stdlib, Darwin `posix_spawn`/kqueue, pytest and Ruff; no compiler, installer, dependency or lock change.

**Spec:** `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md` and ADR 0012. Written authority approved at `10681ce1f218b17c8bba98bcb4eb1d7352f520b6`; approval record reviewed at `666476af7f66d93c85d008eb0439f427a247df16` and merged in #147.

**Status:** Written plan approved by the user at exact `b6c4aa0bbd7e1dc1b8b4848c970444c539ad96d3` on 2026-10-07; native execution method preserved. Both component deliverables are implemented; independent review and exact revision gates remain pending. This grants no full-preflight or activation credit. Baseline: 87 inventory/recovery/CI tests PASS. #147 exact-head CI `37615444003` PASS. Its exact merge-main run `37615962268` passed ordinary Python 3.13/3.14 validation but failed overall: stale provider state refused before guest, exit 70; provider absence failed, checkout cleanup passed. No Level-3/A1 closure credit.

## Already-main authority binding

The exact authority commit is **`1ddebe541ee80c0febc4cd35072f3a5046fac5cb`**, already on `main`. Bind these literal paths, lengths and raw-byte SHA-256 values together; never derive a replacement authority from the implementation head.

| Fixed path | Bytes | SHA-256 |
| --- | ---: | --- |
| `docs/decisions/0011-incident-bound-e2e-staging-recovery.md` | 11227 | `c98f99d29f8e02bae4c90f56565241818f23e10a229afcecafbebd2a91b43e3b` |
| `docs/decisions/0012-owned-diagnostic-child-lifecycle.md` | 11238 | `980801f685dba9eee8a8e76c0e39641fd7aa61d5c3453ecd6e10d9ba5f4a51a3` |
| `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md` | 22821 | `650d65243e023f647e4c7424357ad1e2b19d6317eb603cfa1bebde388e358882` |

Before implementation, verify these exact blobs at that commit and the current checkout bytes. Missing objects, mismatches or changed normative bytes stop execution; ancestry alone is insufficient. Keep these three files unchanged in the implementation PR. Embed the immutable literal binding in the module and verify its fixed checkout files before either diagnostic API may spawn. Later full preflight/activation must retain this binding and independently establish trusted-main checkout/workflow context.

## Global Constraints

- No production `src/`, workflow, gate, provider, existing recovery API or native-package change. No CLI or import-time host action. Self-hosted CI only.
- Fixed `getconf`: argv `('/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR')`; collection deadline **5 seconds**; stdout/stderr each **1024 bytes**, combined **2048 bytes**.
- Fixed `ps`: argv `('/bin/ps', '-ww', '-U', '502', '-o', 'pid=,comm=')`; deadline **10 seconds**; combined stdout/stderr **65536 bytes**.
- Environment exactly `{'LC_ALL': 'C'}`; no shell, PATH search, cwd/executable/UID/PID/timeout/output-limit/signal override or borrowed process handle. Stdin fixed `/dev/null`; stdout/stderr only owned pipe write ends in the child's exec table.
- Preserve unrelated/pinned parent descriptors, identities, usability, flags and offsets. Exclude all other descriptors in the child, even inheritable ones. Close only helper-owned parent resources.
- Public internal APIs require Darwin/x86_64, effective UID **502**, account `gha-e2e-orchestrator`, home `/Users/gha-e2e-orchestrator`, non-root, and no admin primary or supplementary group. Require a single-threaded parent, default SIGCHLD and no competing reaper. Thread/handler checks do not prove the absence of a native competing reaper; the trusted standalone parent must establish exclusive ownership. Higher-level GitHub/main/concurrency checks remain a separate integration prerequisite.
- Only a freshly created, exclusively owned, unreaped child may receive **one SIGKILL** on collection failure. No SIGTERM, signal retry, group/descendant signalling, PID rediscovery, marker/inventory/orphan/borrowed PID signalling or `waitpid(-1)`.
- Cleanup deadline **2 seconds**; nonblocking own-PID waits only. Unknown status, ECHILD, signal/reap failure or inability to settle cleanup refuses with explicit uncertainty. Cleanup success never converts collection failure into success. No automatic diagnostic retry.
- No unbounded capture/communicate/wait. Deadlines use monotonic time and are measured before spawn. No hard guarantee over kernel calls, spawn, external cancellation or machine failure is claimed.
- Propose a fail-closed helper resource ceiling of **1024 enumerated FD names**, including scanner entries. Overflow refuses before spawn; it never grants permission to leave an unenumerated descriptor inherited. This additional resource bound is part of this plan's pending review, not a new signal authority.
- Observe no staging/marker state. Read only the three fixed public authority documents plus metadata of the helper's own descriptor table. Create no persistent evidence/cache file, network connection or guest. Unknown `recover.cc8Del` stays untouched; N1c remains paused.

## Scope and later acceptance

This is one component, not full native preflight. A returned capture proves bounded collection and owned wait completion; it is **not** an accepted native temp path, process snapshot, quiescence result or authenticated inspection. The next independently reviewed slice must parse paths/rows and enforce every exclusion, including both-snapshot leftover `getconf`/extra `ps` refusal. It must include the approved cancelled-parent/orphan native fixtures. No inspection activation is allowed before those proofs and the remaining marker/cache/temp/expected-commit namespace checks are complete.

## Review Focus

1. Sparse/high/inheritable FDs and closed stdio must cause full child exclusion or refusal, while preserving parent state — Task 1 native and boundary tests.
2. ECHILD, stale wait state and changed SIGCHLD must never manufacture a zero exit or authorize a signal — Task 2 state-machine tests.
3. Child exit before pipe EOF, EOF before exit and exit during process-event registration must not hang or signal descendants — Task 2 native interleavings.
4. Concurrent stdout/stderr overflow and failed notification setup must preserve limits and cleanup uncertainty without sleeps/retries — Task 2 unit/native tests.
5. Authority file replacement, symlink/special-file substitution or partial reads must refuse before spawn, without reading an arbitrary file — Task 1 real-file tests.

## Files and interfaces

- Create `ops/live-e2e/staging_diagnostics.py`: fixed binding, context, launch resources and owned collection. Keep one cohesive private lifetime; no generic executor or PID-control utility.
- Create `tests/ops/test_live_e2e_staging_diagnostics.py`: portable binding/guard/resource/lifecycle adversarial tests with OS-boundary fakes.
- Create `tests/ops/test_live_e2e_staging_diagnostics_native.py`: mandatory disposable Darwin/x86_64 FD and lifetime evidence; explicitly skipped on other platforms, never counted as native proof there.
- Modify `tests/live/README.md`: actual counts, native platform/version/results and remaining full-preflight/activation gates.

Produced types: `DiagnosticError(RuntimeError)` with fixed text `staging diagnostic rejected` and read-only exact-bool `cleanup_uncertain`; frozen/slotted `DiagnosticCapture(kind: Literal['getconf', 'ps'], stdout: bytes, child_pid: int)`. No process object, stream or mutable lifetime handle escapes. Success requires empty stderr, exact owned zero-exit wait result and both stream EOFs within the collection deadline.

Produced APIs: `capture_getconf() -> DiagnosticCapture`, `capture_ps() -> DiagnosticCapture`. No parameters. They validate `_require_identity()` and invoke private `_capture_fixed(kind: Literal['getconf', 'ps']) -> DiagnosticCapture`, which always checks actual `_require_wait_context()` and `_verify_authority()` before spawn. The latter never accepts argv, executable, PID, process or limit arguments. Native developer fixtures may fake account eligibility only; they must preserve the actual Darwin/non-root/thread/SIGCHLD/wait checks. No test bypass is shipped.

## Task 1: Authority, identity and child descriptor resources

**Consumes:** The already-main binding and Global Constraints.

**Produces:** `DiagnosticError`, fixed constants, private `_require_identity() -> None`, `_require_wait_context() -> None`, `_verify_authority() -> None`, and `_prepare_launch(*, deadline: float)` context manager. The deadline is an internal absolute monotonic value calculated from the selected fixed budget; it is not a public timeout option. Its private resource object supplies owned stdin/read/write FDs and immutable spawn file actions; `close_child_ends() -> None` closes only helper-owned parent copies. It has no spawn/signal method and takes no caller FDs or command parameters.

- [x] **Step 1: Write binding/context/resource RED.** Tests `test_binding_matches_exact_main_blobs`, `test_binding_refuses_changed_symlink_special_or_unstable_documents`, `test_context_refuses_wrong_platform_identity_admin_or_reaper_state`, `test_launch_excludes_inheritable_parent_fds_without_mutation`, and `test_fd_enumeration_overflow_refuses_before_spawn`. Assert fixed paths/lengths/hashes above, no lower-level error text, no child on refusal, and import produces no host action/output. Pin constant names and exact values with the following test (the `diagnostics` fixture imports the dormant module without invoking it):

  ```python
  def test_fixed_constants(diagnostics):
      assert diagnostics.GETCONF_ARGV == (
          "/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"
      )
      assert diagnostics.PS_ARGV == (
          "/bin/ps", "-ww", "-U", "502", "-o", "pid=,comm="
      )
      assert diagnostics.GETCONF_SECONDS == 5
      assert diagnostics.PS_SECONDS == 10
      assert diagnostics.CLEANUP_SECONDS == 2
      assert diagnostics.GETCONF_STREAM_BYTES == 1024
      assert diagnostics.GETCONF_COMBINED_BYTES == 2048
      assert diagnostics.PS_COMBINED_BYTES == 65536
      assert diagnostics.MAX_FD_NAMES == 1024
      assert diagnostics.AUTHORITY_COMMIT == (
          "1ddebe541ee80c0febc4cd35072f3a5046fac5cb"
      )
  ```

  Add native `test_parent_fds_preserved_and_absent_after_exec` and `test_closed_stdio_sparse_high_fds_and_lowered_limit_are_safe`; use fixture-owned canary files/descriptors, not incident state.
- [x] **Step 2: Run RED.** `env PYTHONPATH=src /tmp/pr119-verification-venv/bin/python -m pytest tests/ops/test_live_e2e_staging_diagnostics.py tests/ops/test_live_e2e_staging_diagnostics_native.py -q -o addopts=--import-mode=importlib`. Expected: missing module/interfaces; preserve output. No signal-capable implementation before plan approval.
- [x] **Step 3: Implement guards and resources.** Derive the fixed checkout lexically from the module location, with no caller root or alternate table. Walk its absolute directory chain from `/` using pinned no-follow directory FDs, then open each literal authority path relative to those FDs. Every directory must have owner UID in `{0, os.geteuid()}` and exact permission mode in `{0o700, 0o750, 0o755}`. Each document must be a regular file, owner UID in that same set, `st_nlink == 1`, and exact permission mode in `{0o600, 0o644}`. Reject other types, owners, modes or unsupported stat fields before bounded reads; use O_NONBLOCK for file-race safety. Compare file `(st_dev, st_ino, st_uid, st_gid, st_mode, st_nlink, st_size, st_mtime_ns, st_ctime_ns)` before/after the exact-length read plus EOF check. For every directory compare `(st_dev, st_ino, st_uid, st_gid, st_mode)` before/after, then reopen every name relative to its pinned parent and require those same identities/predicates; repeat the file identity/metadata comparison at the namespace lookup. Directory timestamps need not stay unchanged when unrelated siblings change. Require the exact raw lengths/hashes from the table. These are explicit POSIX metadata predicates plus immutable content binding, not a claim of complete ACL/same-account-compromise protection; trusted standalone checkout context remains a separate activation prerequisite. `_require_identity()` checks the exact account/home/UID and primary/supplementary admin membership. `_require_wait_context()` checks actual Darwin/x86_64, non-root, single-threaded/default SIGCHLD state; unsupported lookup/parent state refuses. Keep eligibility separate from wait ownership so native developer tests cannot erase lifecycle prerequisites.

  Allocate only owned pipes and fixed `/dev/null`; classify the latter as the trusted character-device source. Move helper-owned FDs below 3 to owned close-on-exec duplicates at or above 3, restoring originally closed parent stdio. Enumerate `/dev/fd` with bounded iteration/checks against the supplied absolute monotonic deadline; require canonical decimal descriptor names representable by the platform C file-descriptor type, reject duplicates/ambiguity and 1024-name overflow. No helper descriptor creation may occur between the completed enumeration and spawn; signal handlers/native background code that mutate FDs or reap children are unsupported standalone-parent conditions. Build child actions in order: duplicate owned stdin/stdout/stderr sources to 0/1/2, then close every still-open enumerated descriptor at or above 3, including helper pipe read ends. Add owned resource FDs explicitly. Check enumerated slots with fstat after the scanner closes; omit only non-owned slots proven closed by EBADF, reject every other error or missing owned FD. No descriptor may be allocated between this verification and spawn. Do not derive a closing range from RLIMIT_NOFILE or change borrowed flags.

  Use stdlib `os.posix_spawn` in Task 2. Its file actions affect the child; in-range already-closed descriptors are specified separately from other action errors by [POSIX](https://pubs.opengroup.org/onlinepubs/9799919799/functions/posix_spawn.html). Native Darwin 24.6.0 evidence found that a CLOSE action for the already-closed scanner FD returns EBADF. Omit that proven-closed slot before the first spawn, with no unsafe fallback or spawn retry. The RED/GREEN/native proof and minimal compatibility ruling are retained in the task ledger; the approved exclusion/ownership/signal boundary is unchanged. Do not use a generic Popen wrapper or a poll path that can convert lost wait ownership into exit zero.
- [x] **Step 4: Run GREEN and commit.** Same focused command must pass applicable tests. Native FD probes consume the exact resource actions in a fixture-owned exec and prove parent identity/usability/flags/offsets unchanged on success/error; no configurable production probe executable. Test count 1024/1025 and high FDs without a production-limit monkeypatch. Record actual native version and skips; diff/Ruff clean. Commit authority/resource module and tests only.

## Task 2: Exclusive capture, bounded cleanup and slice gates

**Consumes:** Task 1 constants, error, guards and launch-resource context manager.

**Produces:** `DiagnosticCapture`, both argument-free APIs and `_capture_fixed` above, plus README evidence. No full-preflight parser or caller.

- [x] **Step 1: Write capture/lifetime RED.** `test_fixed_argv_env_and_no_public_overrides`, `test_exact_own_wait_zero_and_both_eof_required`, `test_each_getconf_stream_and_combined_ps_byte_bounds`, `test_deadline_equality_is_refusal`, `test_echild_or_wrong_wait_pid_never_signals_or_succeeds`, `test_one_kill_only_for_current_unreaped_child`, `test_reaped_or_unknown_child_cannot_be_signalled`, `test_two_second_cleanup_and_failed_signal_reap_are_uncertain`, `test_no_partial_return_printing_state_access_or_diagnostic_retry`. Assert exact commands/limits, SIGKILL-only at most once, positive freshly spawned PID only, and no wait on -1/0. Cover spawn/registration errors, changed SIGCHLD, EINTR, nonzero/stderr, duplicated cleanup, ESRCH and retained pipes. The portable `lost_wait` fixture scripts the OS boundary: one freshly returned child PID, followed by `waitpid` raising ECHILD; it spies on all kill calls and output. It must satisfy:

  ```python
  def test_echild_cannot_be_success_or_signal(diagnostics, lost_wait, capsys):
      import pytest

      with pytest.raises(diagnostics.DiagnosticError) as error:
          diagnostics.capture_getconf()
      assert str(error.value) == "staging diagnostic rejected"
      assert error.value.cleanup_uncertain is True
      assert lost_wait.kill_calls == []
      assert capsys.readouterr() == ("", "")
  ```

  Add native positive getconf/ps controls and fixture-owned stdout/stderr, early-exit/early-EOF, overflow, stalled child and retained-descendant-pipe tests.
- [x] **Step 2: Run RED.** Use Step 1's focused command with the capture test names; expected missing capture APIs/behavior, not an unrelated platform failure. Preserve output.
- [x] **Step 3: Implement minimal owned collection.** Public wrappers check identity; `_capture_fixed` itself checks actual wait context and authority before any spawning. Inside `_capture_fixed`, start the monotonic deadline before resource preparation/spawn; select only the two fixed command tuples. Use direct `os.posix_spawn`, explicit environment/file actions and default child SIGPIPE/SIGCHLD; no forked Python application adapter, PATH variant, setuid/group/session option or generic command helper.

  Keep PID, reaped/unknown status and signal-sent state private to this invocation; never expose a live handle. Use only `os.waitpid(own_pid, os.WNOHANG)` and accept a terminal exit/signal status for that exact PID. ECHILD, unexpected PID/status or changed ownership preconditions means uncertainty, not exit zero. A spawn failure with no usable owned PID never permits rediscovery/signalling or a claimed reap.

  Check the same absolute collection deadline again immediately before `os.posix_spawn`; equality or expiry refuses without spawning. Make only owned pipe readers nonblocking. Use Darwin `select.kqueue` read events and an own-child `KQ_FILTER_PROC`/`KQ_NOTE_EXIT` notification, with waits bounded by the remaining monotonic deadline; no arbitrary polling sleep. Create the queue after spawn so it cannot leak to that child. Handle child exit during registration by an exact own-PID wait check; unresolved registration errors refuse. Bound each read by remaining stream/combined allowance plus one overflow byte, reject before retaining excess and never return partial bytes. EOF alone does not prove exit, and exit alone does not prove both EOFs.

  On failure, close owned readers, recheck exclusive unreaped state, permit at most one SIGKILL to the exact known live child, then attempt own-PID reaping within 2 seconds using available bounded notifications. If notification/ownership/status is unavailable, refuse with cleanup uncertainty rather than an unbounded wait or fallback PID search. Never signal a reaped child or descendant; collection failure remains failure after a successful reap. Close every owned resource on every path, preserving borrowed descriptors. Suppress lower-level error detail and emit nothing.
- [x] **Step 4: Run targeted/native GREEN.** Same focused suites PASS; on authorized Intel Mac, zero skipped eligible native cases. Native probes must execute the same resource/collection path; test-only substitution occurs at the OS-spawn boundary and asserts the production fixed argv first, with no shipped override. Faking `_require_identity()` only for developer-owned fixtures does not count as real UID-502/GitHub/main-context proof. Never fake `_require_wait_context()` or owned-wait operations in native evidence. Teardown touches only disposable fixture-owned processes/files; never incident PIDs, marker, staging, QEMU or running E2E. If a syscall/primitive cannot satisfy the contract, stop and revise design; do not relax assertions or add timing retries.
- [ ] **Step 5: Regression and documentation.** Run new suites plus the existing 403 codec/inventory/recovery/CI tests, full Ruff `src tests ops/systemd ops/live-e2e`, compile the new module and supported self-hosted Linux Python 3.13/3.14 full CI. Record native Python/kernel/platform results and every actual skip separately. Update README with actual counts and component-only limitations; no authority-document mutation. Commit the focused implementation/tests/README.
- [ ] **Step 6: Fresh whole-branch review and exact gates.** Review resource completeness, exclusive wait/signal ownership, queue/deadline interleavings, source binding, no host-state/credential reads and no workflow caller. Fix any finding via focused RED/minimal GREEN/regression. Require unchanged exact-head ordinary CI, native proof and no unresolved Critical/Important before expected-head merge. Verify exact merge-main ordinary CI; record actual automatic Level-3 stale-state refusal without cancellation or closure credit. Any other failure requires investigation.
- [ ] **Step 7: Retain evidence and next slice.** Audit clean branch/worktree state; preserve incident worktrees/evidence until A1 closure. Next prepare the process-snapshot/quiescence plan, including cancelled-parent/leftover diagnostics and no orphan signalling. No full-preflight/workflow activation, accepted receipt, apply, marker clearance, unknown-root disposal or N1c resumption follows from this component.

## Self-review and handoff

Task 1 produces only guards/resources; Task 2 consumes those exact interfaces and owns the entire child lifetime. Five Review Focus classes each have named owning tests. The native strategy is explicit because Darwin lacks the tested local Python's POSIX_SPAWN_CLOSEFROM constant, and implicit subprocess reaping is unsuitable for explicit ECHILD uncertainty; native proof remains mandatory, not inferred from that inspection.

Full row/path parsing, both-snapshot orphan refusal, pinned incident namespace/content revalidation and trusted workflow provenance are intentionally outside this component and remain acceptance prerequisites for the next slices. No full ADR 0012/preflight/A1 acceptance is claimed by partial capture tests. Read and approve this written plan before implementation; preserve the already selected native execution method.
