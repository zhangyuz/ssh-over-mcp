# Protected E2E Namespace Health Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one dormant, reusable check that accepts only a contemporaneously clean protected/known-legacy namespace and refuses unsafe, residual, drifted or unbounded evidence.

**Architecture:** Three focused Python modules separate immutable evidence, fixed Darwin metadata/discovery, and shared namespace inspection. The inspection has no caller-selected path or UID and no directory/marker mutation; fixed native temp discovery retains its explicitly permitted OS-managed directory effect. Existing orchestration, recovery and workflows continue using their current route until a later reviewed activation slice.

**Tech Stack:** Python >=3.13; stdlib descriptor-relative POSIX APIs and ctypes; Intel Darwin/APFS; pytest and ruff; existing dual-Python hosted CI.

**Spec:** [approved design](../specs/2026-10-13-protected-native-e2e-staging-design.md), reviewed at ef8961cca7fd546b476b9685fc8e44a435149831. The operator approved the written design on 2026-10-13 at 20:21:38 America/Toronto. This implementation plan still requires review and execution-method selection.

## Global Constraints

- Fixed protected root: `/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-e2e/staging-v1`.
- Fixed initial real/effective UID `502`, account `gha-e2e-orchestrator`, home `/Users/gha-e2e-orchestrator`; retain non-admin group policy.
- Trusted-main `zhangyuz/ssh-over-mcp`, Intel Darwin, non-root context before filesystem actions; no new CLI or workflow call site in this iteration.
- Legacy detection: literal `/private/tmp` and fixed-account `DARWIN_USER_TEMP_DIR`; only reviewed `/tmp` and native `/var` aliases.
- Existing image cache and two-field `active-run.json` stay unchanged.
- No tempfile selection/probes, arbitrary realpath/access/stat, payload reads, recursion into residuals, permission repair, migration or automatic orphan deletion.
- Native discovery requires a single-threaded standalone caller, default SIGCHLD and exclusive ownership of child wait status; no competing native reaper or FD-mutating signal handler.
- Fixed getconf stdout <=4096 bytes, stderr <=1024 bytes, 5-second execution deadline and at most 2 seconds owned-child termination/reap.
- Metadata scans: <=4096 direct entries per legacy parent, <=64 matching names, <=16 dedicated-owner matches across legacy parents; protected enumeration <=64 entries; aggregate 10-second metadata deadline.
- Protected provider base/staging-v1 require mode `0700` and no extended ACL entries. Existing Application Support permits `0700`/`0755`; Library must exist and validate.
- Only legacy `/private/tmp` permits root-owned sticky `1777`; never apply this exception to protected ancestors.
- Pin every no-follow directory edge; ordinary APFS system/data transitions are allowed, subsequently observed edge/device changes refuse.
- Errors, unsupported evidence and ambiguous resource cleanup refuse; no blind retries, no foreign process signals, no deleting destructor.
- Freeze ADRs 0011/0012, incident-pinned helpers/spec bytes, old envelopes/receipts, ADR0018 disposer/journal and historical provenance. No A1/B8/N1c closure.
- Update ignored worktree-root `progress.md` after each RED/GREEN, review, commit and external gate; preserve other agents' worktrees.

## Review Focus

1. Missing optional protected descendants: stable absence is inspectable, but a missing Library, inaccessible ancestor or substituted entry refuses; health evidence never authorizes later creation.
2. Mode-safe directory with ACL grants: private entries must be ACL-free; ancestor grant/ACL drift must not be mistaken for safety.
3. Cached Python selector differs from environment or appears during inspection: refuse unsupported values and later drift before any candidate-path access.
4. Marker-free residuals and matching non-directory entries: protected and both legacy parents still block; foreign shared-parent entries stay untouched.
5. Output flood, interrupted owned child, directory replacement or ambiguous FD close: preserve refusal/cleanup uncertainty without a second mutation attempt.

---

## Deliverable and deferred scope

The delivered feature is `inspect_namespace() -> NamespaceSnapshot`: an internal zero-argument inspection, with tests, real disposable Mac ACL evidence and ordinary/legacy regression evidence. It returns only after two clean observations and final edge/selector/context checks. The result is detached contemporaneous evidence, **not** a creation/removal capability or persistent health certificate.

| Design requirement | This iteration | Later separately reviewed deliverable |
| --- | --- | --- |
| Fixed identities, ACLs, lexical selectors, bounded getconf, protected+legacy absence | Tasks 1–3 | Reuse the same rules |
| Exclusive marker claim and creation of fixed descendants/run child | Inspection records stable missing suffix only | Owned workspace lifecycle |
| Original-root scoped removal, QEMU reap, no deleting finalizer | No removal API exists | Owned workspace lifecycle |
| Orchestrator/recovery/post-run shared callers and no-argument workflow health command | Dormancy contracts only | Already-main activation |
| Actual UID502 protected placement, guest use, cleanup, layout observation | Not claimed | Post-merge activation acceptance |
| A1/B8 reconciliation and native inputs/Ledger | Not advanced | Subsequent roadmap work |

Before implementation, after the operator reviews this plan and selects execution, integrate approved design/plan docs through PR242 with fresh exact-head checks and review, then verify exact merge-main hosted/native gates. Create an isolated implementation worktree from verified main via using-git-worktrees. The three tasks form **one** implementation PR; each task gets its own RED/GREEN and independent meaningful-GREEN review.

## File map and locked interfaces

Create:
- `ops/live-e2e/staging_namespace_types.py`: immutable evidence and fixed refusal type.
- `ops/live-e2e/staging_namespace_native.py`: fixed getconf lifecycle and FD-bound Darwin ACL snapshots.
- `ops/live-e2e/protected_staging.py`: selectors, context, pinned chains and shared two-observation inspection.
- `tests/ops/test_protected_staging_selectors.py`, `test_protected_staging_native.py`, `test_protected_staging_namespace.py`, `test_protected_staging_dormant.py`: focused portable/adversarial and Darwin fixture tests.
- `docs/evidence/2026-10-13-protected-staging-health-inspection.md`: actual slice evidence and explicit dormant limits, written during execution.

All test filenames above live under `tests/ops/`. Use the existing fixed sibling import pattern; resolve only literal sibling filenames from the trusted module directory. Do not import, modify or extend incident-pinned staging_preflight authority. Tests may monkeypatch private root/discovery/context seams onto disposable trees; production entrypoints expose no path/UID/environment/backend overrides.

Shared frozen dataclasses:
- `NativeTempParent(source: str, canonical: str)`.
- `SelectorSnapshot(overrides: tuple[str | None, str | None, str | None], module_loaded: bool, cached: str | None)`; override order TMPDIR, TEMP, TMP; preserve unset versus empty.
- `DirectoryIdentity(device: int, inode: int, uid: int, gid: int, mode: int, mtime_ns: int, ctime_ns: int)`; exclude atime.
- `AclSnapshot(serialized: bytes, tags: tuple[int, ...])`; tags preserve ACE order.
- `ParentSnapshot(label: str, chain: tuple[DirectoryIdentity, ...], acls: tuple[AclSnapshot, ...])`; labels fixed protected/private-tmp/native-temp.
- `ProviderContext(uid: int, euid: int, gid: int, egid: int, groups: tuple[int, ...])`.
- `NamespaceSnapshot(native: NativeTempParent, selectors: SelectorSnapshot, context: ProviderContext, protected_missing: tuple[str, ...], parents: tuple[ParentSnapshot, ...])`.
- `NamespaceError(reason: str, *, cleanup_uncertain: bool = False)`; fixed reason labels only: context, selector, native-discovery, namespace, residual, budget, drift. Message fixed `protected staging inspection rejected`, no raw path/env/child payload/exception text.

## Task 1: Bounded selector and native-discovery contract

**Files:** Create types/native/protected modules and selectors/native tests above.

**Interfaces:**
- Produces `_capture_selectors() -> SelectorSnapshot`, `_validate_selectors(snapshot: SelectorSnapshot, native: NativeTempParent) -> None` in protected_staging.
- Produces `discover_native_temp() -> NativeTempParent` and private zero-argument `_spawn_getconf() -> subprocess.Popen[bytes]`, `_require_owned_child_context() -> None` in staging_namespace_native.
- Produces the shared dataclasses/error; later tasks use these exact types.

- [ ] **Step 1: Write selector/discovery tests.** Cover each accepted alias and one trailing slash; reject non-str cached values, Unicode/NUL/whitespace, >4096 bytes, relative/dot/redundant separators, /var/tmp, /usr/tmp and another account-token before candidate filesystem access. A loaded tempfile module becoming absent/present or its scalar changing changes the snapshot. Patch gettempdir/gettempdirb/_get_default_tempdir and candidate stat/access/resolve to fail if called.
  `test_selectors_never_probe_paths`: unsupported selection raises reason selector and leaves the access spy empty.
  `test_native_capture_is_canonical`: exact `/var/folders/ab/runner_123/T/\n` yields source without newline and canonical `/private` + source; shard is exactly two lower alphanumerics, token 1–255 lower alphanumerics/underscores.
  Pin representative assertions in the Task1 tests:
  ```python
  assert native.source == '/var/folders/ab/runner_123/T/'
  assert native.canonical == '/private/var/folders/ab/runner_123/T/'
  assert error.value.reason == 'selector'
  assert candidate_path_accesses == []
  ```
  Parametrize zero/nonzero exit, missing/extra newline, truncation, stdout4096/4097 and stderr1024/1025, 5-second deadline, terminate/reap2-second boundary, reap failure, interruption and unrelated PID canary. Reject changed SIGCHLD/non-main or multiple Python threads before spawn; late context drift preserves cleanup uncertainty. Inject waitpid ECHILD/external-reap/PID-reuse canaries and assert no signal occurs after ownership uncertainty.
- [ ] **Step 2: Run RED.** `PYTHONPATH=src /Users/yuz/src/ssh-over-mcp/.venv/bin/python -m pytest -o addopts='' tests/ops/test_protected_staging_selectors.py tests/ops/test_protected_staging_native.py -q`. Expected missing-module/interface FAIL; record individual intended failures before implementing their behavior.
- [ ] **Step 3: Implement the locked types and functions.** Read os.environ and sys.modules only; never import tempfile merely to capture its cache. Freeze/validate exact ASCII scalars, then compare a fresh snapshot before each clean observation. Getconf argv exactly `('/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR')`, env exactly `{'LC_ALL': 'C', 'LANG': 'C'}`, shell=False, close_fds=True, stdin=DEVNULL. Use nonblocking pipes/selectors, incremental capped bytes and one monotonic deadline; never communicate with unbounded capture. Before spawn and each owned wait/signal, require main-thread execution, threading.active_count()==1 and SIGCHLD==SIG_DFL; retain the standalone trusted-caller assumption of no native competing reaper or FD-mutating handler. Use os.waitpid(child.pid, WNOHANG) as the sole wait-status consumer; check returned PID/status, set Popen.returncode only after our positive reap, and treat ECHILD as uncertainty. Do not use Popen.poll/wait/communicate to classify external reap as success. On overflow/timeout/interruption, use os.kill on only the positively owned unreaped child after a fresh wait-context/status check, TERM then KILL as necessary within the single 2-second cleanup budget; never signal after ECHILD/context uncertainty.  uncertain reap sets cleanup_uncertain. Close pipes on every exit; ambiguous close refuses. Native confstr's possible OS-created temp directory is the sole permitted discovery filesystem effect.
- [ ] **Step 4: Run GREEN and meaningful-GREEN review.** Repeat Step2; all Task1 cases PASS. Add disposable real-child flood/hang/reap tests via the private spawn seam, with no foreign signalling or persistent provider use. Record observed timings and review findings in progress.md.
- [ ] **Step 5: Commit.** Stage only Task1 modules/tests. Commit `feat: add bounded protected staging discovery contracts`.

## Task 2: FD-bound ACL and fixed namespace identity checks

**Files:** Modify staging_namespace_native/protected_staging; add native/namespace fixture cases.

**Interfaces:**
- Produces `read_acl(fd: int) -> AclSnapshot` in native module; caller owns the FD.
- Produces private `_pin_namespaces(native: NativeTempParent) -> ContextManager[_PinnedNamespaces]` in protected_staging.
- `_PinnedNamespaces.revalidate() -> None`, `snapshot() -> tuple[ParentSnapshot, ...]`, `protected_missing: tuple[str, ...]`, `protected_fd: int | None`, `legacy_fds: tuple[int, ...]`; private held chains remain usable only in the context. No mutation methods. `_open_literal_root() -> int` is the zero-argument disposable-fixture seam.

- [ ] **Step 1: Write identity/ACL tests.** `test_missing_support_suffix_is_stable_and_uncreated`: absent optional suffix returns its fixed components; Library absence refuses and mkdir spy stays empty. Parametrize every edge with link/type/owner/mode swaps at stat→open and before final revalidation, normal APFS device transition, later device drift, lost FD and ambiguous close.
  `test_acl_grant_refuses_even_with_mode_0700`: an allow ACE on an ancestor refuses; any ACE including deny on private base/staging-v1 refuses. `test_ancestor_deny_does_not_grant_authority`: deny-only ancestors may pass, exact ACL snapshot drift refuses. Pin representative Task2 assertions:
  ```python
  assert pinned.protected_missing == ('Application Support', 'ssh-over-mcp-e2e', 'staging-v1')
  assert fixture_mutations == []
  assert error.value.reason == 'namespace'
  assert ambiguous_close.value.cleanup_uncertain is True
  ```
  Add null-return/errno, bad ABI/symbol, bad tag, bound and free-failure cases.
- [ ] **Step 2: Run RED.** Run native and namespace test files using Task1 Python command prefix. Expected missing read_acl/pinning behavior FAIL; distinguish injected platform faults from intended product RED.
- [ ] **Step 3: Implement fixed FD ACL acquisition and pinning.** Load only `/usr/lib/libSystem.B.dylib` lazily on supported Darwin x86_64 with explicit ctypes argtypes/restype/use_errno. Use acl_get_fd_np(fd, ACL_TYPE_EXTENDED=0x100), acl_size, acl_copy_ext, acl_get_entry, acl_get_tag_type, acl_free. Never parse ls output or resolve principal names. Bound exported ACL bytes at16384 and ACEs at128. Obtain serialized bytes plus each allow(1)/deny(2) tag, preserve order; reject unknown tags/results. Darwin iteration succeeds with return0, end is -1/EINVAL after FIRST(0)/NEXT(-1), not Linux-style return1/0. Clear errno before retrieval; a NULL/ENOENT is accepted as no ACL only for the supported FD-bound APFS behavior proved by real fixtures and unchanged surrounding fstat/edge evidence; every other NULL/error/ambiguity refuses. Free every owned ACL exactly once; free uncertainty refuses.
  This first deliverable conservatively supports empty or deny-only ACLs on ancestors and rejects **all** allow ACEs, including self/root grants; it needs no UUID/membership/name-resolution exception. Private provider-base/staging-v1 require zero ACEs. Document this narrower supported set; a needed allow-ACE exception requires separate review rather than repair or guessing.
  Protected chain: / and Users root-owned safe directories; fixed account home and Library account-owned safe directories; Application Support account-owned0700/0755; provider-base/staging-v1 account-owned0700. Native chain: private/var/folders/shard root-owned safe; account token0700/0755 and T0700 account-owned. Safe means no group/world write or unexpected special mode bits. Literal private/tmp is separately validated root-owned1777 inspection-only; snapshot its ACL without treating shared grants as private-root authority.
  Open one component at a time O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC; compare preceding no-follow stat with fstat, owner/group/mode/ACL and held parent edge. Pin from literal /; detect fixed allowed missing suffix via ENOENT with the parent held, never conflate EACCES or replacement with absence. Preserve normal device transition instead of requiring all ancestors on one device.
- [ ] **Step 4: Run GREEN plus real Mac fixture evidence and review.** Same focused tests PASS. On the non-root developer Mac account, use only newly created pytest-owned disposable directories: no ACL, explicit empty ACL, everyone deny delete, everyone allow write, inheritable allow, ACL change while FD held and renamed/replaced directories. Fixture chmod ACL operations and fixture cleanup target only their own temporary trees; never UID502 roots, provider payload, sudo or account repair. Compare libc results with fixture metadata, require actual ACL tests PASS (Linux skips are not Mac evidence). Record Darwin/APFS/runtime versions and resource cleanup. If NULL/ENOENT semantics or ABI differ, stop with a ruling/revised plan, never silently accept it.
- [ ] **Step 5: Commit.** Stage Task2 changes only. Commit `feat: pin protected staging namespace and native ACL evidence`.

## Task 3: Shared two-observation namespace health check

**Files:** Modify protected_staging; add namespace/dormant tests; add slice evidence and update the current ADR/design/roadmap status only to implemented-dormant after verified implementation.

**Interfaces:**
- Consumes Task1 discovery/selectors/types and Task2 pinned namespaces.
- Produces `inspect_namespace() -> NamespaceSnapshot` with zero arguments; no filesystem/process actions at import time.
- Private `_validate_context() -> ProviderContext` validates current context and snapshots real/effective IDs and sorted actual group IDs; no caller identity input.
- No CLI, marker/QEMU judgement, create/remove helper, new receipt or replacement of existing recovery APIs. Later trusted callers must separately validate exact trusted-main checkout, marker/process state and perform inspection at the required lifecycle boundary.

- [ ] **Step 1: Write health/dormancy tests.** `test_marker_free_protected_entry_blocks`: any private entry, even wrong prefix/owner/type, raises residual. `test_legacy_owned_entry_blocks_without_read`: directory/file/link/FIFO/socket matches in either legacy parent block without reading content/traversing targets; foreign shared-parent matches remain untouched. Parametrize4096/4097 direct entries and64/65 foreign prefix matches (aggregate conservative limit) in otherwise clean legacy scans, plus10-second scan budget. Owned inventories of16/17 and private inventories of64/65 must refuse without exceeding bounds; early residual refusal is permitted and must not enumerate the rest just for reporting. Clean checks require two passes; inter-pass entry insertion, selector/group/context drift, ACL or ancestor replacement and last-revalidation swaps refuse.
  `test_public_inspection_has_no_path_override`: signature has zero parameters and supplied arguments raise TypeError.
  `test_module_is_dormant`: imports have no host operations; existing orchestrator/recovery/workflow bytes and pinned historical helpers remain identical to baseline. Patch unlink/rmdir/chmod/chown/mkdir/tempfile probes and unrelated signal paths to fail during inspection. Pin representative Task3 assertions:
  ```python
  assert inspect.signature(module.inspect_namespace).parameters == {}
  assert error.value.reason == 'residual'
  assert residual_payload_reads == []
  assert foreign_canary.read_bytes() == b'preserve-me'
  ```
- [ ] **Step 2: Run RED.** Run selectors/native/namespace/dormant files; expected missing inspect_namespace or missing refusal FAIL. For each fault, first prove the fixture actually reaches the intended race/boundary.
- [ ] **Step 3: Implement inspect_namespace and context.** Require GITHUB_ACTIONS=true, GITHUB_REPOSITORY exact, GITHUB_REF=refs/heads/main, event push/workflow_dispatch, canonical GITHUB_SHA, Intel Darwin, real/effective UID502, fixed passwd identity/home, no admin membership; snapshot/recheck real/effective GIDs and supplementary IDs as well as UID context before success. No extra context child or arbitrary process inventory is added.
  Freeze selectors, complete/reap fixed discovery, validate selectors lexically, pin all declared parents (deduplicate native aliases), then perform two bounded metadata-only scans under one10-second monotonic metadata deadline. Use os.scandir on held directory FDs and os.stat(single_name, dir_fd=..., follow_symlinks=False); never allocate an unbounded entry list. Matching legacy objects owned by502 always refuse; any private entry refuses, including unsupported names. Foreign private/native-boundary evidence refuses when it defeats private ownership rules. Treat every scan error or elapsed-budget edge as refusal.
  Revalidate edges/ACLs and stable missing suffix before/between/after scans, recheck selectors/context/groups and return detached snapshot only after owned-FD close success and final fixed-edge drift checks. Follow existing reviewed two-pass/reverse reject-only post-close drift strategy in new code; do not import frozen incident helpers. POSIX observations are not atomic and do not protect against root or compromised same-account concurrent writers.
- [ ] **Step 4: Run focused GREEN, applicable full regression and review.** Run all new tests and existing tests/ops/test_live_e2e_orchestrator_contract.py, tests/ops/test_live_e2e_recovery.py, tests/ops/test_live_e2e_preflight_native_temp_chain.py and tests/ops/test_project_status_docs.py. Run ruff check src tests ops/systemd ops/live-e2e and compileall with existing Python. Fresh independent security review must cover all tasks, authority/TOCTOU/resource uncertainty and five Review Focus classes; blocking findings get their own RED→GREEN fix.
  Record actual evidence only; never label mock/fixture checks actual provider admission or new-placement native acceptance.
- [ ] **Step 5: Commit.** Commit `feat: add dormant shared E2E namespace health inspection` with matching docs and actual pre-merge evidence.

## PR, merge and iteration completion

- [ ] Run the complete ordinary validation suite through exact-head hosted CI, both Python3.13/3.14 and all eight partitions; review the final exact SHA.
- [ ] Run applicable exact-target no-network legacy E2E with already-main authority before merging this filesystem-boundary slice. Candidate modules are exercised only in the disposable target guest or authorized developer disposable metadata fixtures; no PR helper runs as UID502 on the persistent provider.
- [ ] Merge only after gates and fresh independent final review pass. Verify exact merge-main hosted plus actual native legacy E2E and cleanup. Existing native placement remains legacy; do not claim protected placement proof.
- [ ] Record external CI/review/cleanup evidence in ignored progress/private handoff after merge; do not start an evidence-only commit loop or certify future SHAs. Audit/remove only this completed implementation worktree/branch after authoritative checks. Preserve all historical data and foreign worktrees.
- [ ] Present the single delivered dormant inspection capability and its limits; then prepare the next separately reviewable owned-workspace lifecycle plan.

## Following iteration boundary: creation/removal must not creep into this slice

The approved full design requires a separately reviewed removal decision before any implementation of owned lifetime. Proposed next-plan primitive: explicit descriptor-relative traversal from the original owned root FD; no-follow stat/open/fstat and parent-edge rechecks before each unlink/rmdir; symlink entries are unlinked without following destinations; final root removal/absence is relative to held staging FD. No absolute-path shutil.rmtree fallback, orphan deletion API, implicit finalizer deletion or cleanup retry. That next plan must pin entry/depth/deadline budgets, original-root/child ownership and mount rules, QEMU ownership/reap ordering, marker identity/uncertainty, abrupt-interruption and swap canaries. These choices are **not** implementation authority in this plan.

## Primary-source implementation references

Apple Libc revision `71bbe350ab79eef58113991d817ccc6165061a64`:
- [sys/acl.h](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/include/sys/acl.h), blob be4df84eca77924d1aba92e23fa9689150bacd4b: constants and signatures.
- [acl_entry.c](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/posix1e/acl_entry.c), blob a690c004b2151644b52b81cec13abdc80d161478: Darwin iteration0/-1, tag semantics.
- [acl_file.c](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/posix1e/acl_file.c), blob6b62d13fb9dc1b36f096be67610b7401d4603133; [filesec.c](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/filesec.c), blob64e73d0e7731e2d2ecc19f57dfe76cdf9807fe1b: FD retrieval and missing ACL property ENOENT.
- [confstr.3](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/confstr.3): native discovery's possible OS-managed temp creation. Installed provider macOS15.8 acl_get_fd(3) was read during planning; runtime fixture acceptance remains mandatory.

Self-review: this plan covers all inspection requirements and explicitly defers lifecycle/activation proof. No product code or provider mutation has been executed. Review method recommendation: native implementation in this session with meaningful-GREEN and final independent security review, because the three tasks share tightly coupled evidence types and one read-only namespace boundary.
