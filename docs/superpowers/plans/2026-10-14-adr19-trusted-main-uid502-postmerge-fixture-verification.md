# ADR 0019 Trusted-Main UID502 Postmerge Fixture Verification — Revised Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (or subagent-driven-development). Track RED→GREEN, commits and review gates using `- [ ]` checkboxes.

**Status:** **Revised, awaiting operator approval and independent re-review. NOT authorized to execute code on persistent Mac.** Resolves [PR #250 review #6175203163](https://github.com/zhangyuz/ssh-over-mcp/pull/250#issuecomment-6175203163): 0 Critical / 3 Important / 1 Minor. This PR remains **documentation only**.

**Goal:** Prove the actual **already-merged Slice 2A** dormant FD-bound fixture implementation at real dedicated **UID/eUID502**, x86_64 macOS/APFS; never count a separate lookalike test program as proof.

**Architecture:** Independently reviewed and merged **manual trusted-main-only** self-hosted workflow; fixed and original-FD-verified **verification-only APFS sandbox**, never either legacy temp parent or production protected staging. A harness invokes the exact merged `staging_owned_lifetime.py` and `staging_namespace_native.py` functions and emits per-case source/call provenance. Existing live workspace/marker/reap/placement remain unbound. Every skipped/unexercised case stays **UNVERIFIED**.

**Tech Stack:** Python **>=3.13** (pinned offline interpreter); GitHub Actions `workflow_dispatch`; existing pinned checkout; macOS x86_64, `fstatfs$INODE64`/ACL; Python stdlib and existing 2A module. **Spec:** [ADR0019](../../decisions/0019-protected-native-e2e-staging.md), [approved design](../specs/2026-10-13-protected-native-e2e-staging-design.md), [approved 2A plan](2026-10-14-adr19-owned-protected-workspace-lifetime.md), [methodology](../../development-methodology.md).

## Global security constraints

- **Trusted source only:** trigger exactly `workflow_dispatch`, repository exactly `zhangyuz/ssh-over-mcp`, event name `workflow_dispatch`, ref `refs/heads/main`, no caller/PR SHA, dynamic inputs, `workflow_run`, push or fork trigger. Fail before checkout on any mismatch. Require lowercase 40-hex `GITHUB_SHA` and exact `git rev-parse HEAD == GITHUB_SHA` **after** checkout, clean `git status --porcelain=v1`, no checkout secrets. No code from PR target executes on persistent host.
- **Checkout (test each option):** `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` with `ref: github.sha`, **`persist-credentials: false`**, **`clean: true`**, **`fetch-depth: 1`**. Explicitly test no persisted auth token/credential helper and no `GITHUB_TOKEN`/`GH_TOKEN`/application tokens passed to interpreter. No credential-bearing env, sudo, network install or dynamically sourced shell script.
- **Runner trust:** exactly `[self-hosted, macOS, X64, ssh-over-mcp-e2e-orchestrator]`, real/effective UID502, fixed account `gha-e2e-orchestrator`, non-admin, Darwin x86_64, `contents: read`, `concurrency: group: live-local-e2e; cancel-in-progress: false` shared with old native Level-3. Wrong/unknown identity, existing provider marker or running/unknown QEMU refuses before any fixture mkdir. No runner or production workflow permissions changed.
- **Python provenance:** prohibit PATH lookup of `python3`, `/usr/bin/python3` fallback, Conda/venv autoactivation or runtime `pip install`. Read-only discovery on Yuz.local UID501 found `/usr/local/bin/python3.13` resolves to `/usr/local/Cellar/python@3.13/3.13.16/Frameworks/Python.framework/Versions/3.13/bin/python3.13`, CPython **3.13.16 x86_64**, owned by trusted operator UID501, not root; ancestors are likewise operator-owned and not writable by UID502 in current observation. **Explicit plan/security approval must accept or reject this operator-owned supply-chain risk**; do not silently presume root ownership. Only the approved fixed absolute resolved binary may execute. Revalidate file and all ancestor/symlink owner/group/ACL/mode, no UID502/group/world write, `sys.executable`/realpath, `sys.version_info >= (3,13)` and approved exact interpreter version. Record actual path, stat and version as run evidence. Changed interpreter or unsupported version refuses; no skip-as-pass.
- **Fixed verification namespace:** `/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-uid502-verification-v1`, a **literal sibling** of production `.../Application Support/ssh-over-mcp-e2e/staging-v1`. Verify UID502 home/`Library`/`Application Support` via pinned original directory FDs, `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, owner, device/inode, mode and APFS ACL; no symlink/alias or untrusted test root selector. Only missing literal verification parent may be created mode `0700` with checked parent dir_fd and immediate original-FD revalidation. Existing unexpected/unsafe parent or ACL refuses (no chmod, chown, repair or adoption). Per-run direct child **`adr19-uid502-verify-` + 32 lowercase hex** nonce created exclusively within verified verification-only parent; inside it allocate a **nested `Library`** for the actual 2A fixture marker and child operations.
- **Explicit disjointness:** Never use `tempfile.gettempdir()`, `tempfile.TemporaryDirectory()` or ordinary pytest `tmp_path` for the verifier root. The verification parent and children are **not inside** the fixed provider marker (`Library/Caches/ssh-over-mcp-e2e/active-run.json`), protected staging parent, literal `/private/tmp`, nor discovered native `DARWIN_USER_TEMP_DIR` (including canonical `/private` variant). Parent/child original-FD proofs and bounded inventory enforce disjointness, not just string prefix. Legacy scanners examine **direct children** of both temp parents for `ssh-over-mcp-e2e-`; verification direct child names start `adr19-uid502-verify-` and exist outside both parents. The *nested* real 2A workspace retains its genuine `ssh-over-mcp-e2e-` prefix in the isolated subtree. Test a retained injected-failure artifact to prove it cannot become a supported legacy residual, with original protected+both-legacy inspections before/after.
- **Forensics (no orphan disposer):** preflight verification-only parent with bounded FD-relative scan; any prior unknown/residual child blocks a fresh attempt **before mkdir**. On fixture interruption/failed unlink/close/ACL, **retain** the failed run's exact original files *in place in the verification-only namespace*; report original basename, dev/inode, mode, ACL, FD disposition, error reason, and whether provider/legacy scans still pass. This is “quarantine by containment,” **not** moving, deleting, adopting or recovering foreign state. Explicit separately reviewed manual disposition required for residuals; no broad `rm -rf` or automatic retry. POSIX check→unlink is non-atomic; require exclusive single-writer UID502 fixture principal.
- **Real module or no acceptance:** test harness must invoke the exact **merged** original `staging_owned_lifetime._claim_disposable_fixture`, `_create_for_fixture`, `_fixture_never_started_receipt`, `_dispose_never_started_fixture`, `_FixtureOwnedWorkspace.verify_single_owned_child`, `_FixtureOwnedWorkspace.close` and original `staging_namespace_native.read_acl` plus native `fstatfs$INODE64`. No rewritten clone of their mkdir/ACL/unlink algorithm is acceptable. Production `create_owned_workspace()`, `OwnedWorkspace.__init__()`, `OwnedWorkspace.dispose()` must still fail `unbound`. Source module path and code-object provenance must resolve inside exact trusted-main checkout.
- **Provider health:** before and after test, independently verify actual marker absence, QEMU absence and `protected_staging.inspect_namespace()` clean observations covering **protected + BOTH legacy parents** (account context must be valid; refusal/unknown state stays UNVERIFIED). No repair/deletion of provider marker, legacy residual or unknown fixture. Existing old-path [main Level-3 #38610244911](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38610244911) PASS is *not* UID502 fixture proof.
- **Evidence & merge:** output exact SHA, run/job IDs, uid/euid/group, interpreter path/version/owner, APFS device/mount, actual original-module SHA+path, per-row function call audit, fixed root identity and cleanup/retention plus protected+legacy health. “UID502 PASS” requires **every mandatory row physically exercised on UID502** and clean scoped disposition; mock-only/skip/indirect cases remain **UNVERIFIED**. No production activation, real original O_EXCL marker handoff, QEMU-reap issuer or automatic PR-native authority. Request independent implementation review when code/self-review complete **without waiting for CI**; exact-head CI and security review still gate merge.

## Test-to-original-code traceability — all required for UID502 acceptance

| Real UID502 case | Exact merged code path, NOT duplicate algorithm | Observed assertion |
| --- | --- | --- |
| Exclusive marker | `_claim_disposable_fixture(library_fd)` / original `_FixtureClaimPermit` | Fresh `O_CREAT|O_EXCL`, original claim FD+inode; pre-existing same-PID lookalike refuses |
| Parent chain, creation | `_create_for_fixture(permit)`, `_FixtureOwnedWorkspace._verify_claim_and_ancestors` | Original nested Library → Application Support → base → staging FD/ACL/mode/inode, foreign mkdir rejected |
| Positive lifecycle | `_fixture_never_started_receipt` then `_dispose_never_started_fixture` | Original owned test child deleted by real code; marker FD/identity logged, success-only exact-marker + empty-wrapper teardown separately checked |
| Positive actual APFS and ACL | `staging_namespace_native.read_acl`, original `_validate_private_dir`, `fstatfs$INODE64` | UID502 0700 + no-ACE held FDs; APFS mount/device |
| Negative actual ACL | Same real `read_acl`/`_validate_private_dir` with isolated allow/deny/extended ACE fixtures | **Real** OS ACL rejection before unsafe mutation; no mock-only credit |
| Root/marker/ancestor replacement | `_FixtureOwnedWorkspace.verify_single_owned_child`, original `_dispose_never_started_fixture` | Wrong original inode/symlink/renamed ancestor refuses; outside files unchanged |
| Symlink and bounded scan | Original `_remove_fixture_descendants` + `_bounded_names` | No-follow nested foreign target and 140-entry stop at 129; no outside deletion |
| Interrupted unlink/FD close | Original `_dispose_never_started_fixture`, `_FixtureOwnedWorkspace.close`, `_FixtureClaimPermit.close` | Uncertain state, no automatic retry/finalizer removal, original evidence retained |
| Disabled production entrypoints | Original `create_owned_workspace`, `OwnedWorkspace.__init__`, `OwnedWorkspace.dispose` | All refuse `unbound` and leave provider untouched |

**Trace enforcement:** `tests/ops/test_uid502_fixture_harness.py::test_harness_traces_original_2a_calls` must FAIL when any original call/import or code-object provenance is removed or replaced. The runtime harness records actual calls to the original merged functions, rejects mock-only “PASS,” verifies each `__code__.co_filename` and module path under exact main checkout, and refuses to close UID502 acceptance when any row is unobserved. No test-selection or path input accepted from dispatch.

## Review Focus

1. Untrusted PR/fork/ref/dirty checkout or token exposure → `test_native_uid502_workflow_never_checks_out_pr_head` and `test_checkout_is_credential_free_exact_main` (Task 1).
2. Wrong UID/admin/Python 3.12/PATH/changed interpreter ownership → `test_native_uid502_identity_gate` and `test_interpreter_provenance_refuses` (Task 1).
3. Marker/QEMU/foreign legacy residual or retained test artifact → `test_native_uid502_provider_busy_gate` and `test_retained_failure_never_matches_legacy_prefix` (Tasks 1–2).
4. Parallel recreated algorithm, fake trace, original root/ancestor replacement → `test_harness_traces_original_2a_calls` and `test_native_uid502_swap_preserves_foreign` (Task 2).
5. Real ACL denial, failed close/unlink or missing tested row → `test_actual_acl_negative_unverified_if_unavailable` and `test_native_uid502_failure_preserves_evidence` (Task 2).

---

## Task 1 — Trusted checkout + interpreter + marker/QEMU preflight

**Files:** Create `.github/workflows/adr19-uid502-fixture.yml` and `tests/ops/test_uid502_fixture_workflow.py`.

- [ ] RED `test_checkout_is_credential_free_exact_main` plus workflow contract: manual-only main/exact-repo/event, original checkout action SHA and **all** `ref=github.sha`, `persist-credentials=false`, `clean=true`, `fetch-depth=1` settings; clean worktree, exact SHA, no credential env/helper, serialized runner + provider marker/QEMU refusal.
- [ ] RED `test_interpreter_provenance_refuses`: interpreter provenance: exact approved absolute resolved binary (observed CPython 3.13.16), owner/ACL/parent chain verified and inaccessible to UID502 modification; wrong Python/owner/ACL/path/permission refuses.
- [ ] GREEN implement *merged-main-only* workflow/preflight; never run PR-controlled candidate on Mac. Run focused contract regression/Ruff; commit.

## Task 2 — Fixed disjoint sandbox + actual-code trace and UID502 negative matrix

**Files:** Create `ops/live-e2e/verify_uid502_fixture.py` (or small same-purpose driver) and `tests/ops/test_uid502_fixture_harness.py`; extend original native fixture tests only for actual host-only cases.

- [ ] RED `test_retained_failure_never_matches_legacy_prefix`: preflight and retained-failure tests: verification parent is FD-held sibling under UID502 Application Support; never either legacy direct child nor production staging/marker. Force interrupted nested fixture, **retain** its original in-place identity, show full `inspect_namespace()` and both-legacy clean, and block next run on leftover evidence.
- [ ] GREEN construct one verified fixed parent/run `adr19-uid502-verify-<32hex>` and pass its nested fixture Library FD to *real* `_claim_disposable_fixture`. No `tmp_path` fallback, unverified preexisting entry reuse, generic recursive cleanup or separate private mkdir implementation. **Success-only outer teardown:** after the actual 2A disposer removes its original run child, verify the original fixture marker FD/entry and empty nested directories using held FDs, unlink only the exact original test marker and rmdir only the now-empty fixed named wrappers and this original nonce child via pinned parents. Log their original dev/inode and final absence; never touch a production marker. If cleanup or identity becomes uncertain, stop and retain the whole verification-only run in place (no retry or path fallback).
- [ ] RED `test_harness_traces_original_2a_calls`: replace/remove call to each exact original implementation object and require failing contract; verify source path/bytecode file and exact main SHA.
- [ ] RED `test_actual_acl_negative_unverified_if_unavailable`; GREEN actual original-code matrix in table: ACL allow/deny real APFS ACEs, ancestor/marker/root swap, symlink, 140-item bound, unlink/close interruption, disabled live API; bounded deterministic fixture-only operations and explicit per-row verdict. If a safe real ACL fixture cannot be made, mark **UNVERIFIED**, never claim acceptance.
- [ ] Run fixed-matrix tests plus protected staging regression and Ruff; commit. No workflow execution on UID502 until independent review and main merge.

## Task 3 — Documentation and immediate independent security review

**Files:** New `docs/evidence/2026-10-14-adr19-uid502-native-acceptance.md`; edit `docs/development-plan.md`.

- [ ] Document proposed execution protocol, exact code trace, interpreter trust decision and unverified real-host state, avoiding premature native PASS.
- [ ] Run host-independent contract tests, Ruff, compileall, `git diff --check`, and no modifications to current orchestrator/recovery/legacy Level-3 workflows.
- [ ] Open separate implementation PR; **request whole-project independent review immediately upon coding/self-review**, not after CI. Resolve findings RED→GREEN; require exact final SHA CI and clean review before merging.

## Task 4 — Trusted already-main actual UID502 execution and evidence

- [ ] **Only after** reviewed workflow/harness merges on `main`, dispatch manually with no inputs while native Level-3 idle. Confirm execution code source equals checkout `GITHUB_SHA`.
- [ ] Inspect original job logs for UID/eUID502, nonadmin, approved real interpreter version/ownership, APFS/ACL, original-code call trace for **all nine rows**, cleanup or retained original forensic evidence and clean protected+both-legacy observations.
- [ ] On any skip, missing trace, prior fixture residual, interpreter drift, unknown provider/QEMU/ACL, bad FD close or unclean verification root: leave **UID502=UNVERIFIED** and preserve evidence without automatic retry/deletion.
- [ ] After genuine full PASS, separately review evidence closure. Protected placement and QEMU-reap/marker handoff still require separate Slice 2B/3 approvals.

## Approval gate

This is a **new persistent trusted-host test surface**. Prior instruction to merge inert PR249 is not permission to install/run an unreviewed workflow or bypass current runner privilege boundaries. **First** obtain operator approval and independent security re-review of this plan, including trust in the observed operator-owned Python binary and fixed sandbox parent. **Then** native inline RED→GREEN implementation, immediate independent implementation PR review while CI runs, exact-main merge and manual host verification.
