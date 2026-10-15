# ADR 0019 UID502 Inert Trusted Preflight Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** DRAFT for joint operator review with the spec; **NOT approved for implementation or persistent Mac execution.**

**Goal:** Deliver a host-independent, fail-closed UID502 preflight *schema/consistency contract* and adversarial tests without granting real host or CI execution authority.

**Architecture:** One inert Python 3.13+ module of immutable evidence records and pure validators; one hosted-only test file imports it as an external file. Deterministic `CONTRACT_REFUSED` or `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` results are **not authorization, real host attestation, or UID502 acceptance**. An optional future trusted-main collector remains outside this PR.

**Tech Stack:** Python >=3.13 stdlib (`dataclasses`, `re`, `stat`, `typing`), pytest, Ruff; repository CI uses hosted Ubuntu 26.04 Python 3.13/3.14.

**Spec:** [2026-10-14 ADR 0019 UID502 trusted preflight design](../specs/2026-10-14-adr19-uid502-trusted-preflight-design.md). Related: [original postmerge UID502 physical matrix plan](2026-10-14-adr19-trusted-main-uid502-postmerge-fixture-verification.md), [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md), [methodology](../../development-methodology.md).

## Global Constraints

- **Proven baseline:** existing trusted `main` `23f64a9d26fdaf6d4f6806397fffbb3636f9ddc4`, [CI #38648215422](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38648215422) SUCCESS, including real old-path QEMU Level-3 and postrun marker absence. This does **not** prove UID502/APFS protected staging.
- **Source scope:** Create `ops/live-e2e/uid502_preflight_contract.py` and `tests/ops/test_uid502_preflight_contract.py`; modify only `docs/development-plan.md` and an appropriately small verification evidence note. Never change `.github/workflows/`, frozen incident/native source, `staging_owned_lifetime.py`, `protected_staging.py`, orchestrator, recovery or runner/CI permissions. Any out-of-scope change needs a fresh design gate.
- **No new authority:** No CLI `main`, `if __name__ == "__main__"`, workflow, dispatch, status writer, host collector, `os.stat/open/readlink`, subprocess, network, root/sudo, UID switch, filesystem mutation, QEMU or real provider access. The module may only inspect **synthetic caller-supplied evidence**. Import-time activity must be limited to constants/types.
- **Untrusted evidence:** Caller supplied metadata is **not authenticated**. Even a valid record or test-only `InterpreterTrustPolicy` is **not** operator approval. Host use needs separately reviewed trusted-main collector and a distinct operator decision on the UID501/admin-owned Homebrew Python.
- **Fixed literals:** Repository `zhangyuz/ssh-over-mcp`; event `workflow_dispatch`; ref `refs/heads/main`; SHA exactly `[0-9a-f]{40}`; pinned `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, ref expression `${{ github.sha }}`, `persist-credentials=false`, `clean=true`, `fetch-depth=1`; dedicated `gha-e2e-orchestrator` UID/EUID `502`, `/Users/gha-e2e-orchestrator`, Darwin x86_64; candidate resolved CPython `/usr/local/Cellar/python@3.13/3.13.16/Frameworks/Python.framework/Versions/3.13/bin/python3.13`; private verification root `/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-uid502-verification-v1`.
- **Failure semantics:** Absent/malformed/unknown/incomplete/drifted evidence returns `CONTRACT_REFUSED`; no permissive defaults, no skip-as-pass. Violation messages are fixed code literals, deterministic, bounded (at most 32 distinct codes), sorted and contain **no raw caller path, token or process text**. `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` is never `UID502=PASS_CLEAN`, `BEHAVIOR_VERIFIED_EXPECTED_QUARANTINE` or permission to run a persistent-host process.
- **Review/merge:** Operator reviews **both** written spec and this plan before code. Then fresh implementation worktree from clean main, RED→GREEN for each task, immediate independent project-wide PR review on readiness (do not wait for CI), exact-final-head hosted CI, fresh clean review, merge and exact-main CI/old-path Level-3; only afterward clean owned implementation worktree. The docs-only planning worktree stays separate.

## File Map and Interfaces

| File | Single responsibility |
| --- | --- |
| `ops/live-e2e/uid502_preflight_contract.py` (new) | Frozen evidence data classes, fixed literals, pure validators and non-authoritative aggregate result |
| `tests/ops/test_uid502_preflight_contract.py` (new) | Import actual source via `importlib.util.spec_from_file_location` with temporary `sys.modules` registration for `dataclasses`; synthetic hostile-evidence tests and zero-I/O guard |
| `docs/development-plan.md` (edit) | Truthful current main/natively-passed baseline, PR #249–#251 closures, and new *inert-only* contract delivery |
| `docs/evidence/2026-10-14-adr19-uid502-preflight-contract.md` (new) | Feature evidence template, source SHA/test results, explicit unverified real UID502 state, no false release PASS |

**Locked public API** (types defined as `@dataclass(frozen=True, slots=True)`; all collection properties immutable `tuple`, no `dict`-typed mutable field):

- `RunIdentity(repository: str, event: str, ref: str, github_sha: str, inputs: tuple[tuple[str,str], ...])`.
- `CheckoutEvidence(head_sha: str, clean: bool, checkout_uses: str, checkout_ref: str, persist_credentials: bool, checkout_clean: bool, fetch_depth: int, credential_env_present: bool, credential_helper_present: bool, complete: bool)`.
- `RunnerIdentity(user: str, home: str, uid: int, euid: int, groups: tuple[str,...], platform: str, arch: str, complete: bool)`.
- `PathWitness(name: str, dev: int, ino: int, uid: int, gid: int, mode: int, acl_state: str, kind: str, target: str | None, writable_by_uid502: bool)`. `name` is an exact literal fixed component, never a user-chosen base path.
- `InterpreterInventory(resolved_path: str, sys_executable: str, version: tuple[int,int,int], arch: str, complete: bool, chain: tuple[PathWitness,...])`.
- `InterpreterTrustPolicy(approval_id: str, expected_path: str, version: tuple[int,int,int], allowed_owner_uid: int, allowed_owner_gid: int, approved_chain: tuple[str,...])`. A test-only injected policy is *not* cryptographically authenticated.
- `NamespaceEdge(name: str, original: tuple[int,int,int,int,int], current: tuple[int,int,int,int,int], acl_state: str, nofollow: bool)` (identity tuple is dev/ino/uid/gid/full mode).
- `NamespaceEvidence(verification_root: str, protected_root: str, native_temp_parent: str, edges: tuple[NamespaceEdge,...], complete: bool, foreign_entry: bool, quarantine_present: bool, alias_disjoint: bool)`.
- `ProviderInventory(marker_state: str, marker_chain_pinned: bool, qemu_state: str, qemu_count: int | None, protected_clean: bool, legacy_private_clean: bool, legacy_native_clean: bool, complete: bool)`.
- `ContractEvidence(run: RunIdentity, checkout: CheckoutEvidence, runner: RunnerIdentity, interpreter: InterpreterInventory, namespace: NamespaceEvidence, provider: ProviderInventory)`.
- `ContractResult(status: str, violations: tuple[str,...])`, where `status` is exactly one of `CONTRACT_REFUSED` or `CONTRACT_ELIGIBLE_FOR_HOST_PROBE`.
- Pure interfaces: `validate_run(run: RunIdentity, checkout: CheckoutEvidence, runner: RunnerIdentity) -> tuple[str,...]`; `validate_interpreter(inventory: InterpreterInventory, policy: InterpreterTrustPolicy | None) -> tuple[str,...]`; `validate_namespace(namespace: NamespaceEvidence) -> tuple[str,...]`; `validate_provider(provider: ProviderInventory) -> tuple[str,...]`; `assess(evidence: ContractEvidence, *, interpreter_policy: InterpreterTrustPolicy | None = None) -> ContractResult`.

All validation functions return only documented finite code literals; `assess` sorts/deduplicates code strings and returns fixed `EVIDENCE_INVALID` on malformed shapes rather than throwing a success-looking result. Never interpret arbitrary `approval_id` as authority.

## Review Focus

1. A green synthetic fixture or a user-supplied `approval_id` could be mistaken for real permission: `test_synthetic_eligible_result_never_authorizes_host` (Task 4).
2. Malformed checkout or additional `workflow_dispatch` inputs could create PR target selection: `test_untrusted_inputs_refuse` (Task 1).
3. Ambiguous pinned Python symlink/owner/ACL ancestry might silently trust operator-admin-owned artifacts: `test_interpreter_unapproved_by_default` and `test_interpreter_chain_tamper_refuses` (Task 2).
4. A detached/replaced APFS namespace parent or retained forensic quarantine could be reported clean from caller records: `test_namespace_identity_and_quarantine_refuse` (Task 3).
5. Empty but failed/truncated QEMU inventory or dangling marker could be called absent: `test_provider_incomplete_refuses` (Task 3).

---

### Task 1: Trusted run, checkout and runner contract

**Files:** Create `ops/live-e2e/uid502_preflight_contract.py`, `tests/ops/test_uid502_preflight_contract.py`.

**Interfaces:** Define `RunIdentity`, `CheckoutEvidence`, `RunnerIdentity` and `validate_run(...)` exactly as File Map specifies. Future tasks import these names; no host collection.

- [ ] **Step 1: Write failing tests.** In `test_uid502_preflight_contract.py`, load actual module using `spec_from_file_location` and explicit `sys.modules` registration; construct synthetic valid `RunIdentity("zhangyuz/ssh-over-mcp", "workflow_dispatch", "refs/heads/main", "a"*40, ())`, fully verified checkout with `head_sha="a"*40`, and fixed UID502 nonadmin runner. Assert `validate_run(...)=()`. Parameterize `test_untrusted_inputs_refuse` by one change at a time: repository/fork, `pull_request`, `workflow_run`, PR ref, unexpected input tuple, uppercase/nonhex/short SHA, changed HEAD, dirty checkout, wrong checkout SHA/ref/options, incomplete record, leaked credential env/helper; also wrong UID/euid/admin group/account/home/Darwin/arch and missing groups. Assert expected fixed code for each and no dynamic path/text in output. Reject booleans masquerading as integer UID/checkout depth.
- [ ] **Step 2: RED.** `"$R/.venv/bin/python" -m pytest -q tests/ops/test_uid502_preflight_contract.py -k 'trusted_run or untrusted_inputs' ` from new implementation worktree, `R` referring to main repo root; expected missing module/interfaces assertions FAIL (not environmental or collection failure).
- [ ] **Step 3: GREEN.** Implement frozen records, fixed allow-list, `validate_run` using `re.fullmatch("[0-9a-f]{40}", sha)`, exact ASCII literals, explicit `type(value) is int/bool` for critical primitives, no `os.environ` or GitHub API reads. Checkout `checkout_ref` is the exact literal `${{ github.sha }}`, and `inputs == ()`.
- [ ] **Step 4: Verify.** Run the same focused test selection; expected all PASS. Run `"$R/.venv/bin/python" -m ruff check ops/live-e2e/uid502_preflight_contract.py tests/ops/test_uid502_preflight_contract.py`.
- [ ] **Step 5: Commit.** `git add ops/live-e2e/uid502_preflight_contract.py tests/ops/test_uid502_preflight_contract.py && git commit -m "feat: add inert UID502 run and checkout contract"`. Update ignored implementation-worktree `progress.md`.

### Task 2: Interpreter provenance candidate and explicit trust refusal

**Files:** Modify same new module and same new test file.

**Interfaces:** Define `PathWitness`, `InterpreterInventory`, `InterpreterTrustPolicy` and `validate_interpreter(...)` from File Map.

- [ ] **Step 1: RED.** `test_interpreter_unapproved_by_default` passes synthetic complete valid CPython `(3,13,16)` inventory and `policy=None` and asserts exact `("INTERPRETER_TRUST_UNAPPROVED",)`. Define one explicit **test-only** policy for candidate `/usr/local/Cellar/python@3.13/3.13.16/Frameworks/Python.framework/Versions/3.13/bin/python3.13` with `allowed_owner_uid=501`, `allowed_owner_gid=80`, an exact finite literal component list, and mock approval ID clearly `TEST_ONLY_NOT_AUTHORITY`. `test_interpreter_chain_tamper_refuses` parametrizes changed reported executable/realpath/version/arch, missing/reordered/symlinked ancestor, changed original path, invalid dev/ino, unknown ACL, UID502 owner, group/world writable bit, `writable_by_uid502=True`, changed owner/group, empty policy ID. Assert nonempty fixed refusal code(s), not exception or pass. A fully consistent synthetic inventory plus explicit test policy returns `()` but **never host authority**.
- [ ] **Step 2: RED.** `"$R/.venv/bin/python" -m pytest -q tests/ops/test_uid502_preflight_contract.py -k interpreter`; expected missing types/functions failures.
- [ ] **Step 3: GREEN.** Enforce **exact ordered** literal chain, each full `stat.S_ISDIR` ancestor (regular executable leaf), positive dev/ino, pinned owner/group and `mode & 0o022 == 0`; reject any symlink or ACL uncertainty (only `acl_state="verified_safe"`), explicit `writable_by_uid502=False`, exact version/path and equality to `sys_executable`. Do not perform `stat`, `realpath` or permission probing: all are supplied test evidence. Never accept an implicit default policy, even if the candidate matches observed Homebrew ownership.
- [ ] **Step 4: GREEN verify.** Focused interpreter tests and Ruff PASS; existing Task 1 tests still pass.
- [ ] **Step 5: Commit.** `git add ops/live-e2e/uid502_preflight_contract.py tests/ops/test_uid502_preflight_contract.py && git commit -m "feat: refuse unapproved UID502 interpreter inventory"`. Update `progress.md`.

### Task 3: Fixed protected namespace and provider evidence contract

**Files:** Modify same new module and same new test file.

**Interfaces:** Define `NamespaceEdge`, `NamespaceEvidence`, `ProviderInventory`, `validate_namespace(...)`, `validate_provider(...)` from File Map.

- [ ] **Step 1: RED.** `test_namespace_identity_and_quarantine_refuse` builds finite synthetic held FD identity records for literal home → Library → Application Support → verification-only sibling. First check matching original/current dev/ino/uid/gid/full mode and `acl_state="verified_safe"`, `nofollow=True`, no foreign entry or quarantines. Then flip exactly one field: wrong root, root alias into protected/cache/private/native temp, symlink/alias flag, one missing/duplicate/reordered edge, mismatched original/current identity, foreign owner/mode/ACL, `complete=False`, `foreign_entry=True`, `quarantine_present=True`. Assert fixed denial codes. `test_provider_incomplete_refuses` requires `marker_state="absent_no_follow"`, pinned marker chain, QEMU `qemu_state="complete_empty"` and `qemu_count=0`, each protected/legacy clean true and complete; reject marker file or dangling leaf/parent, failed/truncated process inventory (even count zero), count unknown/positive, one legacy or protected scan uncertain/dirty.
- [ ] **Step 2: RED.** `"$R/.venv/bin/python" -m pytest -q tests/ops/test_uid502_preflight_contract.py -k 'namespace or provider'`; expected missing interfaces FAIL.
- [ ] **Step 3: GREEN.** Use exact fixed roots, exact ordered literal component names and no-follow identity comparisons; require mode `0o40700` for UID502 private directory evidence when represented as full `stat.S_IFDIR|0o700`, verified ACL, UID502 ownership; reject unexpected `native_temp_parent` or root overlap via strict literal separation and `alias_disjoint=True`. The future collector, **not this module**, owns real FD checks, APFS discovery, QEMU inventory and full legacy scanners. Do not add a worktree cleanup function, recovery fallback, or filesystem operations.
- [ ] **Step 4: GREEN verify.** Focused tests and Ruff; rerun Tasks 1–2 tests.
- [ ] **Step 5: Commit.** `git add ops/live-e2e/uid502_preflight_contract.py tests/ops/test_uid502_preflight_contract.py && git commit -m "feat: validate synthetic UID502 namespace and provider evidence"`. Update `progress.md`.

### Task 4: Safe aggregation, full adversarial regression and truthfully scoped documentation

**Files:** Modify same module/test; modify `docs/development-plan.md`; create `docs/evidence/2026-10-14-adr19-uid502-preflight-contract.md`.

**Interfaces:** Define `ContractEvidence`, `ContractResult` and `assess(evidence: ContractEvidence, *, interpreter_policy: InterpreterTrustPolicy | None = None) -> ContractResult` as File Map specifies, calling Task 1–3 pure validators. No other exported execution API.

- [ ] **Step 1: RED.** `test_synthetic_eligible_result_never_authorizes_host`: `assess(valid_fully_synthetic_record, interpreter_policy=test_only_policy)` returns exact status `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` with no violations; without policy exact `CONTRACT_REFUSED` and `INTERPRETER_TRUST_UNAPPROVED`. Assert result has **no** `dispatch`, `run`, `token`, `pass_clean` or `ready_to_dispatch` attribute. `test_single_field_mutation_refuses` takes valid snapshot and mutates each trust/security field independently, asserting refused. `test_malformed_and_secrets_do_not_leak` supplies malformed tuple/dict/wrong-type evidence and `token=SECRET_SENTINEL`/path strings; assert a finite fixed code list, no raw text in result/repr and bounded size. `test_no_host_io_or_execution_surface` checks module AST/bytecode imports and monkeypatches dangerous OS/subprocess/network entrypoints so `assess` cannot touch them. Ensure AST catches `__main__` CLI and workflow-related exports.
- [ ] **Step 2: RED.** `"$R/.venv/bin/python" -m pytest -q tests/ops/test_uid502_preflight_contract.py -k 'synthetic_eligible or single_field or malformed or no_host_io'`; missing assessment interface FAIL.
- [ ] **Step 3: GREEN.** Implement frozen aggregate records, deterministic `tuple(sorted(set(codes)))`, max 32 finite registered reason codes, `EVIDENCE_INVALID` refusal on malformed shapes. Do not echo exception messages or untrusted field content; never expose execution/approval methods. Update roadmap with exact prior [main CI #38648215422](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38648215422) and distinguish merged ADR0019 2A dormant code, this contract, and still-unverified real UID502 fixture/2B/3. The new evidence file captures exact future implementation commit, focused test command/results, previous gate closure and explicit non-authorization; do not fabricate CI or native execution outcomes.
- [ ] **Step 4: Verify actual suite and scope.** `"$R/.venv/bin/python" -m pytest -q tests/ops/test_uid502_preflight_contract.py tests/ops/test_native_marker_postrun_workflow.py tests/ops/test_protected_staging_dormant.py tests/ops/test_live_e2e_orchestrator_contract.py tests/ops/test_pr_ci_shadow.py` (if a named file is absent, inspect the actual `tests/ops` names and use only existing equivalent contract tests, recording the exact command). `"$R/.venv/bin/python" -m ruff check src tests ops/systemd ops/live-e2e`; `"$R/.venv/bin/python" -m compileall -q src tests ops/systemd ops/live-e2e`; `git diff --check`; doc relative-link check. Run hosted exact-head CI on PR. Mac-wide Linux-only `ctypes.prctl` tests do **not** count as Darwin-green; native runner is only trusted-main postmerge gate.
- [ ] **Step 5: Security diff audit and commit.** Assert changed tracked paths are **only** this module, test, roadmap, evidence; verify `git diff main -- .github/workflows ops/live-e2e/staging_owned_lifetime.py ops/live-e2e/protected_staging.py ops/live-e2e/verify_native_provider_absence.py scripts/run-live-local-e2e-orchestrator.py` empty and preexisting frozen-hash table unchanged. Commit `git add ops/live-e2e/uid502_preflight_contract.py tests/ops/test_uid502_preflight_contract.py docs/development-plan.md docs/evidence/2026-10-14-adr19-uid502-preflight-contract.md && git commit -m "feat: finish inert UID502 preflight contract and evidence"`.
- [ ] **Step 6: PR, review and merge gates.** Immediately push branch and open implementation PR; request independent whole-project security/code/docs review **before hosted CI completes**. Repeat review → scoped RED→GREEN fix → exact-new-HEAD CI → fresh final review until no blocking findings. Only then merge; check exact merge-main hosted+real no-network Level-3, including final marker-absence step. Update root and worktree `progress.md`; archive evidence, remove only owned implementation worktree/merged branch. Leave UID502 workflow/interpreter/operator trust decisions and real fixture matrix untouched.

## Execution Handoff

- **This is a draft for the operator's requested joint review with its spec.** Drafting it does not retroactively approve either document. **Do not create an implementation worktree, execute TDD, open the feature PR or dispatch a native runner before both are approved and an execution approach chosen.**
- Recommended method after approval: **subagent-driven** with independent review per task and whole-branch review, because incorrect trust-field semantics could make a later host collector unsafe; a native single-agent run is also acceptable with a separate final reviewer.
- On handoff: begin from the current exact clean `origin/main`, not the docs-planning branch; use `superpowers:using-git-worktrees` and `superpowers:test-driven-development`. Keep `progress.md` updated in every worktree and root for another agent to take over. No real protected staging/UID502 activation occurs through this plan.
