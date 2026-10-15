# ADR 0019 UID502 Interpreter Provenance — Gate A Implementation Plan (PROPOSED)

> **For agentic workers:** Upon operator approval of both design and plan,
> use Superpowers `executing-plans` or `subagent-driven-development`,
> with strict per-task RED→GREEN and independent whole-project final review.

**Status:** Joint operator review draft, **NOT approved for code, new
persistent-host workflow, interpreter installation, or native UID502 runs**.

**Goal:** Deliver a host-independent, pure, bounded provenance **schema**
for a not-yet-selected immutable CPython candidate. It never authenticates
real installation state, supply-chain approvals or executable authority.

**Architecture:** One inert typed module with immutable input records,
compositional schema validators and fixed non-authorizing result states.
Dedicated hosted-only adversarial tests; documentation truth sync.
**Spec:** [UID502 immutable interpreter provenance design](../specs/2026-10-14-adr19-uid502-immutable-interpreter-provenance-design.md).
**Baseline:** [Merged PR #253](https://github.com/zhangyuz/ssh-over-mcp/pull/253),
main `4d8449a8eec95eb37f33bd8c193cdaf7cf19be61`.

## Files and hard limits

- Create `ops/live-e2e/interpreter_provenance_contract.py`
  (**pure stdlib data + validation only**, no API calling the provider).
- Create `tests/ops/test_interpreter_provenance_contract.py`
  (import actual module by path, synthetic fixtures).
- Update only `docs/development-plan.md` and add a concise new
  `docs/evidence/2026-10-14-adr19-interpreter-provenance-contract.md`
  for concrete Gate A results. All other tracked paths are immutable for
  this implementation iteration, especially `.github/workflows/**`,
  `uid502_preflight_contract.py`, `staging_owned_lifetime.py`,
  `protected_staging.py`, original native 2A and recovery logic.
- No root, sudo, package install, chmod/chown, actual host I/O, spawning
  programs, network, GitHub API dispatch, Mac runner/test fixture, dependency
  lookup, dynamic import/exec, `os.stat`, `codesign` or symlink traversal.
  No operator/user-selected paths used for filesystem operations.
- All fields/collaborators *untrusted*: require exact dataclass identity,
  exact `type(...) is str/int/bool/tuple`, recursively bounded primitive
  tuples before equality/regex/sort/set. Never invoke custom comparisons or
  stringify attacker objects. Require absolute canonical lexical POSIX
  paths (reject `.`, `..`, duplicate `/`, NUL, relative/alias claims).
- Refusal is the default for missing trust policy, digest evidence,
  out-of-policy owner/mode/ACL/loader path, wrong runtime/version/arch,
  UID502-effective write, unexpected/DYLD/PYTHONPATH modifiers, incomplete
  transitive dependency graph or unbounded/unknown evidence.
- An `approval_ref` or caller `signature_verified=True` field is only
  text supplied by an attacker. Do not expose actual approval, signature
  verification, valid executable path, host execution, `PASS_CLEAN`, new
  trust grant or simulated operator signature.
- Proof states **only** `PROVENANCE_REFUSED` and
  `PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED`. Returning the latter from a
  fictional fixture does not change real UID502 contract's
  `INTERPRETER_TRUST_UNAPPROVED` outcome. Actual homebrew remains blocked.

## Locked proof inputs for code implementation (subject to review)

Define frozen-slot dataclasses, tuple-only immutable collections:

- `ArtifactClaim(package_sha256: str, python_version: tuple[int,int,int],
  platform: str, arch: str, approval_ref: str, complete: bool)`.
- `ProvenanceNode(node_id: str, path: str, kind: str, dev: int, ino: int,
  uid: int, gid: int, mode: int, acl_state: str, digest_sha256: str,
  writable_by_uid502: bool)`. Kinds exactly `directory`, `binary`,
  `framework`, `dylib`, `stdlib`, `extension`; directory digest
  may be a literal documented `NOT_APPLICABLE` only with complete identity
  evidence, file digests must be 64 lowercase hex. UID0:GID0 and no
  group/world write on all candidate and dependency nodes (not merely
  executable). Full POSIX type bits/kind must agree.
- `DependencyEdge(parent_id: str, child_id: str, loader_kind: str)`,
  where loader kind is one of a fixed allowlist, and every edge resolves to
  a unique present node; no unknown dynamic/injected paths.
- `RuntimeClaim(binary_node_id: str, sys_executable: str,
  module_search_paths: tuple[str,...], dyld_environment_clean: bool,
  python_environment_clean: bool, graph_complete: bool)`.
- `ProvenanceEvidence(artifact: ArtifactClaim, runtime: RuntimeClaim,
  nodes: tuple[ProvenanceNode,...], edges: tuple[DependencyEdge,...])`.
- `ProvenanceResult(status: str, violations: tuple[str,...])`.
- `assess_provenance(evidence: ProvenanceEvidence) -> ProvenanceResult`.

**Evidence limitations:** These do not confer independently verified
signature, source trust, installed dependency loader trace, graph
completeness or operator approval. A separately reviewed Gate B must
actually authenticate them. The fictional package digest is a
well-typed SHA string, not a measured actual artifact.

**Bounding:** Maximum 64 nodes, 128 edges, 1024 chars/path, 32 distinct
fixed refusal codes. Deny duplicates, disconnected/unreachable vertices,
cycles that thwart a finite closure, missing binary/framework/stdlib
required roles or ambiguous resolution; no `repr`/exception content from
caller. Any incompatible exact-version/arch combination or missing
positive completeness fields refuses.

## Task 1 — Evidence types and hostile-field rejection

**Files:** new module and tests only.

- [ ] **RED**: test a fictional, root-owned, all-immutable graph with
  exact pinned Python 3.13.16 / Darwin x86_64, positive complete module
  paths and finite closure; expected schema-consistent-unattested only.
  Define `test_unknown_type_refuses_without_rich_comparison` for hostile
  objects with observable/raising `__eq__`, across every string field,
  nested node/edge tuple, module paths and `approval_ref`. Assert zero
  callback invocations and fixed refusal. A missing/unknown record refuses.
- [ ] Verify genuine RED against missing module/types, not a Python
  environment failure. Use `PYTHONPATH=$PWD/src <repo-venv-python> -m
  pytest -q tests/ops/test_interpreter_provenance_contract.py`.
- [ ] **GREEN:** smallest typed immutable data structures, finite explicit
  type validation before comparisons. Favor pure explicit checks; no host
  imports. Run focused GREEN and Ruff, commit
  `feat: add inert interpreter provenance evidence records`.
- [ ] Update ignored worktree `progress.md` after RED/GREEN with commands
  and exact result; keep Task 1 commit recoverable.

## Task 2 — Fail-closed origin / dependency closure

**Files:** same module and test.

- [ ] **RED:** missing package digest, wrong version/arch, mutable UID501
  Homebrew `/usr/local/Cellar` group-write, UID502 ownership/writeable
  witness, uncertain ACL, mode/kind mismatch, bad/no absolute path,
  duplicate/path alias, unexpected DYLD/Python runtime environment,
  absent stdlib/framework/loader dependency, disconnected node, duplicate
  ID, cycle/unknown target, false `graph_complete`, excessive vertices/
  edges/path length all refuse. Ensure no dynamic caller comparators.
- [ ] **GREEN:** deterministic finite graph-shape checks and positive
  closure; fixed sorted reason-code results with maximum 32 codes;
  `PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED` only for fictional valid
  static evidence. **Never** accept real observed Homebrew, authorize an
  executable or infer signatures from caller assertions.
- [ ] Rerun Tasks 1–2, Ruff, commit
  `feat: fail closed on mutable interpreter dependency provenance`.

## Task 3 — Non-authority regression, evidence and PR

**Files:** same module/test + permitted docs.

- [ ] **RED:** AST or controlled-import tests prove zero `os`, network,
  subprocess, `codesign`, environment or runner interactions and no
  `run`/`dispatch`/approval/host-token exports. Negative checks
  reject forged `approval_ref` and “signature valid” claims as an
  authorization path. Positive state stays explicitly **unattested**.
- [ ] **GREEN:** close non-authority API, add evidence/roadmap distinction:
  Gate A synthetic schema only; Gate B not implemented; *real* trusted
  interpreter source **UNVERIFIED/UNAPPROVED**; nine-row UID502 matrix
  unexecuted; no protected placement and no manual evidence deletion.
- [ ] Verify entire applicable pytest suite on hosted-safe runner (do not
  count Darwin-host-only Linux `prctl` tests as macOS-green), Ruff,
  compileall, `git diff --check`, relative links and exact changed-path
  allowlist. Compare forbidden workflow/orchestrator/marker sources
  against main to ensure no change.
- [ ] Commit source, tests, roadmap and evidence, push and create a
  **separate implementation PR**. Request independent code/security/docs
  review immediately while exact-head hosted CI runs. Fix findings
  RED→GREEN, obtain new exact SHA CI and independent clean final review
  before merge. After merge check trusted-main native Level-3 and clean
  owned worktree/branches without deleting retained host evidence.

## Required separate future approval

Do **not** install a Python runtime, select an unverified root path,
modify host permissions, run a UID502 test, create a new workflow or
dispatch from this plan. Gate B (actual operator-chosen package, offline
supply-chain and signature verification, macOS/dylib feasibility, immutable
install, trusted-main attestation, original-code nine-row test) **requires a
new design, implementation plan, operator security approval and postmerge
trusted-main evidence**. Merely approving Gate A does not approve Gate B.
