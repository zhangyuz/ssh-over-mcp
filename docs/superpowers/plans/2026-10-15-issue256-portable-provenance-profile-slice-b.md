# Issue 256 Slice B1 — Darwin-only Profile Router Implementation Plan (PROPOSED)

> **For agentic workers:** REQUIRED SUB-SKILL: use Superpowers subagent-driven-development or executing-plans. Implement only after operator approval; every task follows RED then GREEN and a review gate.

**Goal:** Deliver ONLY Slice B1, an explicit inert Darwin-only router that
preserves Gate A behavior. Do NOT claim an OS-neutral shared contract is
delivered or approve Linux execution.

**Architecture:** Keep original assess_provenance(evidence) Darwin
contract implementation unchanged. A frozen strict selector statically
delegates to the same loaded Gate A module. Do not extract or alter common
invariants in B1. A later independently approved **B2** MUST extract a typed
reusable OS-neutral contract plus behavior-preserving parity tests before
Linux Slice C may start. If extraction proves unsafe, re-review architecture;
never silently skip B2 or describe router-only as portable.

**Tech stack:** Python 3.13/3.14, frozen dataclasses, stdlib, pytest, Ruff.
**Spec:** [Issue 256 profile design](../specs/2026-10-15-issue256-cross-platform-provenance-profiles-design.md).
**Status:** Joint-review draft only; no code implementation authorized by this document.

## Immutable scope and baseline

- Main baseline [PR #255](https://github.com/zhangyuz/ssh-over-mcp/pull/255), f3a39b3594951defae4b31e6fdcf252b2503a507.
- Preserve existing Darwin assess_provenance API and all current test results; no synthetic result can be host authority.
- No .github/workflows, UID502 preflight, QEMU provider, protected staging, incident recovery, CI runner or physical fixture modifications.
- No OS/network/process/file I/O; no platform detection or user-chosen dynamic imports.
- Keep 64 nodes/entries, 128 edges, 64 paths, 1024 ASCII-byte paths, 64-byte approval labels, no NUL, no special mode bits and duplicate claimed identity refusal.
- Existing full-profile result PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED remains unauthenticated. Linux deliberately refuses until separately reviewed Slice C. **C requires B2 complete AND the operator-confirmed macOS full-feature release/launch milestone**; neither is yet established.
- macOS full-feature development, actual verified acceptance and launch are the delivery priority. Neither a green Ubuntu CI nor the existing legacy native Level-3 test is sufficient launch evidence. Future Gate B and real UID502/APFS acceptance must be separately authorized before being used to support a release claim; none is authorized by this plan.
- B1 never implements a portable core; B2 needs independent spec, plan,
  implementation approval and fresh security review. Do not change the
  existing Gate A implementation in B1, and no Linux profile may be
  registered as an early shortcut.

## Proposed exact interfaces and changed files

- Create ops/live-e2e/provenance_profile_router.py with frozen ProfileSelector(os_family: str, machine_arch: str, python_abi: str, role: str, profile_id: str); frozen ProfileResult(status: str, violations: tuple[str,...]); assess_profile_claim(selector: ProfileSelector, evidence: object) -> ProfileResult.
- Create tests/ops/test_provenance_profile_router.py, importing the router via a fixed trusted source path and reusing fictional Gate A fixtures for regression.
- DO NOT modify existing ops/live-e2e/interpreter_provenance_contract.py
  in B1. Its public assess_provenance(evidence) and result shapes are
  frozen; call via a fixed trusted adapter in the router.
- Update docs/development-plan.md and add docs/evidence/2026-10-15-issue256-portable-profile-router.md after implementing. No other tracked paths permitted.

**Selector schema (locked and exact, before any equality/hash/regex):**
ProfileSelector must be an exact dataclass identity (no subclass),
each field must have exact builtin type str, be nonempty ASCII and
satisfy both its maximum byte count AND exact allowlist membership:

| Field | Maximum bytes | Values permitted in B1 |
|---|---:|---|
| os_family | 6 | Darwin |
| machine_arch | 6 | x86_64 |
| python_abi | 18 | cpython-313-darwin |
| role | 19 | developer_ci; native_orchestrator; e2e_guest; managed_target |
| profile_id | 31 | darwin-x86_64-cpython313-v1 |

Role is descriptive only; no runtime host/guest identity authority.
Use exact case-sensitive equality only **after** types, ASCII and lengths
are validated. No prefix/alias/suffix/mixed-profile acceptance. Invalid
selector (including Linux or any unavailable Linux profile) returns
ProfileResult(status="PROVENANCE_REFUSED",
violations=("EVIDENCE_INVALID",)) without ever accessing the evidence
object or calling untrusted comparison/repr.

**Fixed trusted import/adapter:** use a package-private, single-identity
module imported from the fixed sibling source path
ops/live-e2e/interpreter_provenance_contract.py, relative ONLY to
the router's __file__ (never the workdir, profile_id, selector or
user input). Concretely, implement importlib.util.spec_from_file_location
with a fixed module name (e.g. _som_gate_a_darwin_v1), and the fixed
sibling module source path, with sys.modules registration before
exec_module for dataclass identity. Cache the one module instance
per interpreter, do not reload per call, and do not expose a source
path or loader override in the public API. Importing trusted code
itself may load the source file; the no-host-I/O restriction applies
to **processing untrusted provenance evidence** and does not permit
stat/FD/probe/open of claimed installed interpreter paths.

**Return parity:** for VALID selector and any evidence E, the
router MUST return ProfileResult with
(status, violations) == original fixed imported
Darwin module.assess_provenance(E).(status, violations).
Preserve exact refusal strings, order and bounded shape; a valid
selector never converts a legacy denial to a new generic denial,
and never changes positive UNATTESTED to a privileged state.
To build parity fixtures, use the router's **same fixed Gate A module
object** for constructing the frozen records, not a second
importlib-loaded copy: exact dataclass type identity otherwise
makes a valid record falsely refuse.

Cross-profile negative pairs are **declared mismatches only**:
Linux selector + declared Darwin evidence -> REFUSE at selector;
valid Darwin selector + evidence claiming platform Linux or
architecture arm64 / wrong cpython tag -> REFUSE via old Gate A;
mixed selector fields -> REFUSE at selector. A fully
fabricated, coherent Darwin selector AND Darwin package evidence
may still be UNATTESTED, even if undisclosed real package bytes
were ELF; B1 cannot inspect or discover real ELF versus Mach-O.
This belongs solely to separately approved Gate B.

## Review focus / failure examples

- Declared Linux-selector/Darwin-evidence or
  Darwin-selector/Linux-declared-evidence mismatches must REFUSE;
  coherent fictitious Darwin records, irrespective of unknown real
  ELF bytes, may only be UNATTESTED. No format byte inspection or
  real ELF/Mach-O authentication is possible in B1.
- Malicious selector subclass or nested objects with custom __eq__ and __repr__ must REFUSE without invoking custom methods.
- role=native_orchestrator, user-provided GitHub labels or role=e2e_guest must not authorize dispatch or admission.
- Missing, overlong, mis-cased, aliased or unknown IDs fail closed, without OS autodetection or fallback.
- A table-driven NEW-router parity matrix must assert
  (status, violations) identical to direct Gate A results on
  the **same module object** for both synthetic positives and all
  existing negative fixture classes: standalone/framework valid;
  coherent forged SHA still UNATTESTED; NUL with coherent rehash;
  setuid/setgid/sticky; duplicate dev+ino; mode/int over-budget;
  group-writable UID501, wrong arch/SOABI, malformed manifest;
  framework dylib outside bundle; duplicate/bad loader edges;
  over-budget search paths/labels; custom comparator objects.
  Merely rerunning old direct-call tests does NOT prove router parity.

## Task 1 — Frozen explicit profile selector

**Files:** new router and test module.
**Interface:** ProfileSelector fields above; assess_profile_claim returns a status string and fixed bounded refusal codes.

- [ ] Write test_darwin_explicit_selector_routes_inert_fixture
  using the router's single fixed Gate A module object for dataclasses,
  asserting status and violations identical to direct assess_provenance
  and only PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED for a fictional
  positive, with no trust token or dispatch.
- [ ] Run focused pytest; confirm real RED due to missing interface, not PYTHONPATH environment error.
- [ ] Implement exact frozen-record typing and every selector
  field's locked ASCII/byte/allowlist gate before comparison; import
  and cache exactly the trusted sibling Gate A module with the
  fixed spec_from_file_location identifier and sys.modules guard,
  statically wired Darwin-only; no runtime host detection.
- [ ] Run focused GREEN and Ruff; commit feat: introduce inert Darwin profile router; save command/results in ignored progress.md.

## Task 2 — Negative cross-profile and compatibility tests

**Files:** same router and test module, optionally existing Gate A only if strictly necessary.

- [ ] Add RED tests test_linux_profile_unavailable_refuses,
  test_profile_abi_mismatch_refuses,
  test_role_not_execution_authority,
  test_hostile_profile_type_refuses,
  test_unknown_profile_no_fallback and
  test_darwin_router_exact_status_violations_parity.
  Parametrize exact field allowlists, ASCII/length boundary,
  wrong class/subclass, and paired selector/evidence contradictions.
- [ ] Assert all Linux selectors REFUSE at selection, even with
  otherwise coherent evidence; unknown role, case variants,
  hostile equality/repr, 20-byte role, 19-byte python_abi,
  32-byte profile_id, overlong family/arch and missing fields
  refuse before touching attacker data. Test valid Darwin selector
  with evidence claiming Linux, arm64 and mismatched SOABI REFUSES.
  Include a **coherent forged Darwin-positive** fixture which must
  retain exact UNATTESTED status.
- [ ] Implement minimal fail-closed B1 routing. Run router parity
  table through the same Gate A module object, assert exact status
  AND violations for all fixture classes above. Also run unchanged
  original tests/ops/test_interpreter_provenance_contract.py and
  original UID502 inert checks on hosted-safe runner; Ruff PASS.
  Commit: test: preserve Gate A parity and reject Linux selector.
- [ ] Store RED/GREEN logs and exact SHA in progress.md; do not call host or native workflow.

## Task 3 — Documentation and review-ready code PR

**Files:** allowed router/test, optional proven-compatible source, roadmap and new evidence doc.

- [ ] RED-test that exports do not include dispatch, execute, approve, run, credential, stat or subprocess side effects; no imported OS/platform/network/process helpers.
- [ ] Implement the minimal no-authority module API and update docs to separate product/CI/orchestrator/guest roles. State explicitly Linux synthetic provenance is NOT YET implemented.
- [ ] Run host-independent test regression, Ruff/format, compileall, git diff --check, doc link and exact path allowlist; verify protected workflows, provider and staging remain unchanged.
- [ ] Push a separate code PR, request independent full-project/security review immediately, require exact-final-head CI and clean independent review before any operator-authorized merge.
- [ ] Retain evidence and local progress handoff in ignored worktree until safely archived.

## Separate future work requiring new approval

**B2 (mandatory before C):** separately review/approve a real
typed reusable OS-neutral invariant module and refactor Darwin to
consume it without changing any existing direct or router
(status, violations). B2 needs its own design/plan/PR,
adversarial TDD, exact-head hosted CI and independent review.
**Slice C (BLOCKED until BOTH B2 acceptance and macOS full-feature
launch):** only after the macOS release is actually live and the
operator confirms its completed release gates, and B2 is independently
reviewed/accepted, may a separately approved iteration design and
implement the Linux synthetic ELF/glibc-or-musl/ld.so/SOABI/dependency
profile and hostile-path tests. Linux Slice C must not consume delivery
capacity before that milestone. This is an explicit sequencing rule,
not a prediction or a claim that the Mac has already shipped. **Slice D:** distinct Linux
native E2E host/QEMU/identity/provider/isolation feasibility.
Neither B2, C nor D is authorized by this B1 proposal.
Gate B actual package bytes/host attestation, UID502 staging
and original nine-case physical Mac fixture remain UNVERIFIED.
