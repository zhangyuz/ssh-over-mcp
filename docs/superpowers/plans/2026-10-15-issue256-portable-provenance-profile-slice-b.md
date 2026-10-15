# Issue 256 Slice B — Portable Provenance Router Implementation Plan (PROPOSED)

> **For agentic workers:** REQUIRED SUB-SKILL: use Superpowers subagent-driven-development or executing-plans. Implement only after operator approval; every task follows RED then GREEN and a review gate.

**Goal:** Add a pure, explicit, fail-closed Darwin profile router without adding Linux execution or changing Gate A behavior.

**Architecture:** Keep the existing assess_provenance(evidence) Darwin contract behavior unchanged and delegate only via a static allowlisted selector. Do not register Linux yet. If shared validation extraction is attempted, it must preserve every existing Darwin positive and negative test.

**Tech stack:** Python 3.13/3.14, frozen dataclasses, stdlib, pytest, Ruff.
**Spec:** [Issue 256 profile design](../specs/2026-10-15-issue256-cross-platform-provenance-profiles-design.md).
**Status:** Joint-review draft only; no code implementation authorized by this document.

## Immutable scope and baseline

- Main baseline [PR #255](https://github.com/zhangyuz/ssh-over-mcp/pull/255), f3a39b3594951defae4b31e6fdcf252b2503a507.
- Preserve existing Darwin assess_provenance API and all current test results; no synthetic result can be host authority.
- No .github/workflows, UID502 preflight, QEMU provider, protected staging, incident recovery, CI runner or physical fixture modifications.
- No OS/network/process/file I/O; no platform detection or user-chosen dynamic imports.
- Keep 64 nodes/entries, 128 edges, 64 paths, 1024 ASCII-byte paths, 64-byte approval labels, no NUL, no special mode bits and duplicate claimed identity refusal.
- Existing full-profile result PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED remains unauthenticated. Linux deliberately refuses until separately reviewed Slice C.

## Proposed exact interfaces and changed files

- Create ops/live-e2e/provenance_profile_router.py with frozen ProfileSelector(os_family: str, machine_arch: str, python_abi: str, role: str, profile_id: str); frozen ProfileResult(status: str, violations: tuple[str,...]); assess_profile_claim(selector: ProfileSelector, evidence: object) -> ProfileResult.
- Create tests/ops/test_provenance_profile_router.py, importing the router via a fixed trusted source path and reusing fictional Gate A fixtures for regression.
- Modify existing ops/live-e2e/interpreter_provenance_contract.py only if a necessary static adapter needs it. Freeze return shapes and negative tests.
- Update docs/development-plan.md and add docs/evidence/2026-10-15-issue256-portable-profile-router.md after implementing. No other tracked paths permitted.

Selector allowlist in Slice B: profile_id darwin-x86_64-cpython313-v1, os_family Darwin, machine_arch x86_64, python_abi cpython-313-darwin; role exactly one of developer_ci, native_orchestrator, e2e_guest, managed_target. A profile_id linux-x86_64-cpython313-v1 or a Linux family selector REFUSES even with otherwise plausible data.

## Review focus / failure examples

- A Linux/ELF claim misrepresented as Darwin must REFUSE; do not inspect ELF or reinterpret signatures.
- Malicious selector subclass or nested objects with custom __eq__ and __repr__ must REFUSE without invoking custom methods.
- role=native_orchestrator, user-provided GitHub labels or role=e2e_guest must not authorize dispatch or admission.
- Missing, overlong, mis-cased, aliased or unknown IDs fail closed, without OS autodetection or fallback.
- Existing Darwin tests, NUL rejection, privilege bits, ABI/graph/identity and bounded input all remain behavior-identical on Ubuntu CI.

## Task 1 — Frozen explicit profile selector

**Files:** new router and test module.
**Interface:** ProfileSelector fields above; assess_profile_claim returns a status string and fixed bounded refusal codes.

- [ ] Write test_darwin_explicit_selector_routes_inert_fixture, with a fictional valid Gate A record; assert only PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED, no trust token or dispatch.
- [ ] Run focused pytest; confirm real RED due to missing interface, not PYTHONPATH environment error.
- [ ] Implement exact frozen record typing and allowlisted values, fixed-size early validation, one statically wired Darwin adapter, no runtime host detection.
- [ ] Run focused GREEN and Ruff; commit feat: introduce inert Darwin profile router; save command/results in ignored progress.md.

## Task 2 — Negative cross-profile and compatibility tests

**Files:** same router and test module, optionally existing Gate A only if strictly necessary.

- [ ] Add RED tests test_linux_profile_unavailable_refuses, test_profile_abi_mismatch_refuses, test_role_not_execution_authority, test_hostile_profile_type_refuses, test_unknown_profile_no_fallback.
- [ ] Assert all Linux/ELF-profile selectors REFUSE, even when caller supplies coherent-looking evidence; make unknown role, case variants, hostile equality/repr traps and overlong IDs refuse without callback invocation.
- [ ] Implement minimal fail-closed fixed-code behavior; run GREEN, original entire tests/ops/test_interpreter_provenance_contract.py unchanged, plus UID502 original inert checks; Ruff PASS; commit test: preserve Darwin-only routing and Linux fail closed.
- [ ] Store RED/GREEN logs and exact SHA in progress.md; do not call host or native workflow.

## Task 3 — Documentation and review-ready code PR

**Files:** allowed router/test, optional proven-compatible source, roadmap and new evidence doc.

- [ ] RED-test that exports do not include dispatch, execute, approve, run, credential, stat or subprocess side effects; no imported OS/platform/network/process helpers.
- [ ] Implement the minimal no-authority module API and update docs to separate product/CI/orchestrator/guest roles. State explicitly Linux synthetic provenance is NOT YET implemented.
- [ ] Run host-independent test regression, Ruff/format, compileall, git diff --check, doc link and exact path allowlist; verify protected workflows, provider and staging remain unchanged.
- [ ] Push a separate code PR, request independent full-project/security review immediately, require exact-final-head CI and clean independent review before any operator-authorized merge.
- [ ] Retain evidence and local progress handoff in ignored worktree until safely archived.

## Separate future work requiring new approval

Slice C: specify a genuine Linux synthetic ELF/glibc-or-musl/ld.so/SOABI/dependency schema and hostile-path tests. Slice D: Linux **native** E2E host/QEMU/identity/provider/isolation lifecycle feasibility. Neither is implemented or authorized by this plan. Gate B actual package attestation, UID502 protected staging and original nine-case Mac fixture remain UNVERIFIED.
