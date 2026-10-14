# ADR 0019 Trusted-Main UID 502 Postmerge Fixture Verification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Each checkbox is an individually verifiable RED→GREEN action.

**Status:** Proposal for separate operator and independent security review; not an authorization to run additional work on the persistent Mac.

**Goal:** Close the explicitly deferred UID 502/APFS acceptance gap for squash-merged PR #249 (main SHA `448409231d20aca5a5db5a91aa64edf250b64043`) without ever executing unmerged PR-head code on a persistent macOS self-hosted runner.

**Architecture:** Add a manually dispatched, **trusted-main-only** verification workflow running as the existing non-admin UID 502 self-hosted orchestrator. The workflow checks out its **own exact trusted-main SHA**, confirms dedicated identity, APFS filesystem and absence of conflicting provider/QEMU state, and runs an isolated, bounded, fixture-only verification harness. All writes are limited to a newly exclusively created test root outside production marker/staging namespaces, with descriptor-relative cleanup and explicit absence proof. Review and merge the workflow/harness separately **before dispatching** from trusted main; no PR-target input, automatic trigger or runtime activation.

**Tech Stack:** GitHub Actions `workflow_dispatch`; existing pinned `actions/checkout`; native Intel Darwin APFS + system `python3` standard library; pytest only if a fixed, pre-existing offline environment is established and verified; existing ADR0019 fixture primitives and APFS bindings.

**Spec:** [ADR0019](../../decisions/0019-protected-native-e2e-staging.md), [protected namespace design](../specs/2026-10-13-protected-native-e2e-staging-design.md), [reviewed Slice 2A plan](2026-10-14-adr19-owned-protected-workspace-lifetime.md), [development methodology](../../development-methodology.md).

## Global Constraints

- Only `workflow_dispatch` on `refs/heads/main` from exactly `zhangyuz/ssh-over-mcp`. Must check `GITHUB_SHA` against the Git checkout of that same trusted main run; **no candidate SHA input**, PR event, `workflow_run` trigger or dynamic ref.
- Only existing `[self-hosted, macOS, X64, ssh-over-mcp-e2e-orchestrator]` runner, **real and effective UID 502**, non-admin, `uname -s=Darwin`, `uname -m=x86_64`; read-only `contents: read` permissions. Fail closed if any mismatch.
- Same `concurrency: group: live-local-e2e; cancel-in-progress: false` as the existing native Level-3 workflow to serialize access. Do not add a sudo, Docker socket, service account switch, external package download, long-lived credential or additional GitHub check/status write.
- Verify provider marker absence and no conflicting QEMU process before/after. Don't clear/recreate/recover any unknown marker or foreign directory. Keep incident-pinned legacy acceptance unchanged.
- Only on test-owned **disposable APFS** root with known exclusive O_EXCL claim evidence; no production staging path/active-run marker write, no arbitrary untrusted `path`/UID selector, no arbitrary cleanup. Explicitly verify root/ancestor FD identity and no-follow ownership throughout; failure retains evidence, does not invoke broad `rm -rf`.
- Explicit **single-writer** fixture ownership is required; POSIX check-to-unlink is not atomic against an adversarial same-UID process.
- Run the **already-merged trusted main** fixture code, not unmerged PR HEAD. The existing `test_protected_staging_lifetime_native.py` only repeats one smoke for UID502; verification must add the planned real-OS deny/allow ACL, held-edge swap/refusal, nested-symlink, interrupted deletion, close/FD leakage cases. Do not mark missing cases passed.
- Fixed set of sandbox tests, bounded time, offline dependencies only. If `pytest` is absent on UID502, do not dynamically `pip install`; implement a separately reviewed stdlib-only harness or report blocker.
- Existing production `create_owned_workspace()`/live `dispose()` remain unconditionally `unbound`. No protected staging activation, original live marker handoff, QEMU receipt issuer or automatic PR-native admission.
- Record exact trusted-main SHA, workflow run/job IDs, UID/eUID/GIDs, APFS device/mount, fixture cleanup and original provider-state absence. Native truth requires real observed logs, not green GitHub status alone.
- Update ignored root and owned worktree `progress.md`. **Request independent review immediately when code/self-review finish; CI may run in parallel**. Merge only after external review and exact-head CI; then dispatch and inspect trusted-main native evidence.

## Review Focus

1. Host executes untrusted PR code or attacker-supplied ref → reject, tests `test_native_uid502_workflow_never_checks_out_pr_head`.
2. Workflow operates with UID501/admin/wrong platform → fail before any fixture mkdir, test `test_native_uid502_identity_gate`.
3. Provider marker exists or active QEMU / unknown state → refuse without cleanup, test `test_native_uid502_provider_busy_gate`.
4. Fixture root/ancestor exchanged or symlink inserted mid-test → preserve foreign targets, test `test_native_uid502_swap_preserves_foreign`.
5. Harness fails during ACL or unlink, or test environment lacks dependencies → retain original evidence and refuse rather than silently skip, test `test_native_uid502_failure_preserves_evidence`.

---

## Task 1 — Workflow trust boundary and preflight (code+tests)

**Files:** New `.github/workflows/adr19-uid502-fixture.yml`; new `tests/ops/test_uid502_fixture_workflow.py`.

- [ ] RED: construct workflow contract tests for trigger=manual, main-only/ref/repo, checkout pinned to trusted GitHub SHA, `contents: read`, dedicated runner labels, `concurrency: live-local-e2e`, no sudo/network install and no PR-controlled inputs.
- [ ] GREEN: create workflow with strict preflight and fail-closed provider marker/QEMU absence checks before any fixture invocation; explicitly prevent partial-creation recovery.
- [ ] Run focused workflow contract tests; commit; record security boundary in SDD progress.

## Task 2 — Isolated fixture harness + host-real ACL/interruption matrix

**Files:** New `ops/live-e2e/verify_uid502_fixture.py` (or equivalent existing-trusted-main harness); new `tests/ops/test_uid502_fixture_harness.py`; extend `tests/ops/test_protected_staging_lifetime_native.py` only for real required cases.

- [ ] RED: UID/eUID mismatch, non-APFS, existing provider marker/QEMU, inherited ACL, parent inode swap, symlink outside root, 140+ entries, nested substitutions, failed unlink/close and absent offline dependency must fail closed and not delete external fixtures.
- [ ] GREEN: static trusted-main stdlib-only test harness, bounded deterministic work performed only in exclusively created, FD-pinned disposable test root, no dynamic code import from PR/head ref, no credential use. Explicit cleanup of test-owned entries only with post-run absence verification.
- [ ] Explicitly separate *one never-launched fixture* from real guest QEMU success; permanent live `unbound` remains unchanged. Commit RED→GREEN evidence.

## Task 3 — Documentation + immediate security review

**Files:** New `docs/evidence/2026-10-14-adr19-uid502-native-acceptance.md`; update `docs/development-plan.md`.

- [ ] Document provisional verification path and unresolved actual host acceptance. Do not claim UID502 PASS before a successful real workflow run.
- [ ] Run focused Python + workflow contract tests, Ruff, compileall, git diff --check, and unchanged old orchestrator/recovery/incident boundaries.
- [ ] Push narrow **Ready for review** PR and request independent project-wide security review **immediately after code/self-review, before hosted CI must finish**.
- [ ] Fix reviewer Important/Critical using new RED→GREEN and verify exact-final-HEAD hosted CI before merging. Never run changed candidate workflow on persistent Mac before merged main.

## Task 4 — Authorized trusted-main UID502 run + release evidence

- [ ] Once Task 3's PR is independently reviewed, exact-head green and merged, dispatch **only** the newly merged trusted-main workflow manually while native Level-3 is not running.
- [ ] Verify actual runner UID/eUID502 + non-admin, Darwin Intel, APFS, provider-state absence, source equals trusted-main `GITHUB_SHA`, all planned ACL/edge/interruption tests PASS, no foreign deletion, fixture cleanup absence and provider marker still absent.
- [ ] If any test skips/fails, retain UID502=UNVERIFIED, do not treat the workflow status as acceptance or silently rerun destructive cleanup.
- [ ] Record job logs/IDs/main SHA in reviewed evidence; keep production protected activation blocked until separate ADR0019 Slice 2B and Slice 3 authorizations.

## Decision gate

This proposal is a **new trusted host test-execution surface**. It needs independent review of its workflow and test harness design before any real runner code path is added. Current operator direction authorizes PR #249's dormant-code merge **and subsequent verification**, but does not authorize weakening persistent-host trust boundaries or impersonating UID502 from the UID501 desktop shell. Native inline TDD execution is recommended **after this plan is approved**.
