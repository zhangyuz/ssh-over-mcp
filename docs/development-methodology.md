# Development methodology

This document defines the normative development method for `ssh-over-mcp`.

## Core principle

> **小步快跑，持续迭代，关注质量、安全、一致性。**

In English: **ship small, iterate continuously, and keep quality, security, and consistency as first-class constraints.**

These are operating rules, not slogans. A change is not complete merely because code exists or a happy-path test passes.

## 1. Small, independently reviewable slices

Changes MUST be split into the smallest slices that can be independently reviewed, tested, reverted, and understood.

A slice SHOULD:
- add or change one bounded capability;
- have explicit security invariants;
- have a focused RED → GREEN proof;
- produce its own review and verification evidence;
- avoid unrelated cleanup or opportunistic refactors.

Large architectural work MUST be decomposed into design-approved slices before implementation.

## 2. Continuous iteration

Every slice MUST produce new evidence and reduce uncertainty.

The default loop is:

```text
understand current invariants
→ design/spec when architectural
→ isolated worktree
→ clean baseline
→ RED
→ minimal GREEN
→ targeted verification
→ security/review
→ full regression
→ live/E2E when the touched boundary requires it
→ commit
→ exact-head PR CI
→ fresh final review
→ merge
→ exact merge-main CI
→ cleanup
→ next small slice
```

A review finding SHOULD be converted immediately into a focused regression and the smallest fix. Do not accumulate a batch of known defects for a later cleanup phase unless the issue is explicitly deferred and does not violate the current completion gate.
## 3. Quality rules

Before changing behavior, the worker MUST establish a clean baseline on the relevant supported platform.

Behavior-changing work MUST use test-first development:
1. write a test that demonstrates the missing or incorrect behavior;
2. run it and confirm it fails for the intended reason;
3. make the smallest production change that should satisfy it;
4. run the focused test to GREEN;
5. run the relevant regression layers.

A RED test that unexpectedly passes is evidence that the test does not prove the intended change. Stop and investigate before changing production code.

Harness/tooling/platform failures MUST be distinguished from product failures. A harness failure MAY justify a recorded ruling; it MUST NOT be used as a reason to weaken a product invariant.

Verification MUST be fresh for the exact code being claimed complete. “It passed earlier” or “it should work” is not completion evidence.

## 4. Security rules

Security invariants MUST NOT be weakened to make a test pass.

Security-sensitive review MUST actively search for:
- authority widening;
- secret exposure or retention;
- identity confusion;
- request-controlled privilege/profile selection;
- fail-open behavior;
- retry/replay abuse;
- stale state;
- TOCTOU races;
- network/public exposure;
- cross-profile escalation;
- destructive mutation ambiguity;
- uncertain durability incorrectly converted into success;
- bypasses between central policy, host-local policy, OS policy, approvals, and audit.

Reject as early as possible, fail closed, and avoid exposing lower-level secret/internal detail.

A mutation that may have committed but whose durability/result is uncertain MUST preserve explicit uncertainty semantics. It MUST NOT be treated as a safe automatic retry.

## 5. Consistency rules

Code, tests, security documents, architecture documents, roadmap status, CI evidence, and cleanup state MUST agree.

When they differ, stop and resolve the discrepancy before continuing.

Exact revisions matter:
- PR evidence MUST correspond to the exact reviewed PR head SHA;
- after merge, merge-main evidence MUST correspond to the exact main SHA;
- closure documents MUST reflect the actual CI, review, and cleanup state.

Platform-specific rulings that materially affect future work MUST be written down. Repeated or architectural rulings SHOULD be promoted into the source-of-truth documentation or an ADR.

## 6. Test ladder

The project uses progressively stronger evidence:

```text
unit
→ static contract
→ integration
→ adversarial/security
→ live platform probe
→ full local E2E
→ exact-head CI
```

Not every change needs every level. A change MUST run the strongest level required by the boundary it touches.

### Level 1 — ordinary PR validation

Every behavior-changing PR runs the ordinary self-hosted validation suite:
- unit/static/integration/security tests;
- full pytest;
- supported Python versions;
- lint/compile checks.

### Level 2 — deployment/container validation

Changes to image, Compose, container identity, mounts, secrets, or networking MUST additionally run the applicable live deployment probes on the authorized Docker host.

### Level 3 — full Linux E2E

Changes affecting SSH transport, policy/authorization, approvals/Ledger, credentials, host-agent, containment, filesystem mutation semantics, audit, workload identity, OS hardening, egress controls, SSH CA, secret-manager integration, or the E2E fixture itself MUST have exact-head full E2E evidence before merge.

Phase closure and release-candidate work MUST run full E2E regardless of which files changed.
## 7. Full E2E trust model

Full E2E MUST prefer real kernel/service evidence over mocks when feasible.

The ordinary PR runner MUST NOT be made privileged merely to run E2E. In particular, do not add a Docker socket, broad sudo, host PID namespace, writable cgroup root, or equivalent escape surface to the normal runner.

High-privilege fixture setup belongs to operator-owned infrastructure outside the checkout:
- root-owned helper;
- root-owned configuration;
- narrowly scoped sudo entry;
- exact helper hash/integrity checks;
- exact trusted commit input;
- disposable fixture resources.

Checked-out repository code may request the fixed fixture operation but MUST NOT gain generic root authority.

## 8. Review discipline

Review happens repeatedly, not only at the end.

At minimum:
- review after each meaningful GREEN;
- review the complete slice before PR;
- perform a fresh final review after exact PR-head verification;
- perform post-merge consistency verification when closure state depends on external CI/cleanup evidence.

Use an independent reviewer/subagent when available. If unavailable, explicitly record fresh author self-review rather than implying independent review occurred.

Critical or Important findings block merge. Minor findings may be deferred only when they do not violate the current Definition of Done and the deferral is recorded.

## 9. Evidence before completion

Completion claims MUST include current evidence appropriate to the slice:
- exact tests/probes;
- exact SHA when relevant;
- exact CI run for PR head;
- exact CI run for merge-main;
- explicit review result;
- cleanup result.

Do not call a phase closed while external gates remain pending.

## 10. Cleanup is part of Definition of Done

Merged/superseded implementation branches and worktrees MUST be audited and cleaned after authoritative merge-main verification.

Disposable live-test resources MUST also be cleaned:
- processes;
- containers;
- cgroups;
- sockets;
- keys/tokens;
- temporary databases;
- fixture identities/data when the fixture contract requires disposal.

If cleanup fails, the live/E2E probe fails even when business assertions passed.

Unknown stale privileged fixture state MUST cause the next run to fail closed rather than silently normalize or overwrite it.
## 11. Rulings and deviations

When execution reveals a platform/tooling/security trade-off not anticipated by the plan, record a **Ruling** containing:
- the decision;
- why it is safe enough for the current slice;
- the cost if the decision is wrong;
- what evidence mitigates that cost.

A ruling MUST NOT silently weaken an approved security invariant.

Plan deviations that materially change architecture, authority, trust boundaries, or acceptance criteria require renewed design/ADR review before implementation continues.

## 12. Self-hosted CI policy

Normal CI remains self-hosted only using the repository's configured Linux x86 runner labels.

Do not introduce a GitHub-hosted fallback merely to make CI convenient.

Do not add a Docker socket or privileged runtime to ordinary CI. Specialized live/E2E workflows use their own reviewed trust model.

## 13. Definition of Done checklist

A slice is done only when all applicable items are true:
- intended behavior is defined;
- baseline was clean;
- RED failed for the intended reason;
- minimal GREEN exists;
- targeted tests pass;
- relevant security/adversarial tests pass;
- full regression passes;
- required live/E2E evidence passes;
- docs and roadmap are consistent with code;
- exact PR-head CI passes;
- fresh final review has no blocking findings;
- merge-main exact-head CI passes;
- branches/worktrees and disposable resources are cleaned;
- material rulings are preserved.

Then begin the next small slice.
