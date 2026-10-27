# Development methodology

This document defines the normative development method for `ssh-over-mcp`.

## Core principle

> **从第一性原理出发：明确用户真正需要的能力，分清产品需求与实现假设；小步快跑，持续迭代，关注质量、安全、一致性。**

In English: **start from the user goal, separate functional requirements and security boundaries from inherited implementation assumptions, then ship small with quality, security and consistency.**

These are operating rules, not slogans. A change is not complete merely because code exists or a happy-path test passes.

### First-principles decision test (required for architecture, P0 gates and MVP scope)

Before adopting a requirement, design or release blocker, write down these answers in the design/ADR or PR:

1. **User outcome:** what real user/operator action must work, and on which actual deployment topology? Separate the complete product MVP from a narrower pilot.
2. **Necessary constraints:** which properties would cause real loss of security, correctness or usability if absent? Preserve authentication, authorization, key trust, auditing, data isolation and fail-closed uncertainty; do not waive them merely to gain a green test.
3. **Inherited assumptions:** which requirements came from an earlier test fixture, tooling limitation or rejected design rather than the user outcome? Ask whether the product works without them. Example: a no-NIC VM isolates *untrusted tests*, whereas a remotely accessible MCP→SSH service needs a controlled network; an offline Docker package supply chain is not automatically a product P0.
4. **Simplest sufficient option:** prefer standard, well-supported platform mechanisms and existing tested code. State the smallest *real positive and negative* evidence needed; avoid bespoke subsystems, speculative gates and redundant CI.
5. **Decision/evidence:** explicitly record what is retained, changed, deferred, who has authorized which runtime side effects, and what remains unproven. Never relabel a test-only signed image, an author review or a skipped job as production acceptance.

**Reevaluate P0/P1 classification whenever the product goal or topology changes.** A previously sensible test safeguard is not automatically a release requirement. Conversely, changing an architecture goal does not authorize touching a shared host, installing packages, deploying credentials, bypassing a blocked tool action, or weakening a distinct security invariant. Use a short ADR and a bounded executable pilot rather than endlessly elaborating the old plan.

## 1. One independently verifiable user/operator function per feature PR

Each **feature PR MUST deliver one bounded, independently usable and reproducibly verifiable user/operator capability**. Split by meaningful feature and trust/authority boundary, **not** by a single document, helper, checklist item, test assertion, or mechanical micro-commit. Keep RED → GREEN commits and narrowly scoped modules inside **the same feature PR**.

The feature PR MUST contain, when applicable:
- a real user/operator entrypoint or observable workflow with explicit success **and refusal/error semantics**;
- actual product/operation code, test-first GREEN, adversarial/negative security tests and independent runnable acceptance evidence;
- a usage/runbook example and code/test/roadmap/security documentation consistent with what was actually demonstrated;
- a coherent security boundary, without unrelated refactors, invented approvals or out-of-scope host actions.

**Open a Draft feature PR early** for architecture/design, written plan and governing path-scope review gates **inside that same PR**. Record reviewer findings, corrections and explicit operator approvals as PR comments. The plan/spec alone, or a refusal-only mock where a real positive proof is required, does not qualify the PR as Ready for Review. Mark the **same** PR Ready only after the complete executable feature and required acceptance evidence exist.

Architectural work retains its independent written-spec and implementation-plan approvals; cross-boundary security decisions (trusted signer/root/verifier, real package/host/privilege use, UID502, and releases) remain separate operator gates. Approval of a PR design or a local unit test cannot grant an unrelated runtime authority.

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
→ open one Draft feature PR with in-PR design/plan/security gates
→ implement code+tests+runbook inside the same PR after required approvals
→ independently demonstrate the actual user/operator positive and refusal paths
→ request independent full-feature review (may run concurrently with exact-head CI)
→ mark that PR Ready only after feature/evidence/review requirements are met
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

Every behavior-changing PR runs the complete ordinary validation suite on
GitHub-hosted Ubuntu 26.04 x86 runners, as defined by
[ADR 0013](decisions/0013-hosted-ci-self-hosted-e2e.md):
- unit/static/integration/security tests;
- complete pytest collection, distributed across disjoint exhaustive partitions;
- Python 3.13 and 3.14, each covering the entire collection;
- full source, tests and operator-tool lint/compile checks;
- both historical Python required contexts, failing unless all eight shards succeed.

Hosted CI PASS is not hardened-container or native Level-3 acceptance.

### Level 2 — deployment/container validation

Changes to image, Compose, container identity, mounts, secrets, or networking MUST additionally run the applicable live deployment probes on the authorized Docker host.

### Level 3 — full Linux E2E

Changes affecting SSH transport, policy/authorization, approvals/Ledger, credentials, host-agent, containment, filesystem mutation semantics, audit, workload identity, OS hardening, egress controls, SSH CA, secret-manager integration, or the E2E fixture itself MUST have exact-head full E2E evidence before merge.

Phase closure and release-candidate work MUST run full E2E regardless of which files changed.
## 7. Full E2E trust model

Full E2E MUST prefer real kernel/service evidence over mocks when feasible.

The ordinary PR runner MUST NOT be made privileged merely to run E2E. In particular, do not add a Docker socket, broad sudo, host PID namespace, writable cgroup root, or equivalent escape surface to the normal runner.

Capability-bearing checked-out code MUST NOT execute on a persistent CI/orchestrator host. `CAP_SETUID`/`CAP_SETGID` are intentionally trusted host-agent authority under ADR 0005 and can be used by compromised host-agent code to impersonate other identities, including UID 0 in the same user namespace.

Level-3 E2E therefore uses a fresh disposable Linux virtual machine for every run:
- the persistent orchestrator account is non-admin/non-root and receives no generic sudo;
- the orchestrator executes only trusted-main workflow/orchestration code;
- the target commit is fetched into a bare Git repository and transferred as a bundle; its worktree is never checked out or executed on the persistent host;
- the guest exposes no host filesystem mount to the target code;
- the guest has no virtual network device or other target-controlled path to the persistent host/LAN;
- GitHub tokens, production credentials, and host secrets are not passed into the guest;
- the target commit may exercise root/capability paths only inside the guest;
- in-guest cleanup is still tested;
- the entire guest plus overlay/media/result artifacts are destroyed after every run and their absence is verified.

Unknown pre-existing provider state MUST fail closed rather than being silently reused or deleted.

The reference Phase 7A provider is a dedicated native macOS x86 orchestrator using QEMU/HVF, a pinned Ubuntu 26.04 image, `-nic none`, no host sharing, read-only seed/payload media, a trusted-main read-only root guest gate, and bounded serial-only result collection. The exact target commit supplies manager/probe/support/application code, but the trusted root gate/orchestrator which judges that target must already be merged to `main`. A target change MUST NOT define or modify the Level-3 authority used to certify itself. Equivalent future providers must preserve the same or stronger isolation and anti-self-attestation contract.

## 8. Review discipline

Review happens repeatedly, not only at the end.

**Review request timing:** once implementation code, focused GREEN tests and author
self-review are complete, open the PR and request independent review promptly.
**Do not wait for full CI to pass before requesting review.** CI and independent
review may proceed in parallel; both exact-head verification and a clean final
review still block merge. A subsequent fix requires rechecking the new SHA.

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

## 12. CI and E2E execution policy

The approved migration in PRs #217 and #220 supersedes the former
self-hosted-only ordinary CI policy; see
[ADR 0013](decisions/0013-hosted-ci-self-hosted-e2e.md) and
[primary CI topology](ci-hosted-primary.md). Historical plans retain their
original platform evidence; their self-hosted-only instructions do not override
this current policy for future ordinary CI.

Routine PR validation MUST use the unprivileged `pull_request` event;
main validation MUST use `push:main`. Both MUST use GitHub-hosted Ubuntu
26.04 x86 VMs, read-only tokens, no PR secrets, SHA-pinned actions and
complete coverage on both Python versions. Both historical required Python
check names MUST remain fail closed for every
failed, skipped or cancelled shard.

Manual hardened Linux security validation remains on isolated self-hosted
containers. Dispatch MUST use trusted-main workflow authority and an
independently reviewed exact target revision; `github.ref=main` alone does not
make `inputs.ref` trusted.

Native no-network Level-3 remains on the dedicated non-admin Intel macOS
self-hosted orchestrator, using already-merged trusted-main authority and a
fresh disposable Ubuntu guest at the exact target SHA. Main-push native E2E
MUST depend on both hosted required gates. Unknown provider state still fails
closed and requires separately authorized disposition. Hosted CI success
MUST NOT be reported as hardened-container or native Level-3 success.

Do not add a Docker socket, host namespace or generic privileged runtime to
ordinary CI. Specialized live/E2E workflows retain their reviewed trust model.
Measure PR-style feedback latency separately from the complete main workflow,
including E2E. Keep slow, failed and cancelled attempts in performance evidence;
repeated fast samples do not authorize closing a failed security or cleanup gate.

## 13. Definition of Done checklist

A feature PR is Ready for Review only after its **one complete user/operator function** is runnable with a real required positive proof, negative/refusal proof, correct docs and reviewable acceptance evidence. A Draft PR may host design/plan approval gates and incremental TDD commits without representing acceptance. A slice is done only when all applicable items are true:
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

### Exact-main CI event and merge-token provenance (2026-10-17)

A merge API success and exact-PR-head green CI do **not** prove the merge-main
push workflow ran. PR #268 was squash-merged at
`a184f33644b3d54465c8bc8435e8b110342b907b` on 2026-10-17, but GitHub
Actions API returned **zero** runs for that SHA. The precise event-suppression
mechanism is **not yet established**; do not attribute it to a particular
connector credential without independent evidence. GitHub documents that
events caused by the repository's `GITHUB_TOKEN` do not start most workflows;
do not assume other tokens have the same semantics.

Before declaring a merge closed, use the read-only checker:

```sh
python3 ops/live-e2e/merge_main_evidence.py --sha <exact-40-hex-main-merge-sha>
```

The checker refuses absent/ambiguous push-on-main CI, wrong workflow or SHA,
incomplete pagination, non-successful runs, and missing/skipped/failed/duplicate
jobs (all 8 Python shards, 2 Ubuntu gates, 1 real native Level-3). It **never**
dispatches CI, executes Mac code, changes host state or substitutes PR checks
for merge-main acceptance. A refusal is a **missing gate**, not a CI failure.
For future merges, prefer an operator-approved GitHub CLI merge with an
appropriately authorized non-`GITHUB_TOKEN` credential and observe the
actual exact-SHA main-push event; never auto-retry a possibly committed merge.
Any rerun/dispatch or native Mac operation requires its own applicable approval.


## 14. Agent handoff and shared-worktree discipline

The project uses a three-layer collaboration model:

- `../AGENTS.md`: short operational rules and approval boundaries.
- This document: normative development, verification, security, and review method.
- Each active worktree's root `progress.md`: **local, Git-ignored** operational handoff, initialized from [`templates/progress.md`](templates/progress.md).

On session resume, an agent MUST reconcile the live branch, HEAD SHA,
working tree, other active worktrees, relevant PR/issue decisions, and the
existing handoff before making changes. A conversation or previous handoff
claim alone does not establish a current repository fact. Agents MUST NOT
reset, overwrite, clean, or adopt another agent's worktree or shared state
without an ownership check and appropriate authorization.

Every active development worktree MUST create `progress.md` from the
template. Agents MUST update an existing handoff after material changes,
tests, decisions, review remediation, approval changes, or interruption.
At minimum it MUST distinguish:

- objective, bounded scope, owner/role, worktree, branch, exact SHA and PR;
- verified checkpoints versus assertions or pending jobs;
- concrete test commands/results and links to evidence;
- review findings, outstanding dependencies and deferred gates;
- exact approvals, denials, and actions still needing consent;
- concurrent/shared-host resources and the next executable step.

The handoff MUST NOT contain secrets. Keep durable decisions, material
rulings, and acceptance evidence in version-controlled documents, ADRs,
or PR/issue comments. A Git-ignored handoff does not travel with a PR and
is not a source of security authority.

Agents SHOULD continue independently through ordinary tasks inside
previously authorized scope. Approval to design, inspect, or test
synthetic data MUST NOT authorize execution of candidate artifacts,
privileged host mutation, root/trust admission, protected staging,
release, or merge. When an action may already have committed, inspect
authoritative state before retrying.

On a shared Mac or CI host, author and reviewer MUST avoid competing
native/provider work and must not mutate each other's worktrees.
Reviewers SHOULD independently inspect code, evidence, and targeted
adversarial cases rather than rerunning costly author tests without
cause. Report independent review and author self-review separately.

Progress updates SHOULD report **Completed / Blocked / Next / Approval
required**, with exact evidence where relevant. Agents MUST NOT imply
work is running in the background unless a real task or process exists.

## 15. Reusable adversarial and external-evidence checks

The review cycle for PRs #268–270 exposed repeated input-handling and
evidence-provenance failure classes. Apply these checks across comparable
entrypoints, not only to the file named in the review.

**Untrusted files and structured input:**

- Bound byte count, execution time, memory/CPU exposure and parser nesting;
  a post-parse depth check alone does not protect the parser itself.
- Consider FIFO/special-file substitution and blocking `open()`, symlink
  traversal, race/TOCTOU, file identity changes, and oversized reads.
- Where applicable, use no-follow and nonblocking open, verify the opened
  object is a regular file before reading, and enforce explicit read caps.
- Catch documented parser/resource exceptions (including recursion
  failures) before they become raw tracebacks or inconsistent exit codes.
- Add negative subprocess tests with timeouts for FIFO, oversized/deep
  input, malformed encodings, symlink/special-file substitutions, and
  refusal behavior relevant to the tool.

**External evidence and source authority:**

- Pin and verify the authoritative API/service endpoint rather than
  accepting ambient configuration such as a hostile `GH_HOST`.
- Match evidence to exact SHA, actual run/event, workflow, platform,
  signer, and policy scope as applicable.
- Treat a structurally valid response, hash match, public attestation
  claim, synthetic preflight, or exit 0 as **non-authorizing** unless the
  required independent trust evidence and approval are established.
- Distinguish a verification failure from missing evidence or an
  unsupported platform. Unverified MUST NOT silently become PASS.

For CI efficiency, reproduce the smallest failing case first, move to
focused GREEN, then run the full applicable regression and exact-SHA
acceptance gates. A slow optional investigation MAY be deferred with an
explicit owner and tracked follow-up; mandatory security and completion
gates MUST NOT be replaced with placeholders.
