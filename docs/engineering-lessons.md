# SOM engineering lessons — 2026-10-27

This is a **retrospective**, not an architecture change, approval, CI attestation, or release acceptance.
Operational requirements live in [`AGENTS.md`](../AGENTS.md) and the
[normative development method](development-methodology.md). The current product scope and
open gates live in [`mvp-status.md`](mvp-status.md); do not infer current status from this snapshot.

## What to preserve

1. **End-to-end outcome over activity counts.** A useful slice lets a user/operator perform
   one real, reproducible action with defined success **and refusal** behavior. A commit,
   green unit suite, merged PR, or offline preview is not by itself deployed capability.
2. **Bounded vertical slices.** Design, plan, RED/GREEN implementation, adversarial tests,
   runbook, and acceptance evidence belong in one coherent feature PR. Split at a real
   independently shippable capability or authority boundary, not every helper/document.
3. **Early feedback without weaker gates.** Run focused RED/GREEN before wider regression.
   Request independent review as soon as there is reviewable implementation; run CI and
   review in parallel. Both must cover the final exact head before merge.
4. **Invariants before convenience.** Model input is not authority. Default deny, host-key
   pinning, separated operator approval, host-local enforcement, audit, bounded untrusted
   input, and fail-closed responses are product properties, not optional test fixtures.
5. **Prove the actual boundary.** A mock, configuration shape check, signed test artifact,
   ordinary hosted CI, real Linux kernel probe, isolated guest E2E, and authorized
   production deployment answer *different questions*. Never promote one as another.
6. **Explicit ambiguous-commit states.** When a write may have happened but acknowledgment
   or durability is uncertain, preserve UNKNOWN/committed-uncertain semantics; do not
   silently roll back, claim success, or auto-retry.
7. **Durable handoff.** Each worktree records exact SHA, evidence, approval source, blocker,
   resource ownership and next executable action in its Git-ignored `progress.md`.
   Git/CI/PR state must be rechecked on resumption; conversation memory is not proof.
8. **Agent autonomy within consent.** Investigate, implement and validate approved work
   without redundant checkpoints. Do not infer approval for privileged host changes,
   trust roots, image admission, production network policy, merge or release.

## Failure modes and corrective actions

| Observed failure mode | Corrective action |
| --- | --- |
| Many small PRs, but the next real user workflow is still unavailable | Track independently **accepted capabilities** and end-to-end lead time; package related code/tests/docs as one coherent feature slice |
| Offline preflights and structural checks multiply | Require a named, currently measured blocker or independent operator use case; report `deployment_ready=false` if no runtime proof; otherwise defer |
| A large release-track PR grows multiple unrelated surfaces | Extract truly independent fixes only; keep one visible target workflow and a short critical-path gate list in the parent PR |
| Verification succeeds on the wrong platform, SHA, or event | Bind evidence to exact code, workflow, signer, environment, and event; record `UNVERIFIED` instead of borrowing earlier PASS |
| Privilege/kernel incompatibility invites a shortcut | Measure the actual failure on the target platform, propose the smallest safe candidate, obtain independent security ruling and required authorization |
| Agents repeat work or collide on shared hosts | Check branch/worktree ownership and live fixtures first; preserve checkpoints and do not run competing privileged native tests |
| Documentation describes a future capability as shipped | Report `IMPLEMENTED`, `TESTED`, `REVIEWED`, `MERGED`, `DEPLOYED`, and `ACCEPTED` as distinct claims, each with evidence |

## Backlog decisions

Classify every substantial open item when prioritizing the next slice:

- **RELEASE_BLOCKER:** a mandatory security, trust, deployment, approval, native E2E,
  rollback, or release gate for the proposed release. Never waive or relabel it for speed.
- **FUNCTIONAL_BLOCKER:** the requested operator/user workflow cannot yet complete
  in its declared target environment. Fix it or explicitly label the smaller delivery
  as a **pilot**, without silently reducing the agreed MVP.
- **DEFERRED:** work not necessary for the currently declared outcome or required safety
  gate. Record owner, risk, dependency and the condition for revisiting it.

Favor the earliest real **MCP → Ledger → SSH → host operation → response/audit** positive
and refusal proof possible inside the already-authorized isolated environment.
Use static checks as supporting evidence, not as a substitute for the running path.

## SOM milestone vocabulary (not a scope change)

- **Technical pilot:** bounded, isolated multi-SSH filesystem workflow with real central
  approval/audit, successful and refused operations, and cleanup. It is **not** the full MVP.
- **Full functional MVP:** the separately agreed **eight typed filesystem operations**,
  with both Mode A (single Linux Engine) and Mode B (separate Linux Engines) independently
  demonstrated and the required authorization, mutation and failure contracts enforced.
- **Release accepted:** signed/verified actual runtime identity, production network and
  least-privilege gates, trusted full E2E, rollback/recovery, independent review, exact-main
  evidence and explicit operator deployment authorization.

A pilot cannot silently stand in for the full functional MVP; a full functional test
cannot stand in for a production release. Read the normative scope and current gates
in [`mvp-status.md`](mvp-status.md) and the governing ADRs.

## Evidence from actual project iterations

- [PR #268](https://github.com/zhangyuz/ssh-over-mcp/pull/268):
  successful merge / PR checks did not establish an observed exact-merge-SHA
  `push:main` CI run. The specific credential/suppression cause was **not proven**.
- [PR #343](https://github.com/zhangyuz/ssh-over-mcp/pull/343):
  synthetic subtree visibility preview is useful for offline policy inspection;
  its own output explicitly disclaims runtime authorization and deployment readiness.
- [PR #344](https://github.com/zhangyuz/ssh-over-mcp/pull/344):
  a self-contained `fs_mkdir` durability fix kept potentially committed/uncertain
  writes non-retryable; this does not grant #342 deployment authority.
- [PR #342](https://github.com/zhangyuz/ssh-over-mcp/pull/342):
  real OpenSSH/OCI tests and image attestations are strong *scoped* evidence.
  At this retrospective date it remains Draft/HOLD; neither testing nor attestations
  alone approve production privilege expansion or deployment on Yuz.local.

## A lean execution check

Before starting: identify the agreed end-user outcome, earliest missing real E2E
proof, the authoritative security invariant, the next independently verifiable slice,
and applicable approval gates.

While building: RED → minimal GREEN → targeted security regression; request independent
review early; run the required exact-head CI/E2E concurrently where safe; fix discovered
defects immediately or record a permitted deferral.

Before claiming completion: state **what is usable by whom**, exact revision/environment,
positive and refusal evidence, review and CI status, remaining release gates, cleanup,
and the next action. No skipped/missing test is PASS.

Measure **accepted user capabilities**, feature lead time (start → acceptance),
release-blocker age, regression escapes, and CI/review feedback time. PR count and
test count are secondary diagnostic metrics, not delivery targets.
