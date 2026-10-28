# Agent instructions

This repository is security-sensitive infrastructure. Automated coding agents must treat `/docs` as the source of truth.

All automated coding agents MUST read and follow [`docs/development-methodology.md`](docs/development-methodology.md). Its core principle is: **从第一性原理出发；小步快跑，持续迭代，关注质量、安全、一致性。** First establish the user-visible product goal and actual trust boundaries; challenge inherited implementation assumptions instead of making their costs permanent requirements.

## Required workflow

1. Read `docs/development-methodology.md`, `docs/README.md`, `docs/security-model.md`, `docs/policy-spec.md`, and `docs/mcp-api.md` before changing behavior.
2. Do not weaken a documented security invariant to make a test pass.
3. Any behavior change affecting authorization, command execution, host identity, credential handling, approvals, audit semantics, or network exposure must update the relevant document in the same change.
4. Architectural changes require a new ADR under `docs/decisions/`.
5. Deny rules override allow rules. Default policy remains deny unless an ADR explicitly changes it.
6. Never introduce a generic unrestricted shell path into a low-privilege role.
7. Never accept host address, SSH username, SSH key, or host-key trust material directly from model-supplied tool arguments.
8. Never set `StrictHostKeyChecking=no`, disable host-key verification, or silently trust a changed host key.
9. Never make `NOPASSWD: ALL`, Docker socket access, host PID namespace, or equivalent root escape mechanisms part of a normal profile.
10. Tests must cover both allowed behavior and bypass attempts.

When code and docs differ, stop and resolve the discrepancy rather than silently choosing one.

## Three-layer agent operating model

The three layers have different responsibilities and MUST NOT substitute for one another:

1. **`AGENTS.md` — operational contract:** what agents must do, must not do, and when they must request approval.
2. **[`docs/development-methodology.md`](docs/development-methodology.md) — normative method:** TDD, security and CI gates, review, exact-SHA evidence, and Definition of Done.
3. **Worktree-local `progress.md` — current handoff:** live facts, approved scope, outstanding gates, evidence, and next action. Initialize from [`docs/templates/progress.md`](docs/templates/progress.md). This file is Git-ignored; it is neither an authority source nor a substitute for PR/issue comments.

## Agent execution and handoff

- **Resume before changing anything.** Inspect actual HEAD, `git status`, branch/worktree ownership, active PRs, review comments, and existing `progress.md`. Prior conversations or agent summaries are leads, not proof of current state. Do not reset or clean someone else's worktree.
- **Record durable checkpoints.** Keep worktree-local `progress.md` current after meaningful changes and before handoff: exact SHA, scope, completed work, verification, blockers, granted/denied approvals, shared-host activity, and the next executable action. Never record secrets. Preserve authoritative decisions and durable evidence in the appropriate tracked documents or PR/issue comments.
- **Keep moving within consent.** Complete normal investigation, isolated implementation, focused testing, remediation, documentation, and PR preparation within the approved scope. Do not request redundant confirmation. Never extrapolate approval to privileged host operations, unapproved executables/trust roots, destructive cleanup, release, or merge.
- **Make blockers explicit.** If external trust evidence or approval blocks a feature, seek a smaller independently useful, non-authorizing slice with explicit success/refusal semantics. Keep the original security gate open. A synthetic or shape-only PASS is never production authorization.
- **Separate author and reviewer.** Independent reviews assess exact-head code, security, documentation and evidence. On shared hosts, avoid redundant expensive test runs and coordinate stateful native/privileged fixtures. Do not claim an author self-review was independent.
- **Report verifiable states.** Distinguish implementation, local verification, exact-HEAD CI, independent review, operator authorization, and exact-main acceptance. No skipped or absent check is a PASS. Never claim unscheduled background work.
- **Choose the next user outcome, not more process.** Name the concrete user/operator workflow and earliest missing real E2E proof. Prioritize a bounded vertical slice on the safe delivery critical path. Static/offline preflights are supporting evidence, not production acceptance; do not let helper-PR count substitute for shipped capability. See [engineering lessons](docs/engineering-lessons.md).
- **Triage without waiver.** Distinguish mandatory release/security gates, actual functional blockers, and deferred enhancements. Keep the agreed full MVP scope separate from a smaller technical pilot; preserve authority and approval boundaries even when optimizing delivery speed.
- **Prevent repeat defect classes.** Treat findings on untrusted input bounds, FIFOs/special files, symlinks, parser recursion, ambient CLI configuration, and evidence provenance as reusable security review cases. Detailed requirements belong to the development methodology.

## Merge-main CI event provenance (incident PR #268, 2026-10-17)

A merged PR with green PR checks is **not** proof of `push:main` CI.
PR #268's exact merge SHA lacked an observed main-push CI run; the connector's
merge credential and precise suppression cause remain **unproven**. GitHub's
documented `GITHUB_TOKEN` event-suppression rule is a possible explanation,
not confirmed incident attribution.

- Prefer operator-approved local `gh pr merge` with an appropriate user credential. Do not retry an ambiguous merge without checking authoritative PR/main state.
- Verify exact-merge-SHA `push/main` CI and every required job with `python3 ops/live-e2e/merge_main_evidence.py --sha <40-hex-main-sha>`. Missing, skipped, failed, wrong-SHA, or PR-only evidence means **MERGE_MAIN_UNVERIFIED**.
- No synthetic push, privileged dispatch, `pull_request_target`, or native Mac rerun to bypass provenance without separate approval. Record uncertainty in `progress.md` and PR comments.
- Follow the canonical incident account and gates in [`docs/development-methodology.md`](docs/development-methodology.md).
