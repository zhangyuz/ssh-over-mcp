# Agent instructions

This repository is security-sensitive infrastructure. Automated coding agents must treat `/docs` as the source of truth.

All automated coding agents MUST read and follow [`docs/development-methodology.md`](docs/development-methodology.md). Its core principle is: **小步快跑，持续迭代，关注质量、安全、一致性。**

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

## Merge-main CI event provenance (incident PR #268, 2026-10-17)

**Verified facts:** PR #268 was merged using the ChatGPT GitHub connector REST
merge action to main SHA `a184f33644b3d54465c8bc8435e8b110342b907b`.
The active `.github/workflows/ci.yml` has `push: main`, but GitHub Actions
recorded **no `CI` push run for that SHA**. Previous main merge
`c7c2ad627e4572b804d585780469416ab9d93040` had a real push CI run
`38780209959` with 11/11 required jobs successful. The PR #268 merge API's
**credential type is not exposed** in available evidence; do not claim the
specific token or a definitive suppression root cause was proven.

**Verified GitHub platform rule:** repository Actions `GITHUB_TOKEN`-generated
`push` events do not trigger new workflow runs. GitHub App installation tokens
and personal access tokens can trigger workflows. See
https://docs.github.com/en/actions/concepts/security/github_token .
This rule makes merge-token/event suppression a plausible explanation for
PR #268, **not proof of which credential the connector used**.

**Mandatory agent behavior:**

- For operator-approved merges, prefer the authenticated local `gh pr merge`
  with a normal user credential rather than an opaque connector merge token.
  Never silently retry a merge after an uncertain API result; first query
  authoritative PR and main SHA state.
- After merge, inspect the actual exact-merge-SHA `push`/`main` `CI` run and
  all 11 required jobs. Run the read-only verifier
  `python3 ops/live-e2e/merge_main_evidence.py --sha <40-hex-main-sha>`.
  No run, a different SHA, incomplete/skipped jobs or a PR-only run means
  **MERGE_MAIN_UNVERIFIED**; never claim post-merge acceptance or gate closure.
- Never fabricate a push event or use a PR run as a substitute. Do not weaken
  event provenance with `pull_request_target`, automatic privileged dispatch,
  or native Mac reruns. Such changes require separate explicit approval.
- Preserve exact evidence and incident uncertainty in `progress.md` and PR
  comments; see `docs/development-methodology.md` for the full gate.
