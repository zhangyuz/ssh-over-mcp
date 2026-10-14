# PR Native E2E Shadow Admission — implementation evidence

Status: **unmerged first-slice implementation; integration canary pending**.
Implementation branch: `feat/pr-native-shadow-admission-oct14`.
Trusted base: `main` `18baf09d31a2610c2ce4359bd04a9ebf85cbb62f` after approved design PR #244.
Authority: [vNext design](../superpowers/specs/2026-10-14-local-live-e2e-vnext-design.md),
[rollout](../superpowers/plans/2026-10-14-local-live-e2e-vnext-rollout.md)
and [first implementation plan](../superpowers/plans/2026-10-14-pr-native-e2e-shadow-admission.md).

## Delivered boundary — shadow only

The new `.github/workflows/pr-native-e2e-shadow.yml` observes completed
`CI` workflow runs on GitHub-hosted Ubuntu from the trusted default branch.
It has `contents: read`, `actions: read`, `pull-requests: read` and
**no native dispatch**, **no status write**, no secret/host/guest provisioning,
no fork/PR-controlled source checkout and no workflow_call to the Mac runner.
The existing `.github/workflows/ci.yml`, `live-local-e2e.yml` and native
orchestrator are unchanged.

The read-only API adapter uses bounded, fixed GitHub REST GET endpoints.
It resolves commit-associated live PRs independently (the original event's
`pull_requests` may be empty), pins the immutable HEAD SHA and run attempt,
verifies exact reported job names/conclusions and refuses mismatched
repository, fork, draft/closed PR, stale HEAD, wrong base, duplicate/partial
job or malformed API response. A PR may modify its own CI script to
manufacture ten green job names: metadata alone cannot show what tests
really executed. Consequently the only positive verdict is
`METADATA_MATCH_SHADOW`, always with
`trusted_suite_proven=false`, `base_freshness_proven=false`,
`dispatch_authorized=false`. It is NOT a trusted full-CI attestation, a
PR approval, a Level-3 E2E result or a merge-required status.

Errors use fixed reason codes, with no PR title, token, raw API exception,
host command or generic external URL in output. API failures exit nonzero;
normal fork/stale/ineligible metadata is printed as REFUSED, not as success
evidence (although the observational workflow job may complete normally).
The provider does not write `GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY` or
any PR commit status.

## Evidence and limitations

- Confirmed base project workflow contract suite `tests/ops/test_ci_workflow.py`:
  **11 local tests passed** with the existing project venv and isolated
  worktree-specific `PYTHONPATH=<worktree>/src`.
- Task 1 RED: missing classification module, then GREEN; a separate
  duplicate-job-ID negative test failed before the duplicate guard was
  introduced. Task 2 RED: missing adapter, then GREEN; commit-associated
  PR-detail-number mismatch failed before a bound-number guard. Task 3 RED:
  missing CLI then GREEN. Task 4 RED: missing hosted-only workflow then GREEN.
  Task 5 RED: evidence file missing, then GREEN after this page was written.
- Focused tests simulate wrong run/attempt, missing/duplicate/failing/skipped
  jobs, fork, stale HEAD, ambiguous PR, malformed SHA, API pagination
  limit/total mismatch, redirect/oversize/invalid response and refusal secrecy.
  No local fixture is represented as proof of native macOS/Ubuntu guest execution.
- Task 5 composite local regression (all first-slice contract tests plus
  existing hosted CI and native gate contracts): **120 passed in 0.61s**,
  Python 3.13 from the existing virtualenv with worktree-specific PYTHONPATH.
  Complete repository source/test/operator **Ruff PASS** and
  `python -m compileall -q src tests ops/systemd ops/live-e2e` PASS.
  This is deliberately *not* the full project pytest suite or native E2E.
- For PR #245's reviewed exact HEAD
  `b4c3e0ac0ee99fb4c6fc6bafb8fafd0a368c0bdd`, full GitHub-hosted
  Python 3.13/3.14 CI **PASSED** on
  [run #38567081924](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38567081924)
  and again after Ready for review on
  [run #38567775261](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38567775261):
  all eight full partitions and both aggregate required contexts succeeded.
  PR-only native Level-3 was SKIPPED (expected, not native evidence).
  These results apply to that exact *older* HEAD; the review-fix commit
  must independently pass its own exact-final-head CI before merge.
- Independent [review #6169205482](https://github.com/zhangyuz/ssh-over-mcp/pull/245#issuecomment-6169205482)
  found **no Critical or Important defect**, with two Minor findings.
  Minor 1 adds event-vs-REST upstream identity consistency and missing-field
  refusal tests. Minor 2 corrects this previously stale CI evidence and
  the PR's Ready-for-review description. Both changes remain shadow only;
  the final revised-HEAD CI is pending at the time of this documentation edit.
- Actual post-merge trusted-main shadow workflow_run **canary: pending**.
  Must confirm a successful eligible canary prints only
  METADATA_MATCH_SHADOW; a fork/stale canary prints REFUSED or is safely
  excluded; in both cases zero self-hosted Mac jobs and zero status writes.
- Separate **design baseline**: after PR #244 was merged at
  `18baf09d31a2610c2ce4359bd04a9ebf85cbb62f`, GitHub Actions
  [main CI #38563974688](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38563974688)
  completed SUCCESS including both required Python aggregates and the
  actual `Merge-main no-network Level-3 / No-network Ubuntu 26.04 local E2E`
  native job SUCCESS. This does not verify this new first-slice feature.
- Actual Level-3 native post-merge gate for the implementation commit:
  **pending**; this slice does not alter the native provider, but normal
  main-push exact-main E2E/cleanup remains required by project methodology.
- Separate protected staging owned lifetime, protected activation, pinned
  trusted-main hosted test-manifest verifier, workflow_dispatch broker,
  informational SHA reporter and PR-bound merge enforcement all remain
  independently gated by later plans and reviews.

## Rollback

If shadow misclassifies an eligible PR, fails due to GitHub API behavior,
overloads normal hosted CI or unexpectedly requests extra permissions,
disable/revert only the new shadow workflow. No retry/delete on the Mac
provider, no branch rule changes, and no alteration to ordinary hosted CI,
manual native E2E or merged-main Level-3. Refusal is safer than pretending
that lower-trust CI metadata proves the intended trusted test suite.
