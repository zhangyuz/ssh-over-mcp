# PR Native E2E Shadow Admission — implementation evidence

Status: **merged and acceptance-verified (metadata-only); no PR-native authority**.
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
  These runs apply only to that earlier HEAD. The final review-fix HEAD
  `5cee586116a65b0f005d68d67d67f17c19b92776` separately passed
  [exact-head CI #38579608215](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38579608215)
  and the trusted-main manual exact-target
  [Level-3 #38580133773](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38580133773)
  (including provider-marker absence).
- Independent [review #6169205482](https://github.com/zhangyuz/ssh-over-mcp/pull/245#issuecomment-6169205482)
  found **no Critical or Important defect**, with two Minor findings.
  Minor 1 adds event-vs-REST upstream identity consistency and missing-field
  refusal tests. Minor 2 corrects this previously stale CI evidence and
  the PR's Ready-for-review description. Both changes remained shadow only;
  exact-final-head CI and manual trusted-main Level-3 later passed as linked above.
- **Actual post-merge trusted-main shadow `workflow_run` canary: PASS.**
  A disposable, same-repository, non-draft
  [PR #246](https://github.com/zhangyuz/ssh-over-mcp/pull/246) at
  `69c88b4c38374dc3d9ec9a608d68292db8af6648` completed
  [full hosted CI #38581233248](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38581233248)
  with eight shards and both aggregate gates SUCCESS. The separate
  [trusted-main shadow #38581841150](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38581841150)
  ran its hosted-only read-only job, and the **actual logged JSON** included
  `pr_number=246`, `ci_run_id=38581233248`, `ci_attempt=1`,
  `verdict=METADATA_MATCH_SHADOW` and all three flags
  `base_freshness_proven=false`, `trusted_suite_proven=false`,
  `dispatch_authorized=false`. A completed push-main upstream instead
  produced expected [SKIPPED #38581813613](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38581813613).
  REST `GET /commits/<canary-sha>/statuses` returned `[]` (no custom
  commit-status writes), and the workflow_run job used GitHub-hosted Ubuntu,
  not any self-hosted Mac label; the recent standalone native dispatch list
  contained only the earlier authorized manual run, not a new shadow dispatch.
  The canary PR was CLOSED **without merge** and its own temporary branch
  and worktree removed; acceptance was also recorded in
  [canary comment #6170897124](https://github.com/zhangyuz/ssh-over-mcp/pull/246#issuecomment-6170897124).
  This success is only an observation of current same-repo metadata, not
  verified trusted-test execution, fork admission or PR-bound merge enforcement.
- Separate **design baseline**: after PR #244 was merged at
  `18baf09d31a2610c2ce4359bd04a9ebf85cbb62f`, GitHub Actions
  [main CI #38563974688](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38563974688)
  completed SUCCESS including both required Python aggregates and the
  actual `Merge-main no-network Level-3 / No-network Ubuntu 26.04 local E2E`
  native job SUCCESS. This does not verify this new first-slice feature.
- **Actual native post-merge acceptance: PASS.** PR #245 was squash-merged
  at `7ec63ec7a39803518eda628b95021b46e666899e`; GitHub
  [main CI #38580710142](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38580710142)
  completed SUCCESS for the exact merged-main SHA, including all eight
  hosted partitions, both required Python aggregates, and the genuine
  `Merge-main no-network Level-3 / No-network Ubuntu 26.04 local E2E`
  native job SUCCESS with the provider-absence check. This is the legacy
  Level-3 placement path, **not** ADR 0019 protected-placement activation.
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
