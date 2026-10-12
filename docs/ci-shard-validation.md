# CI validation sharding and timeout budget

## Evidence and root cause

The exact-head Ubuntu 26.04 x86 Python 3.13 Jobs for PR #205 and
#206 completed their full suites in approximately 18–19 minutes.
Python 3.14 and later PRs were frequently cancelled when the previous
single full-suite job reached its 20-minute timeout. In PR #205,
setup/checkout/pip/lint/cgroup/compile completed in under one minute.
The suite reached ~77% rapidly, then spent most of its runtime in
source-reconstruction integration/security fixtures in
`tests/ops/test_live_e2e_staging_projection.py`.

Examples from a completed PR #205 `pytest --durations=15` log:

| Real original-source regression | Seconds (approx.) |
| --- | ---: |
| Dispute overlap real pagination overflow | 109 |
| Private eight-segment / 128-hop maximum | 67 |
| Dispute overlap valid index exceeds wire capacity | 62 |
| Dispute overlap coverage for large valid index | 61 |
| Majority gap, leading/trailing eight-gap bound | 47 |
| Remaining expensive source-bound checks | ~17–21 each |

These are required positive-boundary/security regressions; **do not
delete, mock away, skip or loosen them** to reduce wall time.

## CI plan

The `CI` workflow preserves the exact two legacy required check names,
`Ubuntu 26.04 x86 / Python 3.13` and `Ubuntu 26.04 x86 / Python 3.14`.
Each check is now a **fail-closed aggregator**, dependent on **four
explicitly named, independent reusable-workflow jobs** on the hardened
self-hosted Ubuntu 26.04 x86 runner. No multi-cell matrix result is
used for shard success; every named result is inspected individually:

- Python 3.13 / 3.14 × `source-heavy`: the explicitly enumerated ten
  long-running original-source tests from the projection module.
- Python 3.13 / 3.14 × `everything-else`: **all tests outside** that
  projection file, **plus** every remaining test within the projection
  file selected by the exact logical `not (heavy)` complement.

The two suites are disjoint and exhaustive. Original-source tests remain
in every full Python version's gate; no coverage downgrades. Each
self-hosted shard retains the existing non-root, capabilities-dropped,
no-new-privileges, no Docker socket, cgroup-v2 and Ubuntu x86 validation,
untrusted pull-request guard, SHA-pinned checkout/setup actions, Ruff,
compile and test steps. Each shard retains a 20-minute upper bound,
but the measured ~19-minute suite is now divided into shorter pieces.
The original check-name gate explicitly requires the success of each of
the four named jobs. Shell-level regression tests exercise all 16 single
failed/skipped/cancelled/unset cases and simulated partial reruns: a
successfully rerun shard may not hide another failed job. **Real GitHub
Actions multi-failure partial-rerun validation is still pending**.
A gate **must fail** if *any* shard fails, is skipped or is cancelled.
The merge-main native Level-3 step still depends on the validated gate.

These Jobs can queue on a single runner; **a lower per-Job execution
time is not proof of higher aggregate runner throughput**. Optimize
source fixture rebuild costs next only after profiling without
weakening verification or provenance boundaries. GitHub
`pull_request_target` reads its workflow configuration from the base
branch: a CI-workflow PR's existing base-branch check does **not**
independently certify that the proposed new workflow has executed.
Independent review, dynamic nodeid-set collection-partition tests,
branch-protection gate shell simulations and post-merge/main
exact-head live verification are still required before declaring the
CI issue fully resolved.

The 5-minute external monitoring cadence is unchanged. Native
A1/B8/N1c/UID-502/stale-provider/Level-3 acceptance remains OPEN;
a PR-only `SKIPPED` is not a substitute for native evidence.

## First canary and CI workflow contract migration (2026-10-12)

The first isolated `ci/verify-shards-canary` push run
[`38198741151`](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38198741151)
ran all four shards on the real hardened Ubuntu 26.04 x86 runner.
Python 3.13/3.14 `source-heavy` passed, with the nine present expensive
source-derived tests completing in under their per-shard 20-minute limits.
Both `everything-else` shards **failed, not timed out**, because five
pre-existing `tests/ops/test_ci_workflow.py` assertions still looked for
lint/compile/full-suite steps under the old `ci.yml` `validate` job. The
new `validate` job is a five-minute gate, while actual lint/compile/tests
and the 20-minute bound are in `ci-validation-shard.yml`. Both historical
required gate jobs failed as designed when the rest shards failed.

Contract regressions were updated to check the reusable workflow's actual
validation steps, both explicitly selected Python versions, complete
complementary test selection, container hardening and provenance guard,
while separately retaining the original `self-hosted-security.yml` full
matrix assertions. No production implementation or security boundary was
changed, and no test was skipped to make CI green. A new exact canary run
and post-merge exact-main push remain required before marking this effort
complete. The source-only project-dev venv intentionally lacks some
runtime packages; its whole-project collection test explicitly skips
locally but executes on fully installed CI runner dependencies.
