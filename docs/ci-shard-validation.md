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
Each check is now a **fail-closed aggregator**, dependent on a matrix of
four self-hosted Ubuntu 26.04 x86 shard Jobs:

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
A gate **must fail** if *any* shard fails, is skipped or is cancelled.
The merge-main native Level-3 step still depends on the validated gate.

These Jobs can queue on a single runner; **a lower per-Job execution
time is not proof of higher aggregate runner throughput**. Optimize
source fixture rebuild costs next only after profiling without
weakening verification or provenance boundaries. GitHub
`pull_request_target` reads its workflow configuration from the base
branch: a CI-workflow PR's existing base-branch check does **not**
independently certify that the proposed new workflow has executed.
Independent review, static shard-partition tests and post-merge/main
exact-head live verification are still required before declaring the
CI issue fully resolved.

The 5-minute external monitoring cadence is unchanged. Native
A1/B8/N1c/UID-502/stale-provider/Level-3 acceptance remains OPEN;
a PR-only `SKIPPED` is not a substitute for native evidence.
