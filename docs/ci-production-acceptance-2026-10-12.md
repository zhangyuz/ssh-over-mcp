# Production hosted CI: ten-sample acceptance

**Observed acceptance: PASS, 2026-10-12.** Scope is complete ordinary
GitHub-hosted Python 3.13/3.14 feedback through both historical required gates.
Snapshot: `2026-10-12T23:48:37.918713+00:00`.

| Metric | Observed result |
| --- | --- |
| Comparable complete attempts | 10 / 10 hosted PASS |
| Minimum | 5m43s |
| Median | 7m14s |
| Nearest-rank empirical P95 | 7m22s |
| Maximum | 7m22s |
| Acceptance threshold | Every sample and empirical P95 below 10m |

## Comparable code and complete coverage

The first eight baseline attempts were selected before the final two outcomes;
then exact-main post-merge run `38323133514` and controlled full rerun
`38321930336/2` completed the cohort. All ten retained attempts have all six
partitions and both historical gates SUCCESS. Failed/cancelled comparable
attempts would block this gate, not disappear from its evidence.

Actual checkout commits were extracted from a completed Python 3.13 rest
job's official checkout log in each attempt, fetched without executing target
code, and checked against these exact Git objects:

| Component | Identical Git object |
| --- | --- |
| `.github/workflows/ci.yml` | `626a1905691a1a9ca9b6aa938dbe579f7c3085e6` |
| `src` | `7419107d344e36921b26d9d515d2ec459bff84c7` |
| `tests` | `4e550192020b212e79a1aecb3b969d3386dde2de` |
| `ops/live-e2e` | `44dcf43096147c7a53d4c474c2a28ba77a4f54c2` |
| `ops/systemd` | `405c9b8f4b39577f60beeba34a601a59f7928f09` |
| `pyproject.toml` | `2f37d92ad7d97cfc2e22481cb2e4e87fad1e909d` |

The test tree, source tree and dependency declarations are identical, not
just the PR branch names. This does not assert identical resolved package
versions or hosted hardware. Both PR merge checkouts and real main checkouts
are included. The two experiments and the earlier differing test tree are
excluded for stated workload differences; the old
[pilot snapshot](ci-hosted-acceptance-2026-10-12.md) remains historical.

A fresh developer-Mac collection proof reconfirms **611 = 4 hot + 607 other
projection nodes**, with zero omissions and zero overlap. It is a source
partition proof, not an Ubuntu execution claim. The actual ten hosted runs
execute those three complementary partitions on **both** Python versions;
all other tests stay in the automatically discovered rest partition. Existing
platform skips and product security assertions remain unchanged. Full Ruff
and compilation cover src, tests, ops/systemd and ops/live-e2e in every shard.

## Attempt evidence

| Run / attempt | Actual checkout | Hosted feedback | Whole workflow |
| --- | --- | --- | --- |
| [38304746153 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38304746153/attempts/1) | `932a7b1f7c2f` | 7m22s | success |
| [38304746153 / 2](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38304746153/attempts/2) | `932a7b1f7c2f` | 7m22s | success |
| [38308656457 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38308656457/attempts/1) | `39a4f868bb77` | 5m50s | failure |
| [38310229053 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38310229053/attempts/1) | `19f8b60a647f` | 7m11s | success |
| [38310229053 / 2](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38310229053/attempts/2) | `19f8b60a647f` | 7m16s | success |
| [38321189754 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321189754/attempts/1) | `8fe5078e9fd3` | 7m19s | success |
| [38321821509 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321821509/attempts/1) | `c9ccec7e87d2` | 7m10s | success |
| [38321930336 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321930336/attempts/1) | `28702370b615` | 7m16s | success |
| [38323133514 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38323133514/attempts/1) | `db42a8e7be72` | 7m12s | failure |
| [38321930336 / 2](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321930336/attempts/2) | `28702370b615` | 5m43s | success |

Feedback is specific-attempt `run_started_at` to the later historical gate's
`completed_at`, including the observed queue/setup/test/aggregate interval.
Original workflow creation time is never reused for a rerun. Nearest-rank
P95 is sorted sample `ceil(0.95 * 10)`, which is the maximum here.
[Raw records](evidence/2026-10-12-production-ci-acceptance.json) retain job
outcomes, timestamps, checkout-log job IDs and Git object bindings.

## Main integration and separate native failure

PR #222 merged as `db42a8e7be72e6dee93a51d4350836e7660ed1cc`.
Its exact-main [run 38323133514](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38323133514)
passed all six hosted partitions and both gates in **7m12s**.
The subsequent native no-network Level-3 stage remains **FAILURE** on
pre-existing provider state, so the **whole main workflow is FAILURE**.
No native or hardened-container acceptance is awarded by this CI-speed gate.
No marker/directory cleanup, privilege change, branch-protection change or
E2E guard weakening occurred. See the [provider disposition plan](plans/2026-10-09-native-provider-disposition.md).

This satisfies the ten-sample observed CI-latency gate. The sample includes
correlated reruns within one evening; it does not guarantee future latency
or prove a population P95. Continue retaining routine queue-inclusive
outcomes and reevaluate if any comparable run reaches 10m, fails or cancels.
Six hosted VMs consume private-repository Actions minutes; the existing
96 runner-minute cap per attempt is unchanged.
