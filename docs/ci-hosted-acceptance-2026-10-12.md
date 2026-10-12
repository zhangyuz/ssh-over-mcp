# Hosted CI acceptance evidence — 2026-10-12

## Measurement and scope

Snapshot time: `2026-10-12T23:24:01.370283+00:00` (UTC).

Snapshot reconstructed from GitHub REST attempt-specific workflow and job
records, including **every attempt** of the eight listed six-way runs. Raw
bounded evidence is [stored here](evidence/2026-10-12-hosted-ci-attempts.json).
This is a historical pilot cohort across different workflow revisions, not a
random or independent production sample. Earlier two- and four-way baselines
are excluded because they use different topology. Future slow, failed or
cancelled six-way attempts must be retained and explained, not filtered to
manufacture a successful percentile.

Hosted feedback is measured from `run_started_at` for the specific attempt
to the last hosted required gate's `completed_at`, including queue/setup/test
and aggregate time. For the initial experiment the one full-suite gate is
used. Original workflow `created_at` must not be used for a later rerun.
All six shards and all applicable aggregate gates must succeed for a timing
to qualify as successful feedback. Pending/failed attempts remain visible.
Earlier handoff values used workflow `updated_at`: the initial experiment
was 7m02s overall versus 7m01s final-gate feedback, and PR #220 was
7m23s overall versus 7m22s final-gate feedback. The metrics differ by
workflow finalization time; do not mix them in one percentile.

Native E2E is a separate subsequent stage; its failure keeps the **overall
main workflow failed**, even when hosted checks pass.

| Run / attempt | Event | SHA | Hosted feedback | Overall workflow |
| --- | --- | --- | --- | --- |
| [38300258158 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38300258158/attempts/1) | pull_request | `cd5f26fed62b` | 7m01s | success |
| [38303346075 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38303346075/attempts/1) | pull_request | `def0681a145b` | 5m14s | success |
| [38303775407 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38303775407/attempts/1) | pull_request | `9607fd086ef0` | 7m19s | success |
| [38304746153 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38304746153/attempts/1) | pull_request | `117f1b6717f9` | 7m22s | success |
| [38304746153 / 2](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38304746153/attempts/2) | pull_request | `117f1b6717f9` | 7m22s | success |
| [38308656457 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38308656457/attempts/1) | push | `39a4f868bb77` | 5m50s | failure |
| [38310229053 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38310229053/attempts/1) | pull_request | `0626a407015c` | 7m11s | success |
| [38310229053 / 2](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38310229053/attempts/2) | pull_request | `0626a407015c` | 7m16s | success |
| [38321189754 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321189754/attempts/1) | pull_request | `908339366cef` | 7m19s | success |
| [38321821509 / 1](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321821509/attempts/1) | pull_request | `f06f98137e12` | Pending / not accepted | in_progress |

## Current result and remaining gates

The snapshot has **9 completed hosted successes**, ranging from
**5m14s to 7m22s**.
Nearest-rank empirical P95 **among these 9 completed hosted successes** is
**7m22s**. Pending attempts are excluded from this conditional statistic
and remain in the table. This does not establish the planned ten-sample
production acceptance, a stable population P95, or native E2E success.
Repeated reruns are correlated observations and can be affected by cache
and hosted-runner load. Continue collecting routine production runs and
report topology/revision, all outcomes and queue-inclusive times.

Exact main `39a4f868bb77b0391dbeeee5fb56d3cdb4ae3128` has six hosted
shards and both historical gates PASS, but run `38308656457` is **FAILURE**:
native Level-3 refused the pre-existing provider state before QEMU launch.
[The disposition plan](plans/2026-10-09-native-provider-disposition.md)
continues to block cleanup of the three UID-502 directories and fixed marker.
No disposition, process signalling, ownership change or privilege escalation
is authorized by this report. Manual hardened-container security acceptance
and native Level-3/cleanup remain separate, unresolved gates.


Fresh exact-main [inspect-only run 38321349471](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321349471)
on `39a4f868bb77b0391dbeeee5fb56d3cdb4ae3128` also reports the same
three UID-502 directory identities, all with `expected_commit=null`.
Owner PID input was 0; this neither mutates provider state nor proves
owner death or QEMU quiescence. All native disposition gates remain open.
