# GitHub-hosted Ubuntu 26.04 CI comparison (opt-in experiment)

## Purpose

Measure end-to-end latency, reliability and complete dual-Python coverage on
standard **GitHub-hosted Ubuntu 26.04 x64 runners**, in parallel with the
existing secured Intel-Mac Docker self-hosted runner path. This is **not**
an automatic migration of security checks or a claim that CI is below ten
minutes.

SOM is a **private repository**, so the standard hosted Linux VM has **2 vCPU
and 8 GB RAM**, not the public-repo 4-vCPU/16-GB configuration. Hosted
standard-runner minutes draw down included Actions quotas; beyond included
minutes, the current Linux reference rate is **US$0.006/minute**. The two
20-minute job limits cap one fully running benchmark attempt at 40 hosted
runner-minutes (about US$0.24 over quota, before other usage). Check the
account's Actions billing/spending limit before enabling this routinely.
Sources:
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/billing/reference/actions-runner-pricing

## Experiment

`.github/workflows/ci-hosted-benchmark.yml` is a separate, **nonrequired**
workflow using `pull_request`, *not* `pull_request_target`. Only same-repo
PR branches beginning `ci/hosted-` run automatically; manual dispatch is
available for controlled follow-ups after the workflow is on the default
branch. All checks use least-privilege read-only `contents`, no custom
secrets, SHA-pinned checkout/setup-python, and no persistent credentials.

The two independent hosted jobs run the **unfiltered full test suite** on
Python 3.13 and 3.14, each with `pytest-xdist -n 2 --dist=load`, including
`ops/systemd` and `ops/live-e2e` lint/compilation. No slow tests are
excluded, and both versions must PASS for the comparison to be meaningful.
The checkout is the ordinary safe PR merge revision (no arbitrary fork
head ref override). The maximum budget is 20 minutes *per* hosted job.

The GitHub-hosted VM is **not** the project's hardened no-capabilities,
no-new-privileges, Docker-socket-free self-hosted Ubuntu 26.04 runner.
Do not classify a hosted PASS as satisfying the existing self-hosted
security and native Level-3 acceptance requirements. Keep the original
protected check names unchanged until separately reviewed.

## Comparison and acceptance

For each run, record: workflow trigger/commit SHA, queue delay, setup time,
test time, total end-to-end time, Python version, number of collected and
executed tests, worker crashes, and resource/cost data.

Compare with the same exact source revision on two isolated self-hosted
runner slots (once the optional second runner is independently reviewed and
enabled) and reject missing collection, skipped tests beyond established
baseline, cancelled runs, OOMs, and stale-code check results. The 10-minute
goal applies to **both** Python checks and end-to-end PR feedback, not the
mean duration of one job.

Use at least ten representative successful builds to estimate P95. If the
hosted path is slower, less reliable, or its billed minutes are not worth
the benefit, disable this benchmark and retain the self-hosted path.

## First live comparison and corrective experiment (2026-10-12)

The first hosted run [38285259332](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38285259332)
**FAILED on both versions**, after about 6m40s (Python 3.13) and
10m33s (Python 3.14). These are failed-run durations, **not accepted CI
performance results**. The full-suite attempt revealed hosted VM
supplementary groups violating SOM's strict Linux identity policy, shallow
checkout omitting a historical Git commit used by a diagnostics regression,
nonportable Mac/GNU Bash runner-identity regex, and an xdist-sensitive
wall-timeout test failure.

The Mac/GNU Bash regex and simulated runner environment were corrected in
#213 and synchronized downstream. The hosted-only benchmark now uses a full
Git checkout and a trusted OS `setpriv` utility to start **the complete
unfiltered pytest process** with the **same non-root UID/GID** but **without
hosted desktop supplementary groups**. The workflow checks this identity
before running any test. No SOM product identity policy, security assertion,
or test selection is relaxed. A small privileged OS setup step on a disposable
hosted VM is separate from the non-root test execution; the workflow uses no
repository secrets. Standard hosted runners are not equivalent to SOM's
hardened no-capabilities container.

This correction remains a hypothesis until a subsequent *actual GitHub-hosted*
run completes with both Python versions passing; all prior failed runs remain
recorded, and the goal of end-to-end P95 under 10 minutes is still unproven.
