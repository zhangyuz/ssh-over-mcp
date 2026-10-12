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
