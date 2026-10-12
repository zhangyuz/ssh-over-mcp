# Primary CI on GitHub-hosted; native E2E on self-hosted

Normative policy: [ADR 0013](decisions/0013-hosted-ci-self-hosted-e2e.md).
Attempt-specific latency and unresolved acceptance gates:
[2026-10-12 evidence](ci-hosted-acceptance-2026-10-12.md).

## Current execution topology

Routine `pull_request` (including fork PRs) and `push:main` execute
the **complete** Python 3.13 and 3.14 pytest collections on six independent
GitHub-hosted Ubuntu 26.04 x86_64 VMs (private repo standard 2 vCPU /
8 GB each). Each Python version has three disjoint, jointly exhaustive
partitions: the four exact long-running projection node IDs; all remaining
projection tests (currently 607); and all other project tests. Each job has
a 15-minute fail-closed timeout, `pytest-xdist -n 2 --dist=load`,
complete Ruff/compile operator coverage, full Git history, strictly non-root
test identity and immutable SHA-pinned official actions. Two independent
historical required-check contexts now refer to **aggregate gates**: both
fail unless **all six jobs** succeed (including partial rerun failure).
The existing required check **names** are retained:

- `Ubuntu 26.04 x86 / Python 3.13`
- `Ubuntu 26.04 x86 / Python 3.14`

Running untrusted PR code uses `pull_request` rather than privileged
`pull_request_target`, a **read-only token and no secrets**. Checkout uses
the default PR merge ref (no arbitrary head override), or exact SHA on
`push:main`; credentials are not persisted. Strict LinuxProcessIdentityPolicy
is unchanged; hosted-specific supplementary desktop groups are cleared
before the complete test suite by a trusted OS `setpriv` invocation, with
the original non-root UID/GID preserved and independently verified.

## Security boundaries remain separate

- **Manual self-hosted hardened security regression:** the existing
  `self-hosted-security.yml` workflow (manually dispatched from `main`)
  remains intact on disposable hardened Linux containers. The manual
  `inputs.ref` can select a non-main target revision: the operator must
  review and trust that exact target before dispatch; `github.ref=main`
  alone does **not** authenticate `inputs.ref`. These assert capability
  dropping, cgroup-v2 visibility, non-root status, no privilege escalation,
  Docker socket exclusion and complete dual-Python suite. GitHub-hosted
  job success does **not** demonstrate these VM/container properties.
- **Native no-network Level-3 E2E:** the existing
  `live-local-e2e.yml` only runs on merged `main`, after both hosted
  Python checks succeed, on a dedicated non-admin macOS x86 runner that
  launches no-network QEMU Ubuntu 26.04 guest at exact merged main SHA.
  Its checkpoint, provider-state cleanup and no-network isolation remain
  unchanged. PR-only checks are **not** native Level-3 evidence.
- **Deployment:** do not merge or change branch protection during an
  incomplete or failing required-check migration. Verify exact-head
  hosted matrix success and post-merge exact-main CI + native Level-3.
  Manual hardened security workflow should also run on trusted main
  before declaring security equivalence.

## Why this is more efficient

The old general CI ran two heavy Python suites sequentially on a single
ephemeral x86 Mac Docker runner, which queued PRs and contended with the
developer agent. Hosted VM execution is independent of the Mac's Docker
resources. Existing hosted exact-head baseline
[38294820787](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38294820787)
**PASSED both full suites**: Python 3.13 job 8m43s, 3.14 job
10m57s, workflow end-to-end 12m17s. That is not yet <10 minutes.

The independent [PR #216](https://github.com/zhangyuz/ssh-over-mcp/pull/216)
**PASSED** its four-way, fail-closed experiment in **10m08s** end-to-end.
The further six-way [PR #218](https://github.com/zhangyuz/ssh-over-mcp/pull/218)
also **PASSED 7/7** in **7m02s** end-to-end, splitting only the four most
expensive projection node IDs out of the original 611-node projection module.
Collection was checked: **611 = 4 hot + 607 other projection, 0 missing
and 0 duplicate**. Its success is an empirical Canary, not proof of
P95 under ten minutes. The new required-Python aggregate gates keep legacy
names and independently check the six-job `needs.validate.result` for
`success`; every failure, cancellation and skip must fail closed.

SOM is a **private repository**; standard hosted Linux minutes consume
account included usage, then bill at the published account-specific rate.
Six 15-minute shard caps and two 3-minute aggregate caps permit up to
96 hosted runner-minutes per attempt (excluding other workflows); typical
usage in the six-way green Canary was substantially lower. Check remaining
Actions quota and monitor billable usage before routine production rollout. Monitor queue time, measured test time, end-to-end
P95 (target <10 minutes), billing, and security regression outcomes.

**Rollback:** restore the original `.github/workflows/ci.yml` from the
pre-migration commit and its exact `tests/ops/test_ci_workflow.py` contract.
Do not disable native E2E or hardened security checks.


### Event-transition concurrency safety

While the pre-migration base branch still defines a legacy
`pull_request_target` CI, the updated `pull_request` workflow can fire on
the same PR. The new concurrency key includes the **event name** to avoid
the old base-branch run cancelling the new unprivileged hosted run:
`CI-pull_request-PR` is distinct from the old `CI-PR`. Both sets of checks
must complete honestly during the transition; duplicate check contexts
may appear until the base branch adopts the new workflow. Confirm branch
protection still requires both historical Python checks and inspect **all**
checks at exact PR HEAD before merging, including any legacy checks.
After merge, the main branch contains only the new pull-request CI trigger.
