# Primary CI on GitHub-hosted; native E2E on self-hosted

## Proposed execution topology

Routine `pull_request` (including fork PRs) and `push:main` execute
the same **full** Python 3.13 and 3.14 test collection on independent
standard GitHub-hosted Ubuntu 26.04 x86_64 VMs (private repo standard
2 vCPU / 8 GB each). Each retains a 20-minute timeout, complete pytest,
`pytest-xdist -n 2 --dist=load`, complete Ruff/compile operator coverage,
full Git history (needed by exact binding regressions), strict non-root test
identity and immutable SHA-pinned official actions. The existing required
check **names** are retained:

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
  `self-hosted-security.yml` workflow (trusted main only) remains fully
  intact on disposable hardened Linux containers. These assert capability
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

The independently staged [PR #216](https://github.com/zhangyuz/ssh-over-mcp/pull/216)
benchmarks disjoint projection/rest source partitions on four independent
hosted VMs, with an always-run fail-closed gate. This primary CI topology
change initially selects the already proven **two full suites**; do not
deploy the faster sharded approach until a successful exact-head Canary and
test coverage comparison, and the two historical required check contexts
must remain fail-closed after any subsequent job split.

SOM is a **private repository**; standard hosted Linux minutes consume
account included usage, then bill at the published account-specific rate.
Two 20-minute jobs are at most 40 hosted runner-minutes per run (excluding
any other workflows). Monitor queue time, measured test time, end-to-end
P95 (target <10 minutes), billing, and security regression outcomes.

**Rollback:** restore the original `.github/workflows/ci.yml` from the
pre-migration commit and its exact `tests/ops/test_ci_workflow.py` contract.
Do not disable native E2E or hardened security checks.
