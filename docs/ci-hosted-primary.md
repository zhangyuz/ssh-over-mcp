# Primary CI on GitHub-hosted; native E2E on self-hosted

## Proposed execution topology

Routine `pull_request` (including fork PRs) and `push:main` execute
the same **full** Python 3.13 and 3.14 test collection on six independent
standard GitHub-hosted Ubuntu 26.04 x86_64 VMs (private repo standard
2 vCPU / 8 GB each). Each Python version's complete suite is partitioned
into four hot source-bound projection cases, the other 607 source-bound
projection cases (as of first Canary), and every test outside that module.
The test matrix executes **3 shards per Python**, each with a 15-minute
timeout, `pytest-xdist -n 2 --dist=load`, complete Ruff/compile operator
coverage, full Git history, strict non-root test identity and SHA-pinned
official actions. The test partitions are disjoint and cover the whole
default suite, including future tests outside the four fixed hot node IDs.
A pair of fail-closed post-matrix gates retains the original required
check **names**:

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

Hosted experiments established both correctness and speed:
[PR #216 / run 38297317913](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38297317913)
passed four independent disjoint source partitions plus gate in **10m08s**.
[PR #218 / run 38300258158](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38300258158)
passed six independent disjoint source partitions plus gate in **7m02s**.
Local pytest collection proved **611 projection cases = 4 hot + 607 rest**.
This PR stages that tested six-way partition into primary CI with two
**historical-name, fail-closed required gates**, plus original exact-main
no-network E2E dependency. The gate test checks the entire six-shard result;
failure, cancellation or skip of any shard fails **both** required gates.
Successful optional Canary alone is not sufficient: production exact-head
dual Required Check PASS and postmerge exact-main native Level-3 remain
mandatory.

SOM is a **private repository**; standard hosted Linux minutes consume
account included usage, then bill at the published account-specific rate.
Six 15-minute shards plus two 3-minute gates can consume up to 96
hosted runner-minutes in a timeout-heavy failed run (excluding other
workflows), and are expected to be much lower when green. Monitor queue time, measured test time, end-to-end
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
