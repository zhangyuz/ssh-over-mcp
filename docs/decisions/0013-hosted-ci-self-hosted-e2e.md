# ADR 0013: GitHub-hosted ordinary CI and self-hosted native E2E

## Status

Accepted migration, recorded 2026-10-12. PR #217 merged as
`2a00db8165e5a96ec70f779a3e8925938e1dc462`; PR #220 merged as
`39a4f868bb77b0391dbeeee5fb56d3cdb4ae3128`. This ADR records that
already-approved topology and supersedes the ordinary self-hosted-only rule
in development-methodology section 12. It authorizes no provider cleanup.

## Context

The full suites exceeded the old self-hosted job timeout and queued behind
one ephemeral runner. Four serial shards made feedback slower. Independent
hosted experiments preserved full coverage while reducing measured feedback.
The approved user direction was GitHub-hosted CI with self-hosted E2E.
The migration updated workflows and topology documentation but left the
normative development policy inconsistent; this ADR closes that documentation gap.

## Decision

Routine `pull_request` and `push:main` validation uses six GitHub-hosted
Ubuntu 26.04 x86 VMs: Python 3.13 and 3.14 each run three jointly exhaustive,
disjoint partitions (four exact projection hot nodes; remaining projection
nodes; all other tests), with xdist two workers per VM. New projection tests
enter the remainder partition. The complete `src`, `tests`, `ops/systemd` and `ops/live-e2e` trees
are linted and compiled. SHA-pinned actions, full Git history, read-only tokens and
strict non-root test identity remain required. PR checkout validates the
selected GitHub merge revision; main checkout validates the exact main SHA.

Both historical required contexts, `Ubuntu 26.04 x86 / Python 3.13` and
`Ubuntu 26.04 x86 / Python 3.14`, are always-running aggregate gates and fail
unless all six shards succeed. The dedicated self-hosted Intel macOS
orchestrator runs exact-main no-network Level-3 only after both gates pass.
Trusted-main authority, non-admin host identity, no-network disposable guest,
provider-state refusal and complete cleanup requirements from ADRs 0006 and
0008 remain unchanged.

Manual hardened Linux security regression remains a separate self-hosted
workflow. Its target must be independently reviewed and trusted; dispatching
from main does not authenticate the selected `inputs.ref`.

## Consequences

Hosted VM parallelism removes routine CI contention with Mac development and
Docker capacity. Private-repository hosted minutes consume account quota or
billable usage. Six 15-minute shards plus two 3-minute gates allow up to 96
runner-minutes per attempt, excluding other workflows.

Measure queue-inclusive hosted feedback from attempt start to the final
required gate, separately from native E2E and the overall main conclusion.
Report every attempt and the cohort used for percentiles; ten pilot samples
cannot prove a stable population P95. Rollout is not fully accepted while
native Level-3 or hardened security evidence remains missing or failed.
Branch-protection API access is currently unavailable on the private-repo plan;
retaining names alone is not proof that GitHub enforces the checks.

Historical plans remain historical evidence. Their former self-hosted-only
instructions are superseded for future routine CI by this ADR. Rollback must
restore the pre-migration workflow and matching contracts without disabling
native E2E or hardened security requirements.

## Security impact

Untrusted PR code runs on disposable hosted VMs through `pull_request`, without
PR secrets or write tokens. No `pull_request_target` execution is added.
Hosted-specific supplementary groups are cleared using OS `setpriv` while
preserving the original non-root UID/GID; product assertions are unchanged.
This test-process identity check does not claim that the hosted VM account
lacks sudo or can never obtain root.
Hosted PASS does not establish hardened Docker capabilities/cgroup properties,
native containment, provider provenance or cleanup success. No unknown
provider artifacts may be reused, deleted or normalized by this decision.
