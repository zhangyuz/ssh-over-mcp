# ADR 0020: Trusted PR admission for automated native Level-3 E2E

- Status: **Proposed for operator review — not approved or activated**
- Date: 2026-10-14 (America/Toronto)
- Base: main 64f74b8cc534eda9aa211dbfd0fb109a7039a820
- Design: [Local Live E2E vNext](../superpowers/specs/2026-10-14-local-live-e2e-vnext-design.md)

## Context

Existing hosted CI validates a full dual-Python suite on ordinary pull_request events, including ready_for_review, without privileged runners. A trusted-main native workflow uses a dedicated non-admin Intel Mac, QEMU/HVF and a no-network guest only after merging main or deliberate manual target dispatch. Developers seek pre-merge native acceptance without new Mac exposure or slow manual coordination.

The repository is currently **public**, forks are allowed, and some CI topology text still incorrectly describes a private repository. The GitHub API result for CI on a PR may have an empty pull_requests association. A workflow_run may hold elevated permissions; it must never treat earlier untrusted CI output as trusted commands. ADR 0019's protected staging remains dormant and its lifecycle/activation authority is separate.

## Proposed decision

Keep the existing isolated native test provider and main-push CI. Introduce a separately reviewed trusted-main GitHub-hosted workflow_run admission layer that recognizes only completed-success ordinary CI for an **exact current same-repository non-draft PR head** after full run/job/attempt, SHA, repository and branch verification. Failing or ambiguous association refuses; never infer an exact target from the workflow_run default-branch github.sha. Fork PRs do not automatically allocate the Mac; future maintainer authorization must bind the exact SHA and PR identity.

Only after explicit approval and subsequent security-reviewed implementation may a trusted main reusable E2E workflow dispatch the pinned target into a fresh disposable no-network guest. Candidate PR code never executes on the persistent Mac. Strict one-guest concurrency and fail-closed provider cleanup remain mandatory. Separate minimum-permission hosted status reporting may attest the exact SHA only after verified guest and cleanup success. A GitHub status is evidence for exact bytes, not proof of PR authorization; branch protection or ruleset enforcement must be independently verified and enabled.

Use staged independent delivery: admission shadow only; separately approved ADR 0019 owned protected staging lifetime; already-main protected placement activation and native proof; then pre-merge automatic caller/status and optional actual required-check enforcement.

## Consequences and rollback

Adds extra GitHub API validation, queue management, race/stale-result regression requirements and carefully scoped status-write permission. Positive side: pre-merge native feedback with existing infrastructure, without exposing capability-bearing candidate code to the Mac host or requiring a new service. Initial phase creates no native dispatch or automatic merge authority. Unknown cleanup blocks rather than retries. If a later rollout is unhealthy, disable only the new admission/status and revert the new required context through authorized repository administration; preserve existing manual and merge-main native validation.

Performance goals are measured separately for fast local, hosted feedback and native execution; no security shortcut is authorized in order to meet a time target.

## Security impact

Reject fork auto-execution, untrusted workflow/artifact execution, forged PR association, incomplete/mixed-attempt CI proof, old-head replay, duplicate uncontrolled allocation, status forgery, implicit guest cleanup, historical residual deletion, and root/admin privilege on ordinary runners. Grant statuses:write only to a trusted hosted reporting job, never the Mac provider. Protected staging keeps ADR 0019 authority and distinct acceptance proof.

This ADR is **not an authorization** to activate a native runner trigger, grant status write permissions, alter branch protection or modify a persistent provider.
