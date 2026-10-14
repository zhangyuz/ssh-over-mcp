# ADR 0020: Trusted PR admission for automated native Level-3 E2E

- Status: **Proposed for operator review — not approved or activated**
- Date: 2026-10-14 (America/Toronto)
- Base: main 64f74b8cc534eda9aa211dbfd0fb109a7039a820
- Design: [Local Live E2E vNext](../superpowers/specs/2026-10-14-local-live-e2e-vnext-design.md)

## Context

Existing hosted CI validates a full dual-Python suite on ordinary pull_request events, including ready_for_review, without privileged runners. A trusted-main native workflow uses a dedicated non-admin Intel Mac, QEMU/HVF and a no-network guest only after merging main or deliberate manual target dispatch. Developers seek pre-merge native acceptance without new Mac exposure or slow manual coordination.

The repository is currently **public**, forks are allowed, and some CI topology text still incorrectly describes a private repository. The GitHub API result for CI on a PR may have an empty pull_requests association. A workflow_run may hold elevated permissions; it must never treat earlier untrusted CI output as trusted commands. ADR 0019's protected staging remains dormant and its lifecycle/activation authority is separate.

## Proposed decision

Keep the existing isolated native test provider and main-push CI. Introduce a separately reviewed trusted-main GitHub-hosted workflow_run admission layer that records metadata from completed-success ordinary CI for an **exact current same-repository non-draft PR head** after full run/job/attempt, SHA, repository and branch verification. This is explicitly **shadow observation only**, not trusted-suite execution proof: candidate PRs may alter CI workflow/test commands while preserving ten expected green job names. Failing or ambiguous association refuses; never infer an exact target from the workflow_run default-branch github.sha. Fork PRs do not automatically allocate the Mac; future maintainer authorization must bind the exact SHA and PR identity.

Only after explicit approval, completed ADR 0019 protected-placement acceptance, and a **separate pinned trusted-main CI verifier on disposable GitHub-hosted runners** (trusted procedure and test manifest independent of PR workflow edits) may an exact target be considered for native dispatch. The approved future event transport is a narrow trusted-hosted `actions: write` dispatch into an already-main **`workflow_dispatch` broker**, whose hosted gate revalidates immutable SHA, current PR/base and trusted-verifier proof before invoking the existing native reusable E2E workflow. Direct `workflow_run` reuse is incompatible with the actual Mac `GITHUB_EVENT_NAME` allow-list (`push` and `workflow_dispatch` only) and must not be enabled with a blanket allow-list change. The broker must refuse forged, stale, replayed or PR-origin dispatch inputs. Only then may the existing reusable E2E workflow send the pinned target into a fresh disposable no-network guest. Candidate PR code never executes on the persistent Mac. Strict one-guest concurrency and fail-closed provider cleanup remain mandatory. Separate minimum-permission hosted status reporting may attest the exact SHA only after verified guest and cleanup success. A GitHub status is evidence for exact bytes, **never PR-bound authorization**. Even a required status with selected source could be inherited by another PR, including a fork with identical SHA. Therefore the reporter stays informational; any enforced native merge gate must be a separately specified, independently verifiable **PR-bound receipt/check** and tested against two distinct PRs with identical SHA before admin-reviewed branch protection/ruleset activation.

Use independently reviewed delivery slices: metadata-only shadow; ADR 0019 owned lifetime; already-main protected placement activation; trusted-main hosted test-procedure verifier; workflow_dispatch broker/native caller; **separate** informational status writer; then a separately designed PR-bound merge gate and admin-confirmed enforcement.

## Consequences and rollback

Adds extra GitHub API validation, a trusted test-procedure verifier, a scoped hosted dispatch permission, queue management, race/stale-result regression requirements and separately scoped informational status-write permission. Positive side: pre-merge native feedback with existing infrastructure, without exposing capability-bearing candidate code to the Mac host or requiring a new service. Initial phase creates no native dispatch or automatic merge authority. Unknown cleanup blocks rather than retries. If a later rollout is unhealthy, disable only the new admission/status and revert the new required context through authorized repository administration; preserve existing manual and merge-main native validation.

Performance goals are measured separately for fast local, hosted feedback and native execution; no security shortcut is authorized in order to meet a time target.

## Security impact

Reject fork auto-execution, untrusted workflow/artifact execution, forged PR association, incomplete/mixed-attempt CI proof, old-head replay, duplicate uncontrolled allocation, status forgery, implicit guest cleanup, historical residual deletion, and root/admin privilege on ordinary runners. Grant `statuses: write` only to a trusted hosted reporting job, `actions: write` only to a trusted hosted dispatch step, and neither to the Mac provider. Add explicit modified-CI/ten-green-names and two-PR/same-SHA adversarial tests before any authority increase. Protected staging keeps ADR 0019 authority and distinct acceptance proof.

This ADR is **not an authorization** to activate a native runner trigger, grant status write permissions, alter branch protection or modify a persistent provider.
