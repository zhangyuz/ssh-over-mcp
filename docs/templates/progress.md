# Agent worktree handoff — progress.md

> Copy this template to `progress.md` at the **root of your active worktree**.
> Update it after meaningful checkpoints and before handing over.
> This local file is Git-ignored. It is not a source of approval or acceptance.
> Do not store tokens, credentials, private keys, or other secrets.

## Identity and scope

- Updated at (UTC):
- Owner/agent role:
- Worktree absolute path:
- Branch:
- HEAD (full SHA):
- PR/issue links:
- Objective and one independently verifiable deliverable:
- In scope:
- Out of scope:

## Authority and approvals

| Action or boundary | Status (APPROVED / HOLD / DENIED / NOT REQUIRED) | Exact source and scope |
| --- | --- | --- |
| Approved development scope | | |
| Host/privilege/trust-root changes | | |
| Merge or release | | |

Never infer an approval from this table. Recheck the cited authoritative decision.

## Verified checkpoints

| Exact SHA / environment | Command or evidence URL | Result (PASS / FAIL / SKIPPED / PENDING / UNVERIFIED) |
| --- | --- | --- |
| | | |

Differentiate focused tests, full regression, exact PR-head CI, independent review, native E2E, and exact merge-main CI. A past SHA does not certify the current HEAD.

## Active changes and review

- Modified/uncommitted files:
- Latest implementation milestone:
- Open Critical/Important/Minor findings:
- Author self-review:
- Independent review and reviewed SHA:
- Relevant ADR/spec/runbook/document alignment:

## Blockers, deferred gates, and shared resources

- Current blocker (evidence vs assumption):
- Explicitly deferred issue/owner/acceptance gate:
- Concurrent agents/worktree owners:
- Shared runner/Mac/guest/container/process state (read-only observations):
- Cleanup pending or completed (exact evidence):

## Next executable action

1. Immediate safe action:
2. Required evidence and check:
3. Next operator approval decision, if any:

## Session exit checklist

- [ ] Latest status checked against actual git/PR state
- [ ] Relevant local and CI evidence recorded with exact SHA
- [ ] Permissions/denials and outstanding gates preserved
- [ ] PR/issue comments or canonical docs updated for durable decisions
- [ ] Concurrent worktrees and privileged resources left undisturbed
