# Local Live E2E vNext — staged rollout and review gates

**Status:** Proposed roadmap for operator review; not an approved operational rollout.
**Baseline:** `main` at `64f74b8cc534eda9aa211dbfd0fb109a7039a820`; design Draft PR #244.
**Design authority:** [vNext design](../specs/2026-10-14-local-live-e2e-vnext-design.md), [proposed ADR 0020](../../decisions/0020-trusted-pr-native-e2e-admission.md), [existing ADR 0019](../../decisions/0019-protected-native-e2e-staging.md).

## Deliveries and acceptance

| Slice | Standalone reviewable deliverable | Acceptance | Explicitly excluded |
| --- | --- | --- | --- |
| 0 — written design | Draft PR #244 design, ADR proposal, visibility correction and this roadmap | Operator reviews spec and first plan together | Native dispatch/status write, Mac cleanup |
| 1 — shadow admission | [Detailed implementation plan](2026-10-14-pr-native-e2e-shadow-admission.md): trusted-main completed-CI listener and pure PR/CI admission proof using bounded read-only GitHub API | Test-first identity, API/rerun, workflow contract tests; honest ADMIT/REFUSE on real canary CI after merge; zero native jobs or commit statuses | Mac allocation, fork approval, success attestation, ruleset changes |
| 2 — protected owned lifetime | Separate ADR 0019 plan: fixed original-FD-bound workspace handles and explicit cleanup | Real UID-502/APFS ACL fixtures, unsafe-state/cleanup refusal, exact-head legacy gate | Runtime placement activation, PR automation |
| 3 — protected placement activation | Separate ADR 0019 plan replacing live temp selectors/free-space/recovery routes on trusted main | Actual native UID-502 no-network guest uses fixed protected root; both protected+legacy residual refusal and verified cleanup | PR trigger; claiming A1/B8/N1c closed without proof |
| 4 — trusted automatic native caller | Current eligible same-repo PR HEAD admitted by trusted main after complete hosted CI; pinned SHA queued for isolated guest | Replay/fork/duplicate/cancel/crash tests and true native canary; no host candidate execution | Automatic merge, Mac write tokens, implicit cleanup, required status |
| 5 — hosted status reporter | Separate minimal-token hosted reporter posts pending/success/failure/error for the tested SHA and audited evidence | Real GitHub status on tested SHA, never success on failed/stale/skip/unknown cleanup; cross-PR same-SHA risks documented | Treating SHA status as PR-specific approval |
| 6 — required-check enforcement | Authorized admin verifies ruleset/protection binding to intended status context and source | Live canary pass/fail/cancel/rebased/fork proves actual merge gate; post-merge main accepted | Silently changing repository administration |

## Gates and ordering

1. **Written design + implementation plan review** precede product code. Approval for one slice does not authorize subsequent ones.
2. **Shadow first:** no persistent Mac side effect. GitHub's `workflow_run.pull_requests` may be empty and default checkout SHA is not PR head; the validator must use fresh bounded GitHub API association and verify SHA, exact attempt and job completeness. Shadow output is **not** a certified E2E status.
3. **ADR 0019 owned lifetime and activation before automatic native allocation**, unless the operator separately approves a revised security decision. PR #243 inspection is dormant; successful old-path E2E is not protected-path acceptance.
4. **Caller and reporter are separate authority boundaries:** one allocates scarce Mac compute, the other can influence branch merge policy. The first uses a trusted-main reusable E2E with candidate code only inside the guest; the second receives minimally scoped `statuses: write` only on GitHub-hosted VM.
5. **Enforcement requires actual repository-admin confirmation.** At design time rulesets API was empty and branch-protection read returned 403. A status alone is not a required check; forks remain fail closed until separately reviewed exact-SHA maintainer approval.
6. **Historical/provider boundaries unchanged:** no generic recovery, unwanted runner privilege, mass cleanup, or rewriting ADRs 0011/0012/0018. Existing manual exact-target and main-push CI/native remain working throughout.

## Shared evidence and performance targets

- L0: focused local RED→GREEN checks and Mac-only isolated ACL fixtures where relevant; target under 60 seconds, never called Level-3.
- L1: complete GitHub-hosted Python 3.13/3.14 with eight exhaustive partitions and both required contexts; queue-inclusive P95 target below 10 minutes, measured with full attempts including failures.
- L2: dedicated non-admin Intel Mac on existing trusted-main QEMU/HVF no-NIC/no-share fresh Ubuntu guest; healthy stage P95 target at most 5 minutes **excluding queue**, not a current guarantee.
- L3: exact merged-main hosted and native success plus provider absence and cleanup evidence; record SHA, run ID, attempt, review and disposal in `progress.md`.

Every implementation slice must show meaningful RED→GREEN, focused and full regression, adversarial tests, fresh independent security/code/doc review, exact PR SHA evidence, exact-main verification and owned-only worktree cleanup. Do not duplicate full tests already running in another agent worktree.

## Failures and rollback

- Shadow misclassification/API ambiguity: disable shadow workflow; ordinary CI and existing native E2E remain intact.
- Unknown native provider/cleanup: block new jobs; no implicit retry, chmod, marker reset or foreign/history deletion.
- Later status/ruleset faults: security-reviewed rollback of new admission/reporting and administrator-authorized required-check adjustment. Never silently drop an existing main gate.

## Operator review decisions

1. Same-repository PRs are initially eligible for automated native proof; fork PRs require a future independent exact-SHA maintainer authorization design.
2. Protected staging must pass true UID-502 native acceptance before default automatic Mac dispatch; a read-only metadata shadow is permitted before that.
3. The new PR-head status remains informational until independently tested GitHub ruleset/protection enforcement.
4. Each delivery is a separate PR with its own review/rollback, not one large unreviewable automation merge.
