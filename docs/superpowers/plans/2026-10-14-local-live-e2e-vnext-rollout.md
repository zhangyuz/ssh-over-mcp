# Local Live E2E vNext — staged rollout and review gates

**Status:** Proposed roadmap for operator review; not an approved operational rollout.
**Baseline:** `main` at `64f74b8cc534eda9aa211dbfd0fb109a7039a820`; design Draft PR #244.
**Design authority:** [vNext design](../specs/2026-10-14-local-live-e2e-vnext-design.md), [proposed ADR 0020](../../decisions/0020-trusted-pr-native-e2e-admission.md), [existing ADR 0019](../../decisions/0019-protected-native-e2e-staging.md).

## Deliveries and acceptance

| Slice | Standalone reviewable deliverable | Acceptance | Explicitly excluded |
| --- | --- | --- | --- |
| 0 — written design | Draft PR #244 design, ADR proposal, visibility correction and this roadmap | Operator reviews spec and first plan together | Native dispatch/status write, Mac cleanup |
| 1 — metadata shadow (not CI attestation) | [Detailed implementation plan](2026-10-14-pr-native-e2e-shadow-admission.md): trusted-main completed-CI listener and pure PR/CI metadata cross-check using bounded read-only GitHub API | Test-first identity, API/rerun, workflow contract tests; honest METADATA_MATCH_SHADOW/REFUSE on real canary CI after merge; zero native jobs or commit statuses | Mac allocation, fork approval, success attestation, ruleset changes |
| 2 — protected owned lifetime | Separate ADR 0019 plan: fixed original-FD-bound workspace handles and explicit cleanup | Real UID-502/APFS ACL fixtures, unsafe-state/cleanup refusal, exact-head legacy gate | Runtime placement activation, PR automation |
| 3 — protected placement activation | Separate ADR 0019 plan replacing live temp selectors/free-space/recovery routes on trusted main | Actual native UID-502 no-network guest uses fixed protected root; both protected+legacy residual refusal and verified cleanup | PR trigger; claiming A1/B8/N1c closed without proof |
| 4 — trusted-main hosted CI verifier | Main-pinned runner procedure and required test-manifest run against exact candidate source in ephemeral hosted VM; output bound to PR/SHA/base/verifier revision | Modified PR CI with ten green names cannot become full-suite proof; trusted-case completeness, SHA/base and verifier identity verified | Mac allocation, candidate-controlled test manifest |
| 5 — trusted workflow_dispatch broker/native caller | After trusted verifier, hosted dispatcher with step-scoped actions:write calls a dedicated already-main workflow_dispatch broker; broker rechecks exact PR/CI/verifier then calls existing reusable E2E | Actual allowed event context, forged/direct/stale dispatch rejection, true guest+cleanup canary | Adding workflow_run to Mac allow-list, write token on Mac, required status |
| 6 — hosted informational SHA reporter | Separate minimal-token hosted reporter posts pending/success/failure/error for tested SHA and audited evidence | Real GitHub status on SHA never success on failure/stale/unknown cleanup; cross-PR same-SHA risk remains | Treating SHA status as PR-specific merge approval |
| 7 — PR-bound enforcement (new design required) | Separate reviewed PR-specific receipt/merge gate, then administrator-verified ruleset binding | Two distinct PRs with same SHA (one eligible, one fork): fork remains blocked despite green SHA status; pass/fail/stale/cancel canaries | SHA-only required status as authorization; silent admin changes |

## Gates and ordering

1. **Written design + implementation plan review** precede product code. Approval for one slice does not authorize subsequent ones.
2. **Shadow first:** no persistent Mac side effect. GitHub's `workflow_run.pull_requests` may be empty and default checkout SHA is not PR head; the validator must use fresh bounded GitHub API association and verify SHA, exact attempt and job completeness. A PR can edit its CI workflow to emit ten green expected names without running trusted tests: shadow output is **only metadata matching**, with `trusted_suite_proven=false`, **not** authenticated full-suite success or native authority.
3. **ADR 0019 owned lifetime and activation before automatic native allocation**, unless the operator separately approves a revised security decision. PR #243 inspection is dormant; successful old-path E2E is not protected-path acceptance.
4. **Trusted CI verifier is required before native allocation:** a separate pinned already-main hosted workflow/test manifest executes against candidate source on an ephemeral runner. PR-supplied CI job names, steps or test commands are insufficient.
5. **Caller and reporter are separate authority boundaries:** dispatch uses step-scoped `actions: write` on a hosted agent to call a trusted-main `workflow_dispatch` broker which revalidates current PR/SHA/verifier proof; broker calls the existing reusable native E2E. The Mac orchestrator accepts only push/workflow_dispatch and MUST NOT gain generic workflow_run permission. The separate hosted reporter alone may get `statuses: write`; Mac receives neither.
6. **SHA status cannot enforce per-PR trust:** until another ADR specifies and tests a real PR-bound merge gate, the SHA status remains informational. Same-SHA two-PR (eligible + fork) must fail closed on fork, regardless of green SHA status.
7. **PR-bound enforcement and admin confirmation are distinct prerequisites.** At design time rulesets API was empty and branch-protection read returned 403. A required SHA status/check source alone is insufficient; a separately reviewed PR-specific receipt/gate and real fork/same-SHA test must precede activation.
8. **Historical/provider boundaries unchanged:** no generic recovery, unwanted runner privilege, mass cleanup, or rewriting ADRs 0011/0012/0018. Existing manual exact-target and main-push CI/native remain working throughout.

## Shared evidence and performance targets

- L0: focused local RED→GREEN checks and Mac-only isolated ACL fixtures where relevant; target under 60 seconds, never called Level-3.
- L1: complete GitHub-hosted Python 3.13/3.14 with eight exhaustive partitions and both required contexts; queue-inclusive P95 target below 10 minutes, measured with full attempts including failures.
- L2: dedicated non-admin Intel Mac on existing trusted-main QEMU/HVF no-NIC/no-share fresh Ubuntu guest; healthy stage P95 target at most 5 minutes **excluding queue**, not a current guarantee.
- L3: exact merged-main hosted and native success plus provider absence and cleanup evidence; record SHA, run ID, attempt, review and disposal in `progress.md`.

Every implementation slice must show meaningful RED→GREEN, focused and full regression, adversarial tests, fresh independent security/code/doc review, exact PR SHA evidence, exact-main verification and owned-only worktree cleanup. Do not duplicate full tests already running in another agent worktree.

## Failures and rollback

- Shadow misclassification/API ambiguity: disable shadow workflow; ordinary CI and existing native E2E remain intact.
- Unknown native provider/cleanup: block new jobs; no implicit retry, chmod, marker reset or foreign/history deletion.
- Later informational-status or PR-bound-rule faults: security-reviewed rollback of new admission/reporting plus authorized PR-bound protection adjustment; no SHA-only gate can replace PR authorization. Never silently drop an existing main gate.

## Operator review decisions

1. Same-repository PRs are initially eligible for metadata-only shadow; native eligibility additionally requires trusted-main test-procedure proof; fork PRs require a future independent exact-SHA maintainer authorization design.
2. Protected staging must pass true UID-502 native acceptance before default automatic Mac dispatch; a read-only metadata shadow is permitted before that.
3. The new SHA-native status stays informational; separate PR-bound authorization receipt/check and same-SHA two-PR fork canary are required even if a ruleset pins the status source.
4. Each delivery is a separate PR with its own review/rollback, not one large unreviewable automation merge.
