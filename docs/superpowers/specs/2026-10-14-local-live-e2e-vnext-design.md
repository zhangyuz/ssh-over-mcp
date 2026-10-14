# Local Live E2E vNext: trusted PR admission and native acceptance

Status: **proposed design for operator review; not implemented or authorized for activation**.
Date: 2026-10-14 (America/Toronto).
Baseline: main 64f74b8cc534eda9aa211dbfd0fb109a7039a820 (PR #243).
Decision record: [ADR 0020](../../decisions/0020-trusted-pr-native-e2e-admission.md) (proposed).
Related authority: [ADR 0006](../../decisions/0006-full-e2e-trust-model.md), [ADR 0008](../../decisions/0008-level3-e2e-no-network-guest.md), [ADR 0013](../../decisions/0013-hosted-ci-self-hosted-e2e.md), [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md).

## 1. Intent and success

The operator wants a reliable and efficient **Local Live E2E** system, not merely another CI trigger. Preserve small, reviewed feature slices and fast local feedback while making genuine native Linux/kernel/privilege behavior testable before merging PRs. An automated result may only assert what actually ran, under which authority, at which exact commit, and whether all disposable resources were verified absent.

Success is independent of rollout order:

- Developer can run focused checks locally without affecting the dedicated native provider, with a target of under 60 seconds for the focused path. This is NOT Level-3 acceptance.
- Normal PR CI remains on unprivileged GitHub-hosted Ubuntu 26.04, with all eight exhaustive partitions and both Python aggregate gates. Target: measured queue-inclusive P95 under 10 minutes; no coverage cuts.
- Eligible, current, same-repository non-draft PRs with a reported successful hosted CI run can be **observed in shadow mode** by already-merged trusted-main code. CI job names and success alone do not prove that the expected trusted procedure executed. Public fork PRs receive hosted CI but NOT automatic persistent-Mac execution.
- Native Level-3 runs the specified exact PR HEAD inside a new disposable, no-network, no-host-share QEMU guest; the persistent Mac account never checks out or executes candidate product/workflow code.
- PR status is reported against its exact tested SHA, only after the trusted guest gate, business assertions, and host/guest cleanup pass. No status or ambiguous result is never success.
- Every accepted merge still receives exact merged-main hosted CI plus native Level-3 and cleanup evidence. The result must be independently reviewable by run URL, SHA, authority version and immutable provider facts.
- Activation and completion of protected staging under ADR 0019 remain independently proven, not inferred from successful legacy-placement E2E.

The approved **high-level direction** is layered validation and trusted-main admission. This written specification requires its own operator review, implementation plan and security review before workflow behavior changes.

## 2. Verified baseline and non-goals

Current work: CI already runs on pull_request(opened, synchronize, reopened, ready_for_review) and push(main). Eight GitHub-hosted test partitions feed required Python 3.13/3.14 aggregate jobs. The main-push-only Level-3 job calls the existing reusable Live Local E2E workflow and waits for both required jobs. Manual workflow_dispatch also exists. The native workflow uses a dedicated non-admin Intel Mac, QEMU/HVF and a disposable Ubuntu 26.04 guest. Successful post-merge #243 run 38511642846 verified native job 115682323661 and provider marker absence at exact main 64f74b8. It did NOT execute new protected workspace placement.

Actual GitHub repository metadata on 2026-10-14 says repository **public**, forks allowed. The older CI topology document's private-repository statements are stale. GitHub API returned an empty ruleset list; branch-protection read was forbidden to the connected integration. Neither confirms an enforced E2E merge gate.

ADR 0019 currently has a dormant, read-only namespace-inspection module. Production orchestration still relies on legacy tempfile placement. Owned workspace lifetime, already-main protected placement activation, native UID-502 inspection and A1/B8/N1c closure are distinct open gates.

Non-goals: a new externally hosted orchestration service, elastic Mac fleet, reusable guest snapshots with candidate state, process-root capabilities, ordinary CI privilege changes, historical residual deletion, policy/SSH product changes, or silent ruleset edits. No assumption that a GitHub status by itself authorizes a PR.

## 3. Architecture and ownership boundaries

| Layer | Owner and responsibility | Proof required |
| --- | --- | --- |
| L0 fast development | Normal local developer account; focused unit/contracts, native disposable ACL fixtures if applicable | Exact tests and local worktree identity; never call it Level-3 |
| L1 hosted CI | Unprivileged GitHub pull_request VM; entire 3.13 and 3.14 suite and lint | All 8 named shards and both required aggregate jobs genuinely pass |
| L2 metadata + trusted verification | Default-branch trusted hosted metadata observer; later separate already-main verification gate | Shadow only matches GitHub metadata; actual trusted suite execution must be independently proven before dispatch |
| L3 native Level-3 | Existing trusted main reusable workflow on dedicated non-admin UID-502 Intel Mac | No candidate code on host; new no-network VM; bounded trusted serial result |
| L4 result/status | Separate trusted hosted reporter with commit-status write only | Status for tested PR HEAD, correct context, live state recheck and evidence URL |
| L5 merge-main acceptance | Unchanged trusted main-push hosted + native acceptance | Exact merge-main job success and resource absence |

The actual local developer machine and the persistent Mac E2E runner might be physically colocated, but their permissions, user accounts, run roots, processes and lifecycle remain separate. GitHub-hosted PR work never receives the native runner's labels or credentials.

### 3.1 Trust graph

PR author-controlled code or text -> unprivileged hosted CI. Hostile PR data is NOT executable authority. The resulting GitHub CI run metadata is read as data through bounded authenticated GitHub API calls by a workflow whose definition is already on the default branch. Successful **shadow matching** yields only (repository identity, PR number, exact immutable 40-hex head SHA, CI run/attempt) and fixed flags `trusted_suite_proven=false`, `base_freshness_proven=false`, `dispatch_authorized=false`. It never yields a host path, command, runner label, environment override or candidate workflow script.

Trusted hosted verifier -> dedicated **trusted-main `workflow_dispatch` broker** -> pre-existing trusted-main reusable native workflow -> Mac orchestrator -> candidate source transferred through a bounded Git bundle into the disposable guest. No guest NIC, host share, or secret/token transfer. Trusted read-only root guest gate validates the target's results; product code cannot redefine the gate that accepts itself. Guest and host disposal are mandatory and not inferred from green application output.

Only the L4 hosted reporter gets `statuses: write`; a separate trusted hosted dispatch step MAY receive narrowly scoped `actions: write` after slice-4 approval. The L3 Mac job retains `contents: read` and receives neither write permission nor repository secrets.

### 3.2 Exact-sha admission and TOCTOU

Admission accepts only a **completed successful** CI workflow_run event whose canonical workflow ID/path, repository ID/name, triggering event type (pull_request), attempt number and complete run metadata match independently fetched GitHub API records. The workflow_run payload can have an empty pull_requests list. Resolve candidate PRs independently from the exact commit via bounded paginated API, then fetch each live PR. Require exactly one matching currently open non-draft PR whose base is this repository/main, head repository ID matches this repository, head ref matches the run branch, and head SHA exactly matches the immutable run SHA. Zero, more than one, inability to exhaust pages, API failure, absent identity, changed PR, fork, or stale run: refuse. Do not derive the target from github.sha (the trusted default branch for workflow_run), from a user-supplied PR number, or from a mutable branch name.

Re-read the complete upstream CI job set for that run/attempt (paginate or fail closed). Require exactly eight separately named successful test partitions, both historical required Python aggregate jobs, and no duplicated/missing/failed/cancelled/skipped required job; ensure the run conclusion is success. The PR-only merge-main native job being skipped is expected and not native evidence. Treat partial reruns/attempt mixing as unsafe unless an explicit complete-attempt proof is implemented and tested.

### 3.2.1 CI metadata is not trusted-suite attestation

A same-repository PR may edit `.github/workflows/ci.yml` and invoked test commands, retain the workflow identity plus all eight shard/two aggregate job names, and return green without running the intended suite. The GitHub `workflow_run`/jobs API proves **reported metadata**, not trusted test execution. The first shadow slice MUST emit `METADATA_MATCH_SHADOW` (never `FULL_CI_PROVEN`), with immutable `trusted_suite_proven=false` and `dispatch_authorized=false`; even a modified-CI/ten-green-names fixture remains **non-authoritative**. Do not promote a shadow verdict or GitHub status to native authorization.

Before native auto-dispatch, a separately reviewed **trusted-main verification gate** MUST execute a pinned main-owned workflow and trusted regression-case manifest against the exact candidate source in a disposable GitHub-hosted VM (never on Mac). Fetch the candidate as untrusted source; do not let PR-controlled workflow/test scripts replace or shrink the trusted-main procedure. Candidate-supplied new tests are supplemental only. Persist and authenticate (repository ID, PR number, candidate HEAD SHA, current base revision, main verifier SHA, trusted manifest digest, verification run ID/attempt and pass/fail + complete required case set). Re-fetch and bind these values in the later broker; base/HEAD/verified manifest drift, hostile PR workflow edits, missing cases, or any unverifiable result MUST block. A green PR workflow by itself is insufficient even when steps or job names look normal. The exact trusted-verifier implementation requires its own reviewed plan/PR, and its full test fixtures must demonstrate modified candidate CI remaining ineligible for auto dispatch.

### 3.2.2 Approved future transport matches the current Mac event allow-list

The current trusted Mac orchestrator `_validated_workflow_context` accepts `GITHUB_EVENT_NAME` only `push` or `workflow_dispatch`, and additionally requires `GITHUB_REF=refs/heads/main`, expected repository/source and a checked-out trusted main SHA. A reusable workflow retains the caller's event context: **direct `workflow_run -> workflow_call -> live-local-e2e.yml` would fail before guest creation** and MUST NOT be used or worked around by adding blanket `workflow_run` support on the Mac.

After the independently verified hosted gate, use one step-scoped `actions: write` token **only in a trusted GitHub-hosted dispatcher** to trigger a separate, already-main **`workflow_dispatch` broker workflow**. Its input values (PR number, SHA, CI/verifier run IDs and attempts) are untrusted hints, not proof. The broker runs read-only hosted revalidation of live PR, current HEAD/base, complete CI metadata, and trusted-main verifier identity/manifest/evidence. Only after this fresh authentication may it call `live-local-e2e.yml` as a reusable job with the exact pinned commit SHA; the called Mac job then sees allowed `workflow_dispatch` event and trusted `main` GITHUB_SHA. Keep its token `contents: read` only and checkout trusted main code only. A forged, PR-origin, replayed, stale or manually dispatched broker input without all evidence MUST fail before Mac allocation. The existing manual trusted-main dispatch remains a separate human-reviewed flow. Test both accepted event-context inheritance and `workflow_run`/forged-broker refusal against real orchestrator context contract in that future slice.

Repeat live PR/head and run checks immediately before allocating the native runner. A HEAD change after that does not change what the VM tests: the target remains the pinned old SHA and can never certify a newer SHA. Re-check current PR/head when emitting success. If stale, report the old run honestly without claiming success for the new SHA; deny any update directed at the new SHA.

Do not use PR-controlled artifacts, path/environment, issue comments, labels or shared caches as trusted executable instructions. Cache and job output names are not identity proof. GitHub APIs and data parsing are bounded; variable data is passed through env/quoted arguments, not interpolated into shell scripts.

### 3.3 Eligible PRs and public-fork policy

Initial automatic admission is deliberately **same-repository only**; the required head repo ID must equal the base repo ID. A branch on the base repository is not thereby trusted to execute on the Mac: candidate code stays guest-only. A malicious collaborator PR can still exploit a VM vulnerability; use one serial run, bounded guest time/resources, provider refusal on unknown state and optional policy throttles without silent bypass.

Fork PRs are not automatically dispatched on the persistent Mac. A future separately reviewed operator authorization must bind **PR identity + immutable exact SHA + repository identity + expiry + trusted actor** and recheck all on admission; a mutable label alone is insufficient. Until that capability exists, no native success claim for fork PRs and no implicit waiver of required gates. A global SHA-scoped native status MUST NOT be required as a substitute for PR authorization: an unauthorized fork can share that SHA with an eligible PR.

GitHub commit statuses are scoped to **commit SHA, not PR identity**: the same commit may appear in multiple PRs. A native result on a SHA is evidence for those exact bytes and the recorded trusted gate, not proof that a fork PR is authorized to use the Mac. Ruleset/administrative authorizations must not treat an inherited status as approval for another PR.

### 3.4 Native queue and replays

Use the existing global live-local-e2e concurrency group with cancel-in-progress: false; do not start another guest to hurry a pending PR. Admission/dispatch events must never cancel or delete a running guest. Recommended queue control: only one automatic native run for one validated exact SHA and authority revision, while queued/running; repeated ready/synchronize notifications cannot enqueue an unlimited number. A persisted deduplication mechanism requires its own trusted ledger and replay tests; the first slice is **shadow validation only**, no allocation or status success. Do not claim dedup is solved by GitHub concurrency alone (it serializes but does not collapse duplicates).

Record queue-time separately from native execution. Native timeout/refusal/stale provider markers are fail-closed and must preserve observable diagnostics, not automatically reset the provider.

### 3.5 Status semantics and branch protection

Reserve one status context, for example pr-native-e2e/level-3, to be established before rollout; never overload the existing two Python required contexts. After an independently verified trusted-suite gate, broker authorization and an actual native run, the informational reporter posts pending for the exact tested SHA, then:
- success only if exact target guest assertion, trusted validator, marker absence, VM/process/overlay/owned workspace cleanup and post-run namespace checks all pass;
- failure for verified test failure; error for unknown provider status, failed cleanup, timeouts, exceptions, ambiguous/stale evidence; never success on skipped/cancelled;
- records targeted SHA, PR, event/run ID+attempt, provider authority revision, immutable image/lock digests, bounded timestamps and direct run URL in an auditable artifact or trusted GitHub run summary.

The writer never runs PR code and re-fetches latest live PR/head before success. When the PR changes, the earlier status remains on the old SHA; it cannot certify the new SHA. A missing status is missing evidence, never an implicit native PASS; before a separate PR-bound enforcement mechanism exists it is **not yet** an enforceable merge requirement.

**Native SHA status remains informational, not an enforceable PR authorization.** A required status context and restricted source still certify a commit SHA, not (repository, PR number, SHA). No ruleset may treat a green `pr-native-e2e/level-3` SHA status as sufficient authorization. A future independent ADR/plan must define and implement a **separately verifiable PR-bound merge gate**, using a trusted receipt binding repository ID, PR number, immutable HEAD SHA, live base/ref, trusted-verifier evidence and native-clean evidence. Its check/run attachment, actor/permissions and actual branch-rule semantics need separate security and admin review; do not assume `pull_request_target` or a generic commit status provides PR identity. A live **two-PR/same-SHA** canary (one eligible, one fork) MUST show the fork remains unable to merge despite a green SHA status, plus pass/fail/cancel/rebase cases. Until then SHA status remains evidence only and the existing manual review/CI merge process remains authoritative. Current connection cannot read branch protection; ruleset list was empty.

### 3.6 Protected staging and true local evidence

Keep ADR 0019 as the controlling design for native path creation, owned lifetime and admission. Its fixed path, FD-bound Darwin ACL/identity/time checks, two bounded clean observations, legacy root checks, marker schema, frozen historical incident authorities and no generic cleanup all remain in force. Activation of the fixed protected root is separately reviewed and must run the real UID-502 native provider after merger to trusted main. No fallback to legacy placement can be counted as protected placement acceptance.

Recommended ordering: shadow CI admission first (no Mac); ADR 0019 owned-workspace lifetime and already-main protected activation next; then enable the automatic PR native caller and status writer after real protected-placement and cleanup proof. Manual trusted-main exact-target and existing main-push legacy E2E remain available while the staged architecture is being implemented, subject to existing fail-closed provider checks.

## 4. State machine, failure policy and audit

NEW -> HOSTED_PENDING -> CI_REPORTED_PASS -> METADATA_MATCHED_SHADOW -> TRUSTED_MAIN_SUITE_VERIFIED -> BROKER_REVALIDATED -> QUEUED -> RUNNING -> POST_CLEAN_CHECK -> NATIVE_EVIDENCE_PASSED. Only the first four states are in the initial shadow slice; later states each require a separately approved security boundary. NATIVE_EVIDENCE_PASSED is **not** a PR-specific merge authorization.

Alternative terminal states: REJECTED (ineligible/ambiguous), FAILED (verified test failure), BLOCKED (provider/security uncertainty), STALE (PR head changed), TIMED_OUT, CANCELLED. None authorizes merge.

Store minimum fields: repository ID; PR number; exact PR head SHA; verified base ref/revision; PR-reported CI run ID and attempt (metadata only); independent trusted-main verifier SHA + required-test manifest digest + trusted verification run/attempt; dispatch broker run/attempt and recheck result; trusted main native authority SHA; guest image digest; test scenario/schema version; native run/job ID; start/end/queue timestamps; gate outputs; cleanup and informational SHA-status result. Preserve artifact access controls and bounded retention; never persist GitHub tokens or host secrets. The evidence format is not itself an approval token.

The status writer does not automatically retry a possibly half-completed guest, delete historical data, or repair unknown provider state. Retry requires a fresh independently verified admission and explicit provider-clean evidence.

## 5. Evidence-first acceptance matrix

| Test class | Mandatory scenario | Expected |
| --- | --- | --- |
| Identity | wrong repo ID/name, fork, empty/multi PR association, ref/base mismatch | REJECT; zero Mac jobs |
| State | draft/closed PR, changed head, stale run, malformed SHA, replay | REJECT; no success for newer SHA |
| CI integrity | ten green names but modified PR CI workflow skips all intended tests; missing/duplicate/skipped jobs or mixed attempt | Shadow metadata may match; `trusted_suite_proven=false`; no Mac dispatch until separate trusted-main verifier |
| Privilege boundary | malicious PR changes workflow, scripts or reporting payload | Candidate code never executes on persistent Mac or writer |
| Guest isolation | no NIC, host shares, secrets; pinned QEMU/image; distinct overlay | Gate verifies unchanged isolation |
| Lifecycle | crash/timeout at each create/start/guest/cleanup phase, stale marker, ACL drift | FAIL/BLOCK; no silent retry/delete |
| Reporting | pending, success, failure, cancellation, permission denial, stale PR HEAD | Exact SHA evidence is truthful; missing success is not native PASS but is not PR enforcement without a separate PR-bound gate |
| Admission races | synchronize during queued/running/after E2E; duplicate ready events | No new HEAD certified by old run; no unsafe cancellation |
| PR-bound enforcement | two PRs with identical HEAD SHA, one eligible and one fork; green native SHA status | Fork must not inherit merge permission; separate PR-bound gate + actual GitHub ruleset canary required |
| Main acceptance | exact post-merge SHA, hosted + actual native guest + cleanup | Completed main run and complete audit evidence |

Tests MUST use RED -> GREEN on each implementation slice, targeted focused/regression suites plus ordinary full hosted CI, fresh independent security/code/doc review and exact-head native evidence when the boundary is touched. Mac-specific ACL and child-reaper work requires actual disposable Mac fixtures, not Linux mocks. Do not run duplicate full suites concurrently with other developer agents.

## 6. Incremental deliveries and rollback

1. **Design/ADR only (this document)**: agree trust policy, status semantics, evidence, rollout and acceptance. No workflow activation. Update the stale repository-visibility documentation.
2. **Admission shadow slice**: new trusted-main CI-completion listener and pure bounded identity/CI proof module; hosted-only dry-run decision/logging; NO native dispatch and NO PR success status. Source-backed adversarial tests and fresh independent review.
3. **ADR 0019 lifetime slice**: fixed owned private workspace creation and explicit cleanup, real UID-502 ACL/discovery/drift/regression evidence; no activation yet.
4. **ADR 0019 activation slice**: trusted-main-only use of fixed protected staging for all live/probe/recovery routes, exact-main protected-placement native pass and cleanup; rollback/refusal documented.
5. **Trusted-suite verification slice**: independently reviewed main-pinned procedure and test manifest on hosted disposable runners; authenticate exact PR SHA/base/verifier/run evidence; modified PR CI with ten successful names cannot bypass this gate.
6. **Trusted native broker/caller slice**: narrow hosted `actions: write` dispatch of a main-only `workflow_dispatch` broker, fresh API/attestation revalidation and existing native reusable workflow call. Verify actual allowed event propagation plus forged/direct/PR-origin refusal; no Mac write token.
7. **Informational hosted SHA reporter slice**: only after true native and cleanup PASS; separate narrowly scoped hosted `statuses: write`, failure and stale receipts, no required PR context yet.
8. **PR-specific enforcement design then implementation**: separate ADR/plan specifying a trusted PR-bound authorization/merge gate; live same-SHA two-PR/fork test and admin-confirmed ruleset enforcement. Never make SHA status alone the required authorization. Keep ordinary/manual/main-push CI intact.

Each numbered delivery is independently reviewable with its own feature branch/PR and exact-head gates. Do not bundle protected-placement activation, trust admission and status writing into one unreviewable PR.

Performance targets are not completion claims: L0 focused <60 seconds, hosted feedback queue-inclusive P95 <10 minutes, healthy native stage execution P95 <=5 minutes plus separate queue time. Report sample size, all failures and percentiles. Do not weaken the trust boundary to make the target.


The implementation is decomposed into a [staged rollout roadmap](../plans/2026-10-14-local-live-e2e-vnext-rollout.md) and a [Task-by-Task shadow-admission plan](../plans/2026-10-14-pr-native-e2e-shadow-admission.md). Both are review proposals, not authority to enable native PR dispatch.

## 7. Alternatives and rejected shortcuts

- Direct pull_request or pull_request_target -> persistent Mac: rejected; PR control over host execution or elevated workflow is unacceptable.
- Bare workflow_run -> Mac without API/PR/head revalidation: rejected; mutable/ambiguous PR association, forks, reruns and replay can trigger wrong execution.
- Generic external queue/server: deferred; adds persistent privileged surface, external secrets and operational cost without demonstrated need.
- Cache/reuse candidate guest worktree/overlay: rejected; target state could leak between runs.
- Native-green status just from guest serial success: rejected; cleanup/unknown provider state must gate success.
- Fast status without enforcing GitHub ruleset: not a merge gate; allowed only as explicitly labeled shadow/informational stage.

## 8. Source and compatibility notes

Current project evidence: CI workflows and runtime files in this repository; development-methodology sections 7–13; ADRs 0006/0008/0013/0019; protected staging design; GitHub Actions exact-main run 38511642846.

GitHub guidance:
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- https://docs.github.com/en/rest/commits/statuses
- https://docs.github.com/en/rest/checks/runs

Status source: **proposed design, not approved implementation**. No deployment permission or protected-placement authority is created by this document.
