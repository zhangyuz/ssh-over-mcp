# PR Native E2E Shadow Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Status:** Proposed for operator joint written-spec and plan review. No implementation authorized.

**Goal:** A read-only trusted-main CI completion listener determines whether a GitHub-*reported* completed-success PR CI run's metadata identifies one current same-repo PR and immutable HEAD SHA. A green PR-controlled CI workflow (even ten correct job names) is not trusted-suite proof; this slice does NOT allocate a Mac, attest native E2E or certify full CI execution.

**Architecture:** A default-branch workflow_run listener executes only trusted-main Python on GitHub-hosted Ubuntu. A bounded REST adapter gathers live repository/workflow/run/attempt/commit-associated-PR evidence; a pure validator returns an immutable **non-authorizing metadata observation**; a CLI prints a clearly informational result without status writes.

**Tech Stack:** Python 3.13 stdlib (dataclasses, json, urllib.request, typing), pytest, PyYAML BaseLoader, Github REST Actions API, GitHub Actions YAML. No additional runtime dependency.

**Spec:** docs/superpowers/specs/2026-10-14-local-live-e2e-vnext-design.md. Rollout: docs/superpowers/plans/2026-10-14-local-live-e2e-vnext-rollout.md. ADRs 0006, 0008, 0013, 0019 and proposed 0020.

## Global Constraints

- SHADOW ONLY. No native workflow_call, Mac workflow_dispatch, status/check write token, PR-head checkout, native job, branch-protection update, or production E2E change.
- Repository is public and allows forks: fail closed for forks, draft/closed/stale/ambiguous PRs, wrong base/ref, malformed SHA, missing or mixed CI attempts.
- The original main CI specifies 8 disjoint full suite shards for Python 3.13/3.14 plus required job names Ubuntu 26.04 x86 / Python 3.13 and Ubuntu 26.04 x86 / Python 3.14. **A PR can modify its own workflow and test commands while keeping all 10 expected names green**. This slice validates only consistency of reported metadata, NOT execution of the trusted-main suite. `trusted_suite_proven` and `dispatch_authorized` MUST remain False under every input.
- PR-only Merge-main no-network Level-3 job is legitimately skipped and MUST NOT be represented as native evidence.
- Github workflow_run.pull_requests can be empty; lookup must use commit-associated PR REST endpoint and live PR detail. github.sha is the trusted default branch checkout SHA, not the candidate PR head SHA.
- The normal PR CI validates synthetic merge checkout, not necessarily standalone candidate HEAD or a merge against a subsequently moved base. Shadow never claims base freshness or native admission authorization.
- The GitHub integration returned empty rulesets and branch protection read 403; emission of an informational result is never an enforceable merge check.
- Follow RED then GREEN per test case, isolated owned worktree, update ignored progress.md for takeover, do not run duplicate full tests during other agents' work.

## Review Focus

1. Missing or truncated commit-associated PR pages: Task 1 test_no_association_refuses; Task 2 test_commit_pagination_over_cap_refuses.
2. Mixed rerun attempts or duplicate/missing Python jobs **and a malicious PR changing CI/test commands while reporting ten green names**: Task 1 test_attempt_and_jobs_are_complete and test_modified_ci_same_green_names_is_not_trusted_suite_proof; Task 2 test_only_attempt_jobs_endpoint. A metadata match must never signal actual suite attestation.
3. Base SHA changing while PR head stays identical: Task 1 test_base_freshness_not_claimed; later real dispatch must introduce separate freshness proof, not infer it from this shadow.
4. API redirect/oversized JSON/rate limit or secret in exceptions: Task 2 test_transport_rejects_redirect_oversize_and_http_error; Task 3 test_cli_redacts_secret.
5. Workflow-run elevated-code execution, candidate checkout or accidental Mac/status path: Task 4 test_trusted_sha_checkout_and_no_host_authority.

---

## File and interface map

- Create ops/live-e2e/pr_ci_admission.py — pure validator only.
- Create ops/live-e2e/pr_ci_github.py — bounded read-only REST adapter only.
- Create ops/live-e2e/pr_ci_shadow.py — bounded event file, API orchestration, informational CLI.
- Create .github/workflows/pr-native-e2e-shadow.yml — default-branch workflow_run listener on hosted Ubuntu only.
- Create tests/ops/test_pr_ci_admission.py, test_pr_ci_github.py, test_pr_ci_shadow.py, test_pr_ci_shadow_workflow.py — each tests its corresponding boundary.
- Modify docs/ci-hosted-primary.md and docs/development-plan.md; create docs/evidence/2026-10-14-pr-native-e2e-shadow.md for honest implementation limits and exact evidence.

Freeze these names before implementation:
- class Refused(ValueError): holds a fixed safe reason_code string, no untrusted payloads.
- @dataclass(frozen=True) class ShadowObservation: repo_id: int; pr_number: int; head_sha: str; ci_run_id: int; ci_attempt: int; base_freshness_proven: bool = field(init=False, default=False); trusted_suite_proven: bool = field(init=False, default=False); dispatch_authorized: bool = field(init=False, default=False). These three fields cannot be supplied by the caller and are always False. ShadowObservation is intentionally not named Admission and is not an authorization ticket.
- def decide(event: Mapping[str, object], repository: Mapping[str, object], workflow: Mapping[str, object], run: Mapping[str, object], pull_requests: Sequence[Mapping[str, object]], jobs: Sequence[Mapping[str, object]]) -> ShadowObservation. The PR list contains fresh full-detail PR objects, never event summaries.
- class GitHubReadAPI: def __init__(self, token: str, *, transport: Callable[[str], object] | None = None) -> None; def load(self, event: Mapping[str, object]) -> tuple[dict, dict, dict, list[dict], list[dict]]. Transport receives ONLY a fixed same-repository API-relative path, no caller URL.
- def main(event_file: Path, *, token: str) -> int in pr_ci_shadow.py. Output a bounded JSON object: verdict METADATA_MATCH_SHADOW, REFUSED or ERROR; fixed reason_code and numeric run ID, optionally exact lowercase SHA and PR number on metadata matching. The output MUST contain `trusted_suite_proven: false` and `dispatch_authorized: false` even for METADATA_MATCH_SHADOW; API errors exit nonzero; normal ineligibility exits zero with explicit REFUSED, never native PASS or FULL_CI_PROVEN.

### Task 1: Pure exact CI run + current PR validator

**Files:** Create ops/live-e2e/pr_ci_admission.py; test tests/ops/test_pr_ci_admission.py.

**Interfaces:** Produce the Refused, ShadowObservation and decide interfaces above; no network/IO.

- [ ] Step 1 — Write test_matches_one_live_same_repo_pr_metadata_only: repository id=42, full_name=zhangyuz/ssh-over-mcp, default_branch=main; workflow id=9,name=CI,path=.github/workflows/ci.yml; event action=completed with workflow_run.id=123,run_attempt=1,head_sha=40 lowercase a chars; fetched run same identity with pull_request event, completed/success, head_branch=feat/canary, head_repo/base_repo id=42; one live PR number=40, state=open,draft=false, base main, head SHA/ref/repo match. Include 8 exact Full validation / Python VERSION / PARTITION jobs with VERSION in (3.13,3.14) and PARTITION in (projection-hot,projection-rest-classified,projection-rest-other,rest); 2 required aggregate Python jobs success; PR-only native job skipped. Assert ShadowObservation(repo_id=42,pr_number=40,head_sha=40*a,ci_run_id=123,ci_attempt=1) and individually assert all three proof flags are False; attempts to pass any proof flag as constructor kwargs raise TypeError.
- [ ] Step 2 — Run RED: python -m pytest -q tests/ops/test_pr_ci_admission.py::test_matches_one_live_same_repo_pr_metadata_only. Expected: missing implementation or named symbol, NOT unrelated fixture/platform error.
- [ ] Step 3 — Implement minimal pure validator with fixed exact repo/workflow/path/job identity, robust JSON type guards (bool is not int), 40-hex lowercase SHA, exactly one matching open non-draft current same-repo PR and no ambiguous same SHA/ref. Ensure run/event ID and attempt equal.
- [ ] Step 4 — Run GREEN: same command. Expected: 1 PASS.
- [ ] Step 5 — Write additional adversarial tests FIRST: test_no_association_refuses, test_fork_or_draft_or_closed_refuses, test_changed_ref_head_base_refuses, test_wrong_repo_or_workflow_refuses, test_attempt_and_jobs_are_complete, test_skip_is_not_native_evidence, test_base_freshness_not_claimed, **test_modified_ci_same_green_names_is_not_trusted_suite_proof**. The last case supplies ten successful unchanged names but separately simulates a PR-controlled workflow that bypassed all test commands; since the metadata is indistinguishable, assert the verdict remains ShadowObservation with `trusted_suite_proven=False` and `dispatch_authorized=False`, NEVER an authoritative pass or runnable candidate. Parametrize missing/failed/cancelled/skipped/duplicated required jobs and event vs API run mismatch. Watch a meaningful RED per new rule and then fix to GREEN.
- [ ] Step 6 — Run python -m pytest -q tests/ops/test_pr_ci_admission.py && python -m ruff check ops/live-e2e/pr_ci_admission.py tests/ops/test_pr_ci_admission.py. Expected all PASS.
- [ ] Step 7 — Commit with git add the two files; git commit -m "feat: classify exact PR CI shadow admission"; append test evidence and ruling lines to ignored progress.md.

### Task 2: Read-only bounded exact-attempt GitHub API

**Files:** Create ops/live-e2e/pr_ci_github.py; test tests/ops/test_pr_ci_github.py.

**Interfaces:** GitHubReadAPI.load(event) obtains five snapshots (repository, CI workflow, run, fresh PRs, exact attempt jobs) via a fake-injectable transport and production fixed https://api.github.com GETs. Malformed/partial/unauthorized data raises Refused with fixed reason codes, never prints token.

- [ ] Step 1 — Write test_only_attempt_jobs_endpoint: fake transport records GETs for /repos/zhangyuz/ssh-over-mcp, /actions/workflows/ci.yml, /actions/runs/123, /commits/<40-a-SHA>/pulls?per_page=100&page=1, /pulls/40, /actions/runs/123/attempts/2/jobs?per_page=100&page=1. Assert no /actions/runs/123/jobs (would mix reruns). Use exact event ID=123 attempt=2. Run python -m pytest -q tests/ops/test_pr_ci_github.py::test_only_attempt_jobs_endpoint. Expected RED for missing adapter.
- [ ] Step 2 — Implement bounded GET with timeout <=10 sec, max 1 MiB response, fixed Accept application/vnd.github+json, API version 2022-11-28 and Bearer token only to api.github.com; reject redirects to arbitrary origins and non-GET methods. All path parameters validated numeric run/attempt/PR or fixed repo and 40-hex SHA. No candidate input controls host/path.
- [ ] Step 3 — Run GREEN: same command, expected 1 PASS.
- [ ] Step 4 — Add RED→GREEN cases: test_commit_pagination_over_cap_refuses, test_incomplete_jobs_total_count_refuses, test_transport_rejects_redirect_oversize_and_http_error, test_no_association_refuses, test_malformed_json_and_rate_limit_refuse. For commit associations, paginate up to five 100-item pages; if the limit may be exceeded, REFUSE, not silently truncate. Jobs enumerate exact attempt with total_count, at most 200 records; reject incomplete/duplicate pages or missing records. Fetch every associated PR by exact numeric number before pure admission; never infer from empty workflow_run.pull_requests.
- [ ] Step 5 — Run python -m pytest -q tests/ops/test_pr_ci_admission.py tests/ops/test_pr_ci_github.py && python -m ruff check ops/live-e2e/pr_ci_*.py tests/ops/test_pr_ci_*.py. Expected all PASS.
- [ ] Step 6 — Commit only adapter/tests: git commit -m "feat: fetch bounded exact-attempt CI evidence"; update progress.md.

### Task 3: Informational-only CLI

**Files:** Create ops/live-e2e/pr_ci_shadow.py; test tests/ops/test_pr_ci_shadow.py.

**Interfaces:** main(event_file: Path, *, token: str) -> int wraps tasks 1–2 without issuing status/check or native job. Only controlled JSON output (verdict/reason_code/run numeric ID, optional exact PR and SHA).

- [ ] Step 1 — Test RED test_shadow_cli_emits_informational_verdict: write event JSON to tmp_path, inject fake API, assert exact METADATA_MATCH_SHADOW with `trusted_suite_proven=false` and `dispatch_authorized=false` rather than SUCCESS/NATIVE_PASS/FULL_CI_PROVEN, never prints token or PR title. Expected import failure.
- [ ] Step 2 — Implement event file cap 256 KiB, UTF-8 strict JSON object parsing, safe bounded output. Avoid untrusted interpolation into scripts, stderr/exception/token leakage, GITHUB_OUTPUT, statuses API and external dispatch.
- [ ] Step 3 — Run GREEN: python -m pytest -q tests/ops/test_pr_ci_shadow.py::test_shadow_cli_emits_informational_verdict.
- [ ] Step 4 — RED→GREEN test_cli_redacts_secret, test_malformed_or_oversize_event_errors, test_fork_refused_is_not_pass, test_no_status_or_github_output_writes and test_transport_failure_nonzero. Ensure metadata matched case is informational only and normal denied candidate is explicit REFUSED (non-authoritative), failed API is ERROR and nonzero exit.
- [ ] Step 5 — Run all three task suites plus Ruff, then commit only CLI and tests with message "feat: surface read-only shadow admission verdict".

### Task 4: Trusted-main hosted-only workflow

**Files:** Create .github/workflows/pr-native-e2e-shadow.yml; test tests/ops/test_pr_ci_shadow_workflow.py.

**Interfaces:** on.workflow_run.workflows=[CI],types=[completed]. Permissions contents:read,actions:read,pull-requests:read. A single admission job on ubuntu-26.04, timeout<=5min, Python 3.13, fixed event path and read-only token passed only to hosted CLI. GitHub Actions YAML parsed with yaml.BaseLoader.

- [ ] Step 1 — Test RED: test_only_workflow_run_completed_trigger, test_trusted_sha_checkout_and_no_host_authority, test_shadow_no_status_write_and_no_native_caller. Assert NO pull_request_target, native workflow_call, self-hosted runner, statuses:write, checks:write, candidate checkout, PR-derived shell/paths or GITHUB_OUTPUT; checkout uses pinned actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 with ref github.sha, persist-credentials:false and clean:true. setup-python pinned actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 with 3.13. Job if guards workflow_run.event=pull_request.
- [ ] Step 2 — Run python -m pytest -q tests/ops/test_pr_ci_shadow_workflow.py. Expected RED because workflow does not exist.
- [ ] Step 3 — Add exact workflow. Use concurrency group by upstream run id+attempt with cancel-in-progress:false, verify trusted checkout SHA equals GITHUB_SHA; no native scheduler or secret-bearing PR artifact. Workflow definition only becomes effective once merged to default branch.
- [ ] Step 4 — Run python -m pytest -q tests/ops/test_pr_ci_shadow_workflow.py tests/ops/test_ci_workflow.py tests/ops/test_live_e2e_gate_contract.py && python -m ruff check ops/live-e2e tests/ops. Expected GREEN/PASS, original CI/native definitions unchanged.
- [ ] Step 5 — Commit workflow/tests with message "ci: observe trusted PR CI admission in hosted shadow".

### Task 5: Evidence/docs and end-to-end verification

**Files:** Modify docs/ci-hosted-primary.md and docs/development-plan.md; create docs/evidence/2026-10-14-pr-native-e2e-shadow.md; extend tests/ops/test_pr_ci_shadow_workflow.py.

**Interfaces:** Evidence remains documentary. No activation, protected staging change, or branch-rule edit.

- [ ] Step 1 — RED test test_shadow_is_documented_not_an_e2e_gate checks evidence page explicitly contains shadow only, no native dispatch, no status write, fork/unknown refusal and rollback.
- [ ] Step 2 — Update topology/roadmap, write evidence with exact local test output and security contract, distinguish pending post-merge real canary vs proven facts. Avoid invented run IDs. Explain incomplete PR CI synthetic-merge/base-freshness caveat; status remains informational.
- [ ] Step 3 — GREEN doc test + python -m ruff check src tests ops/systemd ops/live-e2e && python -m compileall -q src tests ops/systemd ops/live-e2e. Then ordinary full supported suite through exact-head GitHub-hosted CI shards; do not claim exploratory Mac Linux-specific baseline failures as PASS.
- [ ] Step 4 — Commit docs/test with message "docs: record PR CI shadow admission evidence and limits".

### Task 6: Independent review, GitHub gates, rollout proof

**Files:** None except exact evidence and ignored progress.md; review entire branch.

- [ ] Step 1 — git diff --check origin/main...HEAD; read full security diff/spec, verify existing ci.yml/live-local-e2e.yml and trusted Mac scripts unchanged. Search new code/YAML for dangerous shell execution, dynamic PR checkout, pull_request_target, statuses:write, self-hosted and guest invocations: each prohibited.
- [ ] Step 2 — Independent full-branch security/code/documentation review (self-review labeled as such if reviewer unavailable). Resolve Critical/Important with test that fails RED before fix; preserve exact full GREEN evidence; keep unrelated work out.
- [ ] Step 3 — Push isolated implementation PR as Draft. Confirm exact PR-head hosted 8 shards and 2 required Python aggregates success, and PR-only native skipped as expected; no premature claims of native acceptance. Manual trusted-main legacy Level-3 exact candidate guest and provider cleanup gate only if required by methodology.
- [ ] Step 4 — After approved merge, verify exact-main hosted+native. On a separate canary PR with new CI completion, observe real trusted-main shadow workflow_run and its honest METADATA_MATCH_SHADOW/REFUSED without ANY Mac allocation or SHA status publication. Real canary evidence must be recorded; when pending, report pending rather than PASS.
- [ ] Step 5 — Preserve other worktrees; clean only owned feature branch/worktree after evidence passes. Record exact SHA, run IDs/attempt, cleanup and limitations in progress.md. No next-slice implementation without new approved plan.

## Execution and review gate

This is a proposed **first-slice** plan; later protected staging lifetime, activation, native dispatch, status reporter and administrative branch rules require their own full implementation plans and PRs. This stage MUST NOT claim trusted-full-suite proof because upstream PR code can alter `.github/workflows/ci.yml` without changing workflow ID or names. A later independent pinned-main trusted suite verifier is required before any Mac dispatch. The operator asked to review the complete architecture and implementation plan together; this document is NOT an implicit execution authorization.

Recommended execution method: **subagent-driven**, with a fresh reviewer at each important trust-boundary task; a permission-check mistake can later expose a persistent Mac. If not available, native inline implementation plus explicit fresh whole-branch review, with the limitation disclosed.
