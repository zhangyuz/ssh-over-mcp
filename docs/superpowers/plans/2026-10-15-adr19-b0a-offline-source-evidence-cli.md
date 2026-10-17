# B0a Offline Source-Evidence CLI Implementation Plan

> **2026-10-16 staged feature amendment:** This six-task full T5B plan
> is retained as a later protected milestone. PR #268's revised completion
> gate delivers the bounded Linux-only `inspect-synthetic` (hard-coded
> archived candidate, bounded safe read, kernel-sealed digest and
> bundle-declared digest preflight), explicit `B0A_INSPECTED_UNTRUSTED`
> reporting without any signature/source authorization, adverse
> changed/symlink/invalid inputs, docs, exact-head CI and author self-review before Ready; independent
> security review *of the reduced feature* after Ready, before merge. Existing
> `verify-synthetic` must keep refusing absent the original exact-material
> T5B-0 approval. Tasks requiring full authenticated executable/roots/TSA
> and actual signed-green plus hostile red are deferred and NOT marked done.
> Nothing changes real macOS B0b/B1–B4 permissions.


> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one reproducible operator command that cryptographically verifies an independently approved signed synthetic B0a fixture against a fully measured immutable byte snapshot, emitting `SYNTHETIC_ONLY` or `B0A_REFUSED` without granting real-artifact source trust.

**Architecture:** A fixed CLI admits only allowlisted fixture IDs and independently authenticated synthetic policy; a bounded trusted ingestor seals the exact input bytes, then a pinned offline Sigstore process checks the authenticated digest (or same sealed FD if selected) and the approved synthetic trust chain. A bounded evidence serializer reports no authority beyond the test-key exercise; every unknown input or missing proof refuses.

**Tech Stack:** Python >=3.13, Linux `memfd_create` + `fcntl` seal checks, standard-library `hashlib`/`subprocess`/`json`, independently pinned Sigstore verifier and immutable signed test fixtures, pytest/ruff.

**Spec:** [2026-10-15 B0a operator CLI written design](../specs/2026-10-15-adr19-b0a-offline-source-evidence-cli-design.md)

## Global Constraints

- Source of truth: [ADR0019 Gate B design](../specs/2026-10-15-adr19-gate-b-macos-interpreter-source-decision-design.md), [B0a/B0b governing plan](2026-10-15-adr19-gate-b0-offhost-package-verification.md), [T1–T5 approval checklist](../../evidence/2026-10-15-adr19-b0a-artifact-trust-approval-checklist.md), `docs/development-methodology.md`.
- **Stop before any implementation until this plan, execution approach, and the proposed B0a path allowlist amendment to `docs/superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md` have independent security review and explicit operator D2 approval inside Draft PR #268.** No new module, fixture, README or methodology change is preauthorized under the original path list. Written spec approval alone does not authorize code.
- **T5 synthetic gate:** before any verifier invocation, independent operator/security review must record the exact executable/runtime/dependency closure digests, test signer SAN/OIDC and key material source, test Fulcio/Rekor/TSA/log roots and signature-time evidence, **complete version-appropriate Sigstore `ClientTrustConfig` (not bare `trusted_root.json`)**, offline clock/freshness/skew/revocation numeric bounds, actual accepted bundle format, and explicit supported `digest-from-sealed-bytes` or `direct-sealed-FD` mode. If any is unavailable, STOP; no fake GREEN, autodownload, ambient cache/root, self-declared `approved=true` or always-REFUSE feature claim.
- No real macOS `.pkg`/`.sigstore` acquisition/use, no **unapproved** verifier/trust-root install or execution, no privileged persistent Mac operation, no candidate-Python execution, no `installer`/B0b, no UID502/APFS, no Linux C. **Separate operator T5A approval granted inspection-only retrieval** of public synthetic research candidates (with exact hashes/provenance recorded); it is **not** T5B execution or test-root approval. Later real `B0A_EVIDENCE_COLLECTED_UNAPPROVED` is **not** part of this PR.
- Runner must be independently trusted disposable unprivileged Linux x86_64, with credentials and networking absent and executable/runtime closure approved. Linux here is verification environment, not postponed Linux product Slice C.
- All emitted success is **`SYNTHETIC_ONLY`**; all uncertain evidence **`B0A_REFUSED`**. JSON is non-authorizing and max 16 KiB. No caller-selected path, root, verifier binary, trust policy or privilege.
- **Original full-T5B work plan, now deferred:** its pinned-verifier GREEN/RED completion gate is **not** a PR #268 narrowed-inspection Ready criterion. This same PR may become Ready only after the amended inspection-only positive/adverse tests, docs, exact-head hosted CI and independent review pass. The genuine tool/root/TSA GREEN/RED plan will require its own separately authorized follow-up. Native Level-3 is unchanged. Merge still needs explicit operator approval.

## File map and responsibilities

| Path | Responsibility |
| --- | --- |
| `docs/superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md` | Proposed exact B0a path allowlist amendment; **independent security review and operator D2 approval required before coding** |
| `ops/live-e2e/gate_b0_immutable_bytes.py` | Fixed trusted synthetic fixture ingestion, writer-exclusion witness, private sealed `memfd`, full measured bytes/SHA-256/size and close-on-failure |
| `ops/live-e2e/gate_b0_sigstore_adapter.py` | Immutable synthetic policy loader/verification, pinned real Sigstore CLI, fixed args/FD or digest handoff, bounded subprocess and offline/result authentication |
| `ops/live-e2e/gate_b0_evidence.py` | Stable bounded non-authorizing JSON schema and refusal error mapping |
| `ops/live-e2e/gate_b0_source_verification.py` | Operator CLI entry, allowlisted `verify-synthetic`, no real-artifact path or authority |
| `tests/ops/test_gate_b0_source_verification.py` | Unit/schema/refusal plus real pinned Sigstore test-key positive/negative integration (tests requiring T5 gated runtime explicitly marked, not silently counted as GREEN when unavailable) |
| `tests/ops/fixtures/b0a_synthetic/` | Reviewed fixed tiny test fixture, bundle, immutable signed test policy or separately authenticated fixture generator inputs; **no ambient generated trust** |
| `ops/live-e2e/README.md` | Operator example, constraints, expected status/exit and independent T5 setup prerequisites |
| `docs/evidence/2026-10-15-adr19-gate-b0-source-verification.md` | Measured **T5A inspection-only candidate integrity evidence**, explicit UNVERIFIED provenance, and **later** genuine signed synthetic GREEN/RED evidence **only after actual approved execution**; early preflight data must never be labeled GREEN |
| `docs/development-methodology.md`, `docs/development-plan.md` | Vertical-slice Definition of Done and accurate unverified Mac release status |

## Review Focus

1. **Synthetic writer-control witness (not a concurrent file race):** `test_untrusted_synthetic_writer_witness_refuses_before_verifier` checks refusal when the test-harness-owned immutable bytes witness has `writer_excluded=False`. Genuine same-inode OS-source rewrite/restore remains **UNVERIFIED** and cannot be claimed by this synthetic interface.
2. **Synthetic fixture identity and FD ownership (not external unsealed-FD proof):** `test_synthetic_fixture_identity_mismatch_refuses` plus Task 1 forged/duplicate/recycled/externally substituted owned-FD closure tests; `test_caller_digest_never_reaches_verifier` applies only to later approved T5 mode. Generic unsealed external FD and concurrently hostile same-process FD reuse remain **UNVERIFIED**.
3. **Genuine signature valid but bundle-declared digest contradictory:** test `test_message_signature_declared_digest_mismatch_refuses_distinctly` in Task 4, with only that bundle field mutated.
4. **Stale trust roots / wrong log/time despite valid signature:** test `test_wrong_signer_oidc_root_log_time_refuses` in Task 4; trust source must be independent of bundle.
5. **Verifier fake JSON or subprocess/clock/resource failure:** test `test_verifier_exit_output_timeout_and_env_refuse` in Task 2; exit and output alone cannot authenticate claimed process or trust context.

---

### Task 0: Independent synthetic T5 tool/root/mode decision — **external approval prerequisite**

**Files:**
- Review: `docs/evidence/2026-10-15-adr19-b0a-artifact-trust-approval-checklist.md`
- Review: `docs/superpowers/specs/2026-10-15-adr19-b0a-offline-source-evidence-cli-design.md`
- Test: `tests/ops/test_gate_b0_source_verification.py` (later Tasks 2 and 4)

**Interfaces:**
- Consumes: signed/operator-authenticated synthetic policy decision produced **outside the untrusted fixture**.
- Produces: a fixed, read-only, independently verified **external synthetic T5 decision record** with exact allowed `fixture_id`, input digest and length, verifier/loader closure, signer/OIDC, roots/log/time, numeric offline cutoffs and one mode. Task 2 defines `SyntheticT5Policy` as the typed, fail-closed representation of this independently authenticated record; the CLI cannot construct or replace it from caller arguments. It is **not** an `approved` boolean passed to CLI.

- [ ] **Step 1:** Obtain distinct operator/security approval of the **actual** T5 synthetic verifier binary/runtime, test certificate identities, roots/checkpoints/time/freshness/revocation and exact mode after independent inspection. No versions or root hashes are guessed by this plan.
- [ ] **Step 2:** Verify attested bytes of every approved offline executable, test fixture, signed bundle, and root artifact **outside** the runtime being verified; compare complete digests to the independent decision.
- [ ] **Step 3:** Record an immutable approved test-only policy fingerprint and choose a real verifier command that supports the selected sealed-FD or `sha256:<measured digest>` interface. Deny any incompatible CLI/DSSE generation rather than changing verification mode.
- [ ] **Step 4:** Document artifact-provenance evidence and whether fixture-key identity, Rekor inclusion and signed time are cryptographically testable under the approved offline trust policy. **STOP here if no genuine test-key GREEN can be reproduced**; the feature cannot be declared ready.
- [ ] **Step 5:** Confirm implementation approval and approved execution method for this written plan. Only then proceed to code. No external tool/bootstrap side effects are allowed by this document.

### Task 1: Bounded sealed-byte measurement with refusal-first tests

**Files:**
- Create: `ops/live-e2e/gate_b0_immutable_bytes.py`
- Test: `tests/ops/test_gate_b0_source_verification.py`

**Interfaces:**
- Produces: `SealedMeasurement(fd: int, sha256: str, length: int, witness_ref: str)` (frozen, read-only), `ingest_fixed_fixture(fixture: FixedFixture, authority: VerifiedFixtureAuthority) -> SealedMeasurement`, `close_measurement(measurement: SealedMeasurement) -> None`.
- Requires: `FixedFixture` contains only a trusted harness-owned byte provider and bounded expected size; `VerifiedFixtureAuthority` binds that exact object to proven exclusive-writer control, not caller assertions. No arbitrary pathname argument.

- [ ] **Step 1: Write failing tests** `test_sealed_fixture_measures_exact_all_bytes`, `test_untrusted_synthetic_writer_witness_refuses_before_verifier`, `test_synthetic_fixture_identity_mismatch_refuses`, `test_length_overflow_or_short_read_refuses`, `test_fd_closed_after_every_failure`, `test_fd_closed_after_late_digest_failure`; also require `test_forged_measurement_cannot_close_unrelated_fd`, `test_copied_measurement_cannot_close_live_owner`, `test_double_close_after_fd_reuse_refuses_and_preserves_replacement`, `test_externally_closed_and_reused_owned_fd_refuses_without_closing_replacement`, and `test_mutated_live_measurement_fd_refuses_and_preserves_borrower`; additionally `test_handoff_rejects_mutated_public_digest_length_or_witness` and `test_handoff_rejects_forged_or_closed_issued_descriptor`. Assert Linux sealing readback, all sealed-byte SHA-256/length, one-time owned-FD closure and fail-closed stale/forged handles. These tests do **not** prove genuine untrusted source concurrent mutation or external unsealed-FD races.
- [ ] **Step 2: RED** `python -m pytest tests/ops/test_gate_b0_source_verification.py -k 'sealed_fixture or untrusted_synthetic_writer_witness or synthetic_fixture_identity_mismatch or length_overflow or fd_closed or forged_measurement or copied_measurement or double_close or externally_closed_and_reused or mutated_live_measurement_fd or handoff_rejects' -q` => intended missing-behavior failures, with **all 13 Task 1 targeted tests collected** (verify collection count; 0 selected is an error). An approved external OS source/FD race test is not represented by this synthetic-only selection.
- [ ] **Step 3: Implement** bounded ingest, writer-exclusive authority before first read, `os.memfd_create(..., os.MFD_ALLOW_SEALING)`, `fcntl(F_ADD_SEALS/F_GET_SEALS)` and readback, complete digest/size on the **same sealed object**, explicit FD ownership and cleanup. Refuse missing Linux features; no temporary mutable-path fallback. Keep `FixedFixture` and `VerifiedFixtureAuthority` internally constructed only.
- [ ] **Step 4: GREEN** rerun the exact Step 2 selection and verify **13 selected / 13 passed / 0 skipped** for Task 1. Separately run the entire focused file (currently 33 tests; archived Rekor/leaf ECDSA/identity/SCT candidate observations and ambient-policy-bypass refusals remain T5A non-authorizing only) to ensure no case was silently omitted. Linux OS-file concurrent rewrites, unsealed external FDs and hostile same-process FD mutation are still **UNVERIFIED**.
- [ ] **Step 5: Commit** `git add ops/live-e2e/gate_b0_immutable_bytes.py tests/ops/test_gate_b0_source_verification.py && git commit -m 'feat: seal and measure B0a synthetic fixture bytes'`.

### Task 2: Exact pinned offline verifier adapter

**Completed pre-T5B preparation, NOT Task 2 acceptance:** `gate_b0_sigstore_adapter.py:check_bundle_digest_consistency()` checks strict bounded Sigstore v0.3 `messageSignature.messageDigest` against a live registered sealed measurement; it does not import/execute any external verifier, select a root or produce an authenticated success. Six focused tests validate the syntactic envelope/digest positive case and adversarial inconsistent/duplicate/incompatible/stale/missing-signature-or-proof cases; placeholders in unit fixtures are **not verified signatures**. Genuine Task 2 verifier/runtime pins, independent T5B approval, cryptographic GREEN/RED and the planned verifier process admission tests are **still unimplemented**.

**Files:**
- Create: `ops/live-e2e/gate_b0_sigstore_adapter.py`
- Test: `tests/ops/test_gate_b0_source_verification.py`

**Interfaces:**
- Consumes: `SealedMeasurement` from Task 1, authenticated `SyntheticT5Policy` from Task 0.
- Produces: `SyntheticT5Policy` (frozen typed policy derived only from the authenticated Task 0 record), `VerifiedSyntheticSignature` (frozen bounded proof fields), `B0aRefusal(code: str)`, and `verify_signed_synthetic(measurement: SealedMeasurement, policy: SyntheticT5Policy) -> VerifiedSyntheticSignature`. A `VerifiedSyntheticSignature` is only constructed after authenticating the exact approved verifier exit, digest, identity and root/log/time context.

- [ ] **Step 1: Write failing tests** `test_caller_digest_never_reaches_verifier`, `test_verifier_exit_output_timeout_and_env_refuse`, `test_wrong_verifier_loader_closure_refuses`, `test_no_network_cache_or_root_fallback`. Include forged stdout with exit zero, nonzero exit, truncation/oversized output, timeout, hostile PATH/LD_* env, non-authenticated trust config and unsupported mode.
- [ ] **Step 2: RED** `python -m pytest tests/ops/test_gate_b0_source_verification.py -k 'caller_digest or verifier_exit or wrong_verifier or no_network' -q` => fail for intended missing checks.
- [ ] **Step 3: Implement** fully pinned absolute exec and dependency closure admission, fixed arguments and explicit offline/time/root/identity policy, **independently approved full `ClientTrustConfig` for `--trust-config` (a bare `trusted_root.json` is incompatible with pinned Sigstore 4.3.0)**, direct authenticated digest or sealed-FD mode, stripped environment, no network/download/cached-root fallback, bounded subprocess timeout/stdout/stderr, exact exit and typed output. Never infer proof from caller JSON/exit alone; actual cryptographic verification must be performed by the approved pinned verifier.
- [ ] **Step 4: GREEN** rerun targeted tests => PASS with zero failures; ensure no network or trust writes even on error.
- [ ] **Step 5: Commit** `git add ops/live-e2e/gate_b0_sigstore_adapter.py tests/ops/test_gate_b0_source_verification.py && git commit -m 'feat: bind B0a measurements to pinned offline Sigstore verifier'`.

### Task 3: Operator CLI and bounded evidence

**Files:**
- Create: `ops/live-e2e/gate_b0_evidence.py`
- Create: `ops/live-e2e/gate_b0_source_verification.py`
- Test: `tests/ops/test_gate_b0_source_verification.py`

**Interfaces:**
- Consumes: `ingest_fixed_fixture` and `verify_signed_synthetic`.
- Produces: `format_b0a_result(status: str, reason_code: str, fields: dict[str, object]) -> bytes` (<=16 KiB); `main(argv: list[str] | None = None) -> int` accepting only `verify-synthetic --fixture <approved-id> --format json` and fixed no-network trusted runtime.

- [ ] **Step 1: Write failing tests** `test_cli_valid_synthetic_emits_one_json`, `test_cli_unknown_fixture_refuses`, `test_output_exact_schema_and_bounded_fields`, `test_refusal_has_no_fake_hash_or_source_authority`, `test_no_arbitrary_path_policy_root_or_real_mode`. Enforce `schema=som.b0a.synthetic.v1`, status strictly `SYNTHETIC_ONLY|B0A_REFUSED`, `evidence_class=NON_AUTHORIZING_SYNTHETIC`; no `source_verified`, `approved` input or secret output.
- [ ] **Step 2: RED** `python -m pytest tests/ops/test_gate_b0_source_verification.py -k 'cli_ or output_exact or refusal_has or no_arbitrary' -q` => absent CLI/schema contract fails.
- [ ] **Step 3: Implement** strict fixed parser and launcher, internal policy/fixture selection, canonical/size-bounded JSON with sanitized refusal and explicit FD/subprocess cleanup. Exit `0` only for a complete synthetic verification, nonzero for every refusal or missing offline runtime. Do not add public `verify-approved`.
- [ ] **Step 4: GREEN** rerun selection; exercise `--help`, unknown fixture and refusal via isolated test harness without installing any real verifier.
- [ ] **Step 5: Commit** `git add ops/live-e2e/gate_b0_evidence.py ops/live-e2e/gate_b0_source_verification.py tests/ops/test_gate_b0_source_verification.py && git commit -m 'feat: add bounded non-authorizing B0a operator CLI'`.

### Task 4: Genuine offline signature GREEN and adversarial RED matrix

**Files:**
- Create: `tests/ops/fixtures/b0a_synthetic/` (exact approved test-key material/bundle and independently authenticated synthetic policy only)
- Test: `tests/ops/test_gate_b0_source_verification.py`
- Modify: `ops/live-e2e/gate_b0_sigstore_adapter.py` only if actual pinned-version behavior is misinterpreted

**Interfaces:**
- Consumes: Task 0 approved/verified synthetic pins, Tasks 1–3 functions, real approved offline Sigstore executable.
- Produces: repeatable GREEN `SYNTHETIC_ONLY` for correct sealed signed digest; RED `B0A_REFUSED` for every attack row, with the same exact verifier/runtime.

- [ ] **Step 1: Write real integration tests** `test_pinned_verifier_real_test_key_green`, `test_same_length_different_digest_refuses`, `test_message_signature_declared_digest_mismatch_refuses_distinctly`, `test_wrong_signer_oidc_root_log_time_refuses`, `test_trust_policy_digest_replay_and_fd_race_refuse`. The third fixture changes **only** `message_signature.message_digest.digest` while preserving a genuinely valid original signature over unchanged bytes; verify a specifically attributable consistency mismatch, not generic invalid signature. Rekor v2 DSSE is independently tested only if allowed by approved pinned bundle format.
- [ ] **Step 2: RED** run the targeted integration suite against the **actual** pinned verifier in the authorized disposable environment. Wrong input cases fail closed; explicitly confirm GREEN currently fails only for the intended missing integration contract. Never skip/mute absence of T5 pins as success.
- [ ] **Step 3: Implement/fix** the minimal adapter/fixture compatibility required for that **exact reviewed version and policy**; do not download roots on demand, downgrade verifier or loosen signed-time/inclusion/revocation checks. If genuine offline signature/time proof is unavailable, STOP for operator policy review instead of manufacturing a pass.
- [ ] **Step 4: GREEN** rerun the exact suite: at least one authentic real-verifier GREEN plus paired multiple REDs; assert `0 failed` and `0 skipped` in mandatory integration cases; retain evidence of binary digest and signed fixture provenance with run ID.
- [ ] **Step 5: Commit** `git add tests/ops/test_gate_b0_source_verification.py tests/ops/fixtures/b0a_synthetic ops/live-e2e/gate_b0_sigstore_adapter.py && git commit -m 'test: prove genuine B0a signature verification and fail-closed negatives'`.

### Task 5: Single user-facing feature PR with usage and verification

**Files:**
- Modify: `ops/live-e2e/README.md`
- Update: `docs/evidence/2026-10-15-adr19-gate-b0-source-verification.md` (**T5A inspection-only provenance/hash/size/metadata receipts may be recorded before T5B, explicitly `NON_AUTHORIZING_SYNTHETIC`; append separately labeled genuine synthetic Sigstore GREEN/RED receipts only after exact T5B approval and actual pinned-verifier execution**; never promote T5A evidence to source trust or signed GREEN)
- Modify: `docs/development-methodology.md`
- Modify: `docs/development-plan.md`
- Review: `docs/superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md` (proposed allowlist change; requires independent approval before implementation)
- Review: `docs/superpowers/specs/2026-10-15-adr19-b0a-offline-source-evidence-cli-design.md`
- Review: this implementation plan and all Tasks 1–4 code/tests/fixtures

**Interfaces:**
- Consumes: proven CLI synthetic-only positive and adversarial refusal statuses.
- Produces: runnable operator example, reproducible full positive/negative evidence and one reviewable complete feature PR.

- [ ] **Step 1:** Write operator runbook with exact separately approved external verifier/test fixture setup, safe no-network invocation, expected output schema, exit status and explicit `SYNTHETIC_ONLY` non-authority disclaimer; avoid promising an executable or root not actually approved.
- [ ] **Step 2:** Change `docs/development-methodology.md` to require one operator/user-verifiable **vertical feature** per PR (code + positive/negative tests + usage + matching security docs), while preserving independent T1–T9/real-material/UID502 and exact-head approval gates. Update roadmap only with **actually evidenced** results.
- [ ] **Step 3:** Run `python -m ruff check src tests ops/systemd ops/live-e2e`, `python -m compileall -q src tests ops/systemd ops/live-e2e`, focused `python -m pytest tests/ops/test_gate_b0_source_verification.py -q`, all relevant provenance/UID502 regression and approved isolated-offline real-verifier demo. Mandatory genuine GREEN must be unskipped and attested. Do not describe hosted Ubuntu CI as B0a/macOS source approval.
- [ ] **Step 4:** Review whole branch for writer controls, pinned tool and root/freshness, disclosure, symlink TOCTOU, subprocess/network, signed digest and B0b separation, check `git diff --check`, then commit documentation and self-review evidence.
- [ ] **Step 5 (DEFERRED full verifier, not PR #268 readiness):** In a separate future authorized iteration, reproduce genuine test-key GREEN/paired RED, exact-head CI and independent whole-project/security review. PR #268 itself is limited to offline untrusted inspection with separately reviewed scope and exact-head CI. Real tool/roots/UID502 acceptance remain gated; no merge without operator approval. Preserve `progress.md`.

## Plan acceptance check

**A PR containing only this plan/spec is NOT feature-ready.** Neither a synthetic test green nor a real signed bundle opens B0b/UID502 permission. An undetermined synthetic verifier T5 decision blocks Tasks 2/4 success and therefore the feature PR; it must not be replaced by mocked or refusal-only code. This plan's approval is distinct from choosing T5 real-world signer/roots or artifact-use permission.
