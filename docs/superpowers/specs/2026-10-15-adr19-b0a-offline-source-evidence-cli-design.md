# ADR 0019 — B0a offline source-evidence operator CLI (feature design)

**Date:** 2026-10-15 (America/Toronto)
**State:** DESIGN FOR OPERATOR REVIEW, **not** an approved trust-policy, implementation plan, binary pin or execution permit.
**Tracks:** [Issue #259](https://github.com/zhangyuz/ssh-over-mcp/issues/259).
**Governing:** [Gate B source decision](2026-10-15-adr19-gate-b-macos-interpreter-source-decision-design.md), [B0a/B0b governing plan](../plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md), [T1–T5 policy checklist](../../evidence/2026-10-15-adr19-b0a-artifact-trust-approval-checklist.md), [B0b Apple Installer boundary](../../evidence/2026-10-15-adr19-b0b-apple-installer-independent-inspection-evidence.md), [methodology](../../development-methodology.md).

## Operator outcome and unit of delivery

**User story:** In an independently trusted, network-denied, credential-free, unprivileged **disposable Linux verification environment** (not the Yuz.local persistent orchestrator and not an Ubuntu *product* Linux Slice C), an operator runs **one** B0a command and receives a bounded machine-readable result proving whether an **approved synthetic test-key** signed bundle cryptographically matches **all independently measured bytes** of a writer-excluded sealed test artifact, with explicit signer/root/log/time semantics. A hostile/missing proof is refused; no result can authorize installation or UID502 execution.

**One feature PR:** source verifier orchestration, real pinned external-verifier adapter, genuine signed synthetic fixtures or reproducible independently controlled fixture generation, adversarial tests, usage/runbook and matching security/methodology/roadmap updates in **the same PR**. Small test-first commits remain useful; standalone compatibility/checklist PRs do **not** count as user features.

### Explicit scope and non-goals

- **Deliver now, after separate written spec/plan/implementation approval and reviewed exact synthetic T5 pins:** a **synthetic-only executable acceptance flow** with status `SYNTHETIC_ONLY` or `B0A_REFUSED`. It must have a **real** pinned verifier GREEN and adversarial REDs. This is not a fake/mock signature adapter.
- **Do not deliver now:** trust policy for CPython `python-3.13.16-macos11.pkg`, any real package/bundle/root/verifier download, production `verify-approved` command, source approval, Apple CMS or notarization inspection, package extraction, `installer`, Python provisioning, host ACL mutation, UID502/APFS, native provider changes, deployment/staging or Linux C.
- **Future separately approved extension only:** `B0A_EVIDENCE_COLLECTED_UNAPPROVED` on the exact real artifact, after **all** T1–T5 signer/artifact/tool/root/time/mode approvals plus separately authorized artifact-use; it is **not** implemented or emitted in this feature. No caller flag can turn a test-only run into it. B0b/T6–T9 and operator source-decision join are independent.
- **Design-stage limitation:** No actual Sigstore verifier executable, trust config, test-key root, artifact cert identity, or offline revocation/freshness policy has been independently authenticated/selected in this conversation. **No code is authorized to assert GREEN** unless these are independently reviewed and pinned; implementation must stop at that gate, not replace GREEN with an always-REFUSE stub.

## Approaches considered

| Approach | Outcome | Decision |
| --- | --- | --- |
| **A. One synthetic-only B0a command with real pinned verifier** | Operators can reproduce a genuine cryptographic test-key GREEN and meaningful REDs now without claiming Python.org source trust; upgrade to real artifact requires a separate authorization | **Preferred**; feature-sized and safe when T5 synthetic policy is approved |
| B. B0a docs, policy checklist, or always-REFUSE adapter | Adds no new user-verifiable signature capability despite repeated CI and review cost | **Reject** as a function iteration |
| C. Combine B0a real source verification, B0b Apple Installer inspection and Mac UID502 provisioning | Reduces PR count but crosses independent signer/host/installation/security trust boundaries and lacks prerequisites | **Reject**; distinct approved phases |

## Trust boundary and component diagram

```text
approved disposable, credential-free, network-denied verifier sandbox
  independently authenticated pinned runner + fixed read-only test policy
                         |
operator -> fixed synthetic fixture ID -> trusted writer-excluding ingestor
                         |                   |
                         |           bounded private sealed memfd
                         |             F_ADD_SEALS + readback
                         |                   |
                         |        full SHA-256 + exact byte count
                         |                   |
                         +---- fixed approved handoff mode
                                      |
                       exact pinned Sigstore verifier binary/runtime
                       + independently anchored test-key root
                       + certificate SAN/OIDC, log inclusion, signed-time
                                      |
                        bounded authenticated exit/result parser
                                      |
                          JSON: SYNTHETIC_ONLY | B0A_REFUSED

No caller-supplied hash/root/signer/binary, no downloaded package,
no artifact trust/UID502 token, no B0b, no Mac orchestration side effect.
```

**Units and responsibilities** (planned names; no code exists yet):

1. `ops/live-e2e/gate_b0_source_verification.py`: narrow fixed invocation and fail-closed status/result assembly; never resolves a verifier via ambient `PATH`; never imports candidate macOS Python.
2. `ops/live-e2e/gate_b0_immutable_bytes.py`: ingestor trust preconditions, bounded exclusive-writer-control proof, copied sealed `memfd`, seal-readback, original-kernel-object identity, complete SHA-256 and length. **An uncooperative, concurrently mutable file cannot be made safe by stat/hash/retry or advisory lock.** If caller cannot supply a trusted ingestion/exclusive-writer witness, refuse *before* copying; a sealed destination alone does not retroactively prove original-source consistency.
3. `ops/live-e2e/gate_b0_sigstore_adapter.py`: strictly pinned verifier executable/runtime, arguments, offline roots/log/time rules, mode-specific authenticated FD or digest handoff, bounded exit, timeout/output, independently validated status. A success-looking stdout string cannot authenticate itself.
4. `ops/live-e2e/gate_b0_evidence.py`: fixed, bounded canonical result schema; no secret dumps, approval booleans or caller-selected privilege escalation.
5. `tests/ops/test_gate_b0_source_verification.py` and focused fixture data: bounded genuine test signed material, positive/negative and no-network admission/exit tests. Single PR also updates `docs/development-methodology.md`, `docs/development-plan.md`, and the operator runbook; **do not** alter existing Gate A/UID502 preflight statuses or native E2E workflows.

## Interface and result semantics

The human-facing intent is **one command**, using a fixed fixture ID in a **separately approved pinned runtime**; this is a proposed UX, not a shell command authorized for execution:

```text
<independently-attested-absolute-runner>/som-b0a verify-synthetic \
    --fixture signed-test-key-1 --format json
```

The wrapper supplies fixed authenticated synthetic policy, input and bundle descriptors internally from its own controlled fixture set. The CLI accepts **only allowlisted fixture names**; no user `--policy`, `--root`, `--binary`, `--mode`, `--approved`, arbitrary path, remote URL, `--insecure`, `--online`, `--fallback`, `--installer`, `--sudo`, or real production artifact route in this feature. The precise executable location, pinned binary/loader and strict exec argv are part of a later **separate T5 synthetic-policy signoff**, not a path to guess here. No runtime dependency installation or trust root fetching at verification time.

Proposed **versioned JSON envelope** (keys are exact; fixed schema, at most 16 KiB, bounded string lengths, no secrets):

```json
{
  "schema": "som.b0a.synthetic.v1",
  "status": "SYNTHETIC_ONLY",
  "reason_code": "TEST_SIGNATURE_VERIFIED",
  "fixture_id": "signed-test-key-1",
  "measured_sha256": "<64 lowercase hex measured over sealed bytes>",
  "measured_length": 0,
  "policy_digest": "<64 lowercase hex independently pinned test policy>",
  "snapshot_ref": "<bounded sealed-object evidence reference>",
  "verifier_digest": "<64 lowercase hex independently pinned executable/runtime closure>",
  "bundle_digest": "<64 lowercase hex observed test fixture bundle>",
  "evidence_class": "NON_AUTHORIZING_SYNTHETIC"
}
```

The `0` length and angle-bracketed fields above are **schema examples only, never test results**. An actual GREEN must contain nonempty test fixture bytes and real measured values. A refusal emits `status=B0A_REFUSED`, a stable generic `reason_code`, and only independently known non-sensitive fields; no hash or signer value is fabricated for missing witnesses. Strictly refuse unknown/malformed schema, conflicting statuses, extra fields, output overflow, untrusted process identity, crash/timeout and unauthenticated evidence. No result is a reusable authorization token, a `source_verified` boolean or an authenticated proof beyond the reviewed trust chain. Exit `0` means **only** a successful synthetic test exercise; nonzero means refusal/error, never implicit retry or downstream promotion.

## Ingestion and exact cryptographic proof

1. **Pre-admission:** verify exact trusted sandbox/runtime, fixed authenticated test-policy revision (a deterministic digest is a cross-check, not proof of operator approval), synthetic fixture origin, exclusive writer control over the same source object before any read, allowlisted bounded lengths and bundle/input size/depth limits. No uncontrolled source pathname ingestion and no file-descriptor identity substitution.
2. **Snapshot:** copy exactly and once from source under demonstrated writer exclusion into a **private anonymous memfd**; apply `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL` and verify readback *before* hashing. Reject absent kernel sealing, mutable aliases, short reads, over-budget data, unexpected FD/object changes and any attempted mutation/restore race even when inode/size/mtime match.
3. **Measurement and mode:** hash **all sealed bytes**, record exact length and original kernel object; check **independently anchored** test artifact digest/length. Explicit **one** handoff mode from reviewed test policy: (a) the **same** sealed FD verified by the exact supported CLI without reopening a path, or (b) an **authenticated locally measured** `sha256:<64hex>` handed directly from trusted hasher to pinned CLI, which cryptographically checks the same digest against signed bundle. Digest-bound was made conditionally eligible by merged plan amendment PR #263, **but no mode is yet selected**; inability to meet the chosen mode => refuse, never a mutable path fallback.
4. **Signed bundle:** require the exact approved test SAN, OIDC issuer, Fulcio/CT policy, Rekor log/key and *cryptographically authenticated* inclusion/signed-time witnesses, cert-validity bounds, policy clock/age/skew/revocation constraints and independently authenticated test roots. Rekor v1 `integratedTime` or an OS wall clock alone is not automatically an independently trusted timestamp. Unknown bundle generation, incompatible DSSE/Hashedrekord version, stale embedded/cache root or missed offline revocation => refusal.
5. **Verifier execution:** independently pin exact binary and complete loader/interpreter/library closure, fixed process identity, fixed args, network-disabled isolation, stripped environment, bounded FDs/stdout/stderr/CPU/memory/time, authenticated exit; no `pip install`, auto-TUF update, ambient `PATH`, trusting bundle-supplied anchors, auto-upgrade/downgrade or fake output. A CLI that cannot show genuine test GREEN is **not** eligible.
6. **Report:** emit only synthetic evidence if the same approved sealed content→measured digest→correct signed bundle→approved fixed verifier/root/time chain passes. All other cases produce `B0A_REFUSED` with a stable reason. Keep any audit/custody receipts immutable and separately authenticated; the JSON alone cannot convey operator authority.

## Acceptance matrix for the one functional PR

| Exercise (TDD, then exact-head CI) | Required observable outcome |
| --- | --- |
| Independently pinned real verifier + approved test signer/OIDC/root, log inclusion and signed time, test-key bundle signing **independently sealed** fixture bytes | `SYNTHETIC_ONLY` with measured SHA/length and bounded evidence. **GREEN mandatory**; no always-REFUSE or mock adapter |
| Same-length different sealed bytes with original valid signature/bundle | `B0A_REFUSED` because signed digest no longer matches measured bytes |
| **Message-signature** bundle valid original signature over measured bytes, mutate **only** `message_signature.message_digest.digest` | `B0A_REFUSED` specifically for **bundle-declared digest consistency**, not generic bad signature; only when approved fixture format supports this form. Independent Rekor v2 DSSE/Hashedrekord fixture checks if that format is allowed |
| Same inode concurrent writer/restore, stale mtime, writable alias, FD substitution, incomplete read, missing writer witness, wrong seal/readback | **Refuse before verifier admission**, not a he-said-she-said before/after hash result |
| Wrong test signer/OIDC, valid key with wrong identity, changed roots/log/issuer, expired/signing-time-incompatible cert, missing inclusion/TSA, stale/unknown revocation or offline freshness | Refuse; no network/TUF cache fallback |
| Caller-forged `approved=true` or hash/size, wrong CLI/binary/loader digest, hostile PATH/env/FD, unbounded output, timeout/crash/fake success JSON | Refuse; no authority promotion or secret leak |
| Unknown fixture, malformed bundle, oversized/deep container, changed policy, replayed custody, B0a→B0b same-name/same-size different bytes | Refuse; if later transferred, `B0_UNVERIFIED` at independent B0b join |
| Run user-facing synthetic command in the **authorized isolated runner** with network denied; observe deterministic schema/exit and no host mutation | Reproducible operator evidence; **not** actual Python.org source, Mac installation or UID502 acceptance |

Test design must demonstrate the real pinned signature verifier returns genuine GREEN and the paired REDs under **the same tested verifier/tool-root policy**; tests must not replace the verifier with a stub that prints success. Unit tests may mock process failure paths, but those cannot satisfy integration acceptance. Local focused RED→GREEN, adversarial and schema coverage, dual-version hosted full collection, independent project-wide/security review and exact-head CI apply. Any later change to the exact verifier/config/policy SHA restarts the evidence gate.

## Independent approvals and stage boundaries

| Stage | Required decision | State at spec authoring |
| --- | --- | --- |
| **This design** | Operator reviews written spec and approves boundaries; then reviews written implementation plan and selects execution method | **Pending written-spec review** |
| **Synthetic T5 policy** | Independently approve exact pinned external verifier runtime/binary/closure and authenticated test keys/roots/log/time, fixed numeric freshness/revocation, selected explicit handoff mode and permitted fixtures | **UNRESOLVED; no real test execution** |
| **Synthetic implementation** | Explicit operator approval after spec and written plan review; isolated feature worktree, complete RED/GREEN tests and one functional PR | **NOT YET AUTHORIZED** |
| **Real CPython material** | Separate T1–T5 artifact signer/OIDC/release/expected SHA+size/trust/offline/mode/tool plus explicit artifact acquisition/use authorization | **UNRESOLVED; not included** |
| **B0b and onward** | Immutable full-byte/size/release/policy B0a→B0b custody, Apple Developer ID **Installer**/notarization/effects and source decision, then B1/B2/B3 UID502/APFS/B4 | **UNVERIFIED; separately gated** |

**Fail-closed milestone:** If exact synthetic test-key verifier/root/time cannot be selected and independently authenticated, do not report even `SYNTHETIC_ONLY`, do not quietly reduce the test scope, and **do not market refusal-only code as the completed user feature**. Escalate that precise blocking T5 decision for operator review. The old Homebrew UID501/GID80 interpreter remains BLOCKED; Linux Slice C stays DEFERRED.

## Operator design review questions

1. Approve synthetic-only CLI as the **one complete function** (rather than asserting unapproved production source verification), plus fixed single-command JSON user acceptance?
2. Approve the security split: genuine test-key verifier GREEN needs a **separate exact pinned T5 synthetic tool/root/time/mode decision** before code execution; real macOS `.pkg` remains independently forbidden until T1–T9?
3. Confirm next process after this **written spec**: author reviewed implementation plan on **the same feature branch**, then TDD code/tests/docs/runbook and finally one PR; no separate spec-only PR.
