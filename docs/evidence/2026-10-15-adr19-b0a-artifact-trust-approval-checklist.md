# ADR 0019 Gate B0a — independent artifact/trust-policy approval evidence checklist

**Date:** 2026-10-15 (America/Toronto)
**Status:** PROPOSED / UNAPPROVED; **all T1–T9 still UNRESOLVED**.
**Tracked by:** [Issue #259](https://github.com/zhangyuz/ssh-over-mcp/issues/259).
**Normative sources:** [B0 signer evidence dossier](2026-10-15-adr19-b0-signer-trust-policy-research.md), [B0a/B0b plan](../superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md), [digest-bound candidate design](../superpowers/specs/2026-10-15-adr19-b0a-digest-bound-offline-verifier-interface-design.md), [ADR 0019](../decisions/0019-protected-native-e2e-staging.md).

> **Authority boundary:** This is a human-review **checklist**, not a filled-in/approved trust policy, signed decision, executable configuration, approval record or permission to retrieve artifacts. The proposed digest interface in merged PR #263 is eligible for **later separate policy selection**, not selected or implemented. A passing synthetic test cannot approve real package provenance. No actual binary, bundle, trust root, verifier, installer or host has been downloaded, authenticated or executed by this documentation slice.

## Why this is a separate decision

Public Python.org metadata can name a release, published digest and general release-manager identity without authenticating **the specific macOS package signature**. A matching hash and bundle downloaded from one source are not independent trust anchors. Sigstore's documented `sha256:<digest>` verification interface does not independently measure the original installer bytes; and an offline invocation may use a **stale cached/embedded root**. Operator/security must independently pin both expected inputs and a verifier/trust policy *before* any B0a implementation or real artifact use.

Public, non-attesting references (not approval or root pins):
- CPython 3.13.16 public release / published pkg checksum: https://www.python.org/downloads/release/python-31316/
- Public installer/bundle index: https://www.python.org/ftp/python/3.13.16/
- General Python signing guidance (not binary-specific signer identity): https://www.python.org/downloads/metadata/sigstore/
- Sigstore digest interface: https://sigstore.github.io/sigstore-python/verify/
- Sigstore offline stale-root caveat and optional trust config: https://sigstore.github.io/sigstore-python/advanced/offline/
- Sigstore certificate/identity/log/time model: https://sigstore.github.io/sigstore-python/policy/

## T1–T5 independently approved evidence ledger (all PENDING)

| Gate | Candidate / open question | Required independent source and decision evidence | Fail-closed response |
| --- | --- | --- | --- |
| **T1 — exact macOS binary signer** | Python.org lists a CPython 3.13 release-manager identity `thomas@python.org` / `https://accounts.google.com`, **not** a measured `.pkg.sigstore` signer | Independently authorize **whether** acquiring only specific untrusted bundle/certificate metadata is permitted in an isolated environment; compare exact certificate SAN, OIDC issuer, signing role, Fulcio chain against a separately authenticated **expected** identity; reviewer names evidence source and signs policy revision | No bundle access approval, wrong/missing identity or only generic release guidance → **UNRESOLVED / B0A_REFUSED** |
| **T2 — approved expected exact artifact** | Published **`python-3.13.16-macos11.pkg`**, candidate SHA-256 `30666509020b4da0dd8bc2e773255f34d76b7bb80b66960a928d5f6daa0192d7`, listed size **70,394,335 bytes** | Operator independently accepts release/name, exact expected digest **and length** from authenticated review channel separate from future artifact retrieval; record immutable approval digest/revision; later separately authorized B0a and B0b each measure **all actual bytes** | Public listing only, digest claimed by artifact, missing/changed length or different source → **UNRESOLVED / REFUSE** |
| **T3 — Sigstore trust roots / log identities** | Which exact trusted Fulcio intermediate/root, Rekor key/log ID, signed TUF/trust-config snapshot and rotation chain are permitted? | Review and hash-pin authoritative root/config artifacts via independent channel; record object digests, signing chain, exact log and allowed certificate roles, distribution and rotation/rollback handling | Unpinned bundle-supplied cert as root, unavailable/mismatched roots or silent rotation → **REFUSE** |
| **T4 — offline time/freshness/revocation** | Choose maximum metadata age, reference time/clock skew, historical signature time, timestamp and inclusion proof, expiry and revocation disposition | Security/operator explicitly fixes **numeric** freshness/skew cutoffs and trusted clock source, root/leaf/log validity and revocation evidence. Prove offline data meets these bounds; document safe refresh outside target host | Cached/embedded root merely because `--offline`, missing secure time/revocation evidence, expired/ambiguous inclusion → **REFUSE** |
| **T5 — exact verifier supply chain / interface** | Independently trusted standalone `cosign` or `sigstore-python` runtime? Precise version/binary digest/loader closure unselected | Prove independently acquired and pinned tool **binary/runtime/dependencies**, network-disabled launch, fixed arguments/root/identity, authenticated process exit; show actual CLI version can verify a **test-key synthetic** known bundle against SHA independently measured over a sealed fixture, plus wrong-digest rejection | Ambient PATH, `pip install` on target Mac, floating dependency, fake CLI success, mismatched digest or always-REFUSE GREEN → **REFUSE** |

**No field above is approved by this document.** The labels `thomas@python.org`, SHA-256, byte length and versions are public **candidates** only. The Apple macOS Installer Developer ID team is a **different** cryptographic identity and belongs to B0b T7, not a substitute for T1.

## Decision record contract — no self-granted authority

Any future operator-facing signed policy decision must independently bind:
1. Exact artifact release/name, expected full SHA-256 **and byte length**, metadata source revisions, approver identity and approval time/channel.
2. Explicit `direct-sealed-FD` or `digest-from-sealed-bytes` mode; exact trusted hasher/verifier executables, dependency closure, fixed offline sandbox/network denial, binary digests and CLI semantics.
3. Exact artifact-specific signer SAN/OIDC/role, allowed Fulcio/Rekor/log root/key sets and independently authenticated trust-config/TUF revision/digest.
4. Numeric trusted-time, root freshness, skew, certificate/log validity, inclusion/signed-time and revocation rules; no default `--offline` cache trust.
5. Stable canonical policy digest/revision and authenticated custody of evidence, with explicit validity scope and revocation/rollback procedure. Missing or changed policy fields **must refuse**; do not infer approvals from a raw JSON key `approved: true`.

**Distinct approval transitions:** (A) review this checklist **only**; (B) security/operator approve exact T1–T5 policy and an explicit handoff mode; (C) separately approve synthetic-only B0a code; (D) separately approve actual installer/bundle acquisition and byte handling; (E) separately approve B0b isolated Mac inspection of Apple CMS/notarization/scripts/effects; (F) B1/B2/B3/B4 host/provisioning/UID502/staging are separately gated. Neither a merge nor any positive CI result performs these transitions.

## Mandatory negative/positive acceptance to propose later (not run)

- **Synthetic GREEN**: selected pinned verifier processes a bundle signed by a **test-key** over `sha256:<digest>` independently computed from a writer-isolated sealed test fixture, with fixed test signer/OIDC/trusted roots/log/time; result **`SYNTHETIC_ONLY`**.
- **Paired RED**: swap same-length fixture to get a different computed digest but retain original signed bundle → **`B0A_REFUSED`**; an always-refusing adapter cannot satisfy GREEN.
- Additional RED: self-reported digest/size, mutable source race+restore, stale roots/unknown revocation, valid signature from wrong OIDC identity, valid signature over wrong bytes, unknown log/checkpoint/time, substituted tool binary or root, ambiguous exit/forged verifier JSON, changed policy/custody replay.
- B0b still requires independently **immutable transferred bytes**, full rehash/length, exact approved policy revision and Apple Installer/effects review. Even synthetic GREEN never claims `B0_VERIFIED`, `HOST_PROVENANCE_VERIFIED`, original UID502/APFS nine-case acceptance or macOS release.

## Reviewer decision request

Review whether the **T1–T5 required evidence is sufficient, independently sourced and safely separable** from T6–T9. Flag any hidden trust-bootstrap loop, unavailable offline revocation/time witness or inability to demonstrate a safe verifier runtime. If actual policy cannot be pinned, explicitly choose **REFUSE / retain UNVERIFIED** rather than fabricating signer/root approval.

**Out of scope:** no B0 implementation, actual package or bundle retrieval, trust config/verifier installation, host privileges, CI workflow changes, provider cleanup, UID502/APFS physical fixture execution, staging release, or Linux Slice C. Actual B0–B4 remain **UNVERIFIED**; Homebrew path **BLOCKED**; Linux C **DEFERRED**.
