# ADR 0019 B0a — digest-bound offline Sigstore verifier interface (design proposal)

**Date:** 2026-10-15 (America/Toronto)
**Status:** PROPOSED — separate operator/security design review needed; **NOT B0a implementation or source approval**.
**Base:** merged main `663f82dc4f4a40cecbce562b0b7b9c92379def0d` ([PR #261](https://github.com/zhangyuz/ssh-over-mcp/pull/261)).
**Governing decisions:** [Gate B source trust architecture](2026-10-15-adr19-gate-b-macos-interpreter-source-decision-design.md), [approved B0a/B0b written plan](../plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md), [source metadata dossier](../../evidence/2026-10-15-adr19-b0-signer-trust-policy-research.md) and [Issue #259](https://github.com/zhangyuz/ssh-over-mcp/issues/259).

## Problem and explicit non-goals

The approved B0a plan mandates one bounded **immutable** package snapshot for byte hashing and Sigstore signature verification, but leaves the **independently trusted verifier interface** unresolved. Passing a pathname to an external verifier can reopen attacker-mutable data. Some verifiers cannot consume an inherited sealed `memfd` correctly. Inventing a path-based fallback would violate the plan.

This documentation slice proposes **content-addressed digest verification** as a *candidate* interface: an independently approved verifier consumes the **digest computed over the sealed snapshot**, not the original package pathname. Its cryptographic signature verification must bind the bundle to that digest. It cannot remeasure physical bytes; the separately trusted hasher/snapshot procedure provides that proof. The two stages remain part of **one security-reviewed trust chain**; a signed/reported hash alone is insufficient.

**Not in scope:** executable B0a code, invoking a verifier, downloading package/bundle/root metadata, Mac host inspection, package installation, provider workflow, sudo/UID502, Gate A schema rewrite, protected staging, Linux C, or a macOS release claim. B0a/B0b/B1–B4 remain **UNVERIFIED**.

## Alternatives and selection for independent review

| Candidate | Advantage | Risk / rule | Status |
| --- | --- | --- | --- |
| A. **Digest-only Sigstore verification** `sha256:<measured-digest>` + separately supplied bundle | Verifier never opens an attacker-controlled artifact pathname; supports a single sealed byte snapshot without FD inheritance | Only valid if independently pinned verifier *actually* verifies signed bytes/digest and identity/issuer/log/time against trusted, fresh enough roots, and **never** treats a supplied digest alone as authority | **Preferred interface to review**, not approved implementation |
| B. Direct identical sealed-FD handoff | Verifier sees exactly the sealed kernel object | Requires independently verified FD-inheritance support, enforcement and no second file opens across the entire verifier runtime | Valid alternative after separate reviewed proof |
| C. Unsealed filename, ambient PATH, cached trust root by default or self-reported success | Easy superficially | Opens TOCTOU, signer/identity and trust-root downgrade paths | **REFUSE**, not a fallback |

**Independent upstream interface evidence (public documentation only):**
- `sigstore-python` verifies a digest prefixed `sha256:`, with an explicit `--bundle` and expected `--cert-identity` / `--cert-oidc-issuer`: https://sigstore.github.io/sigstore-python/verify/
- Sigstore `--offline` prevents root refresh and can use **stale cached/bundled roots**. A separately distributed `--trust-config` exists, but is not independently trusted merely by being a file: https://sigstore.github.io/sigstore-python/advanced/offline/
- Sigstore's published `cosign verify-blob` examples also require explicit bundle + certificate identity/issuer: https://docs.sigstore.dev/cosign/verifying/verify/
- Python.org lists publicly published macOS artifact metadata and signing guides; the **artifact-specific** Sigstore identity is NOT independently confirmed: https://www.python.org/downloads/release/python-31316/ and https://www.python.org/downloads/metadata/sigstore/

These sources establish that an API *may support* digest-only verification, not that a specific verified binary, exact CLI version, trust root or CPython macOS signer has been selected. Actual tool interoperability is a **separate test and approval gate**.

## Proposed narrow B0a evidence flow (no new code authorized here)

1. **Independent immutable policy:** operator/security signs off *before use* on exact release/name/expected SHA-256 and expected length; specific macOS `.pkg.sigstore` signer identity + OIDC issuer; trust-root/issuer/log IDs, signed trust-config/TUF provenance and maximum offline age; explicit revocation/time policy; verifier exact binary/loader version and hash; approved immutable-snapshot and evidence semantics. The current [T1–T9 ledger](../../evidence/2026-10-15-adr19-b0-signer-trust-policy-research.md) is unresolved, **not** a filled policy.
2. **Acquire bytes only after a separate artifact-use authorization.** Isolated credential-free, non-privileged B0a environment must prove bounded ingestion, no uncontrolled concurrent writer, and a kernel-enforced immutable snapshot (for instance verified write/grow/shrink/seal `memfd`). An open FD, file mode, stable inode/mtime/size or before/after hash alone is **not** sufficient. On failure, **REFUSE** without a signature-verification attempt.
3. **Hash exactly those sealed original bytes**, compare full SHA-256 and measured length to approved policy, bind evidence to sealed snapshot identity; never compute from a caller-reported digest. The hasher's own independent execution source, dependencies, original sealed byte identity and integrity are required evidence. Retain no writable artifact alias.
4. **Digest-bound verification:** supply ONLY `sha256:<hash-of-sealed-bytes>` plus the independently received bounded untrusted Sigstore bundle to an independently pinned verifier; require pinned *exact* certificate identity and OIDC issuer, verification of the bundle's signed message/digest, Fulcio chain, Rekor inclusion/signed time, approved historical-time rules and independent trust root/freshness. Verification output must be authenticated against the intended verifier process and bounded/parsed defensively. **Never** let unverifiable flags, bundle-supplied roots, offline default caches or nonzero/ambiguous output become success. If the chosen CLI cannot prove digest↔signature binding or exact root/time policy, **REFUSE** and reopen interface review.
5. **B0a result is never an authority token:** only `B0A_EVIDENCE_COLLECTED_UNAPPROVED` or `B0A_REFUSED`. Even a synthetic fixture "pass" is `SYNTHETIC_ONLY`. No `HOST_PROVENANCE_VERIFIED`, no source acceptance and no claim that signer has been approved.
6. **B0b remains separate:** after its own authorization on isolated Mac, it must independently measure a verified immutable copy and compare complete digest, length, canonical release/artifact ID and **approved policy digest/revision**, with authenticated custody and exact B0a evidence. Apple Developer ID Installer CMS/notarization/revocation and script/BOM/effects approval are mandatory regardless of B0a result. Mismatches or replay → `B0_UNVERIFIED`.

## Adversarial TDD matrix for a future separately approved minimal implementation

| RED test input | Required refusal (never a trusted source) |
| --- | --- |
| Matching caller-supplied digest but altered sealed content | Byte hash or policy mismatch; no verifier admission |
| Same inode written concurrently then restored to previous size/mtime during capture | Refuse without proven writer exclusion; metadata cannot rescue |
| Snapshot not sealed, failed seal, writable alias, incomplete read or missing byte-count proof | Refuse before verifier invocation |
| Correct snapshot bytes but bundle signs *another* digest | Refuse signature/digest mismatch |
| Cryptographically valid bundle from wrong certificate identity or OIDC issuer | Refuse despite a correct SHA |
| Stale/expired/unpinned root, uncertain revocation, absent inclusion/time witness or silent network fallback | Refuse regardless of signature outcome |
| Digest-only CLI unexpectedly reads an untrusted filename, uses ambient PATH or wrong binary revision | Refuse and reopen verifier interface review |
| Fake verifier success JSON, hostile nested object, timeout, crash, ambiguous exit, truncated output | Refuse with bounded diagnostic; no retry-as-trust |
| B0a/B0b same name/length but different actual bytes or different policy digest | `B0_UNVERIFIED` at cross-stage join |
| Replay an old B0a result or replace B0b custody record | `B0_UNVERIFIED`; operator cannot sign source acceptance |

**Implementation handoff, not permission:** after operator/security approve *this* written interface **and independently pin T1–T5 source identities/trust anchors/verifier policy**, prepare a fresh small TDD code slice strictly within the approved plan; prove RED→GREEN using synthetic fixtures on hosted non-privileged CI, and independently review the exact commit. Real package retrieval, B0b Mac inspection, provisioning, UID502/APFS original-code nine-case and staging/release each require additional explicit approvals.

**Reviewer questions:** Is the digest-only verifier an actually safe equivalence to the B0 plan's sealed-byte interface for the selected exact version? What precise, independently anchored hash-of-bytes + signature-to-digest + signer/issuer + offline root/time proof makes the chain non-circular? How is untrusted verifier output constrained? How can B0a's authenticated evidence survive custody into B0b without accepting a forged report?
