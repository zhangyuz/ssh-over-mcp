# T5B-0 next decision: inert candidate material collection (proposal)

**Date:** 2026-10-17. **Plan state:** PROPOSED; no material use or verifier execution authorized. Governing [Issue #259](https://github.com/zhangyuz/ssh-over-mcp/issues/259) process-only T5B-0 / T5B-1 split and [exact-material admission dossier](../../evidence/2026-10-17-adr19-t5b0-exact-material-admission-dossier.md) take precedence. This is **not** a replay of the policy-completeness preflight and does not ask for another false-green shape validator.

## Why this particular slice

A useful next feature is *independently attributable, exact-byte candidate collection* after its own authorization. Today we have a specific verifier candidate (`sigstore-python==4.3.0`, published wheel hash and PyPI attestation workflow/commit) but **no independently approved root/time/source**, no verified installer-specific bundle type, no exact verifier interpreter/loader/31-wheel closure, and no permitted execution image. Executing a verifier now would validate a circular source chain. Public registry metadata is evidence of **publisher claims**, not independent authority.

## Separate gate C0 — candidate material collection, not trust admission

**No actual collection under this PR.** Before any material access, operator/security must explicitly approve a fixed, revisioned manifest containing exactly: (a) a finite URL allowlist and **per-object** max byte length/digest *as untrusted comparison metadata*; (b) a designated fresh disposable unprivileged Linux environment, credential-free and not persistent E2E Mac, no target checkout execution and no privileged runner state; (c) tool source/arguments, read-only network scope to named endpoints, bounded transfer timeout, file descriptors, regular-file/symlink and parsing limits; (d) immutable local custody, arrival time and independent recomputed original-byte hashes; (e) refusal on redirect to unapproved origin, changed artifact, incomplete read, extra dependencies, download failure or unknown provenance; (f) deletion/retention policy and no trust/config import. Even if collected bytes equal their **publisher-listed** hashes, output is only `UNTRUSTED_CANDIDATE_BYTES`, never approval.

The manifest may propose only **inert** bytes from the explicitly named 4.3.0 PyPI wheel and PyPI provenance metadata, Sigstore root-signing/TUF metadata needed for historical chain research, and upstream release metadata. No transitive dependency auto-install or auto-fetch, downloaded root promotion, code execution, package retrieval or unbounded wildcard material. The 31-wheel claim is a *reported candidate count*; enumerate and independently validate the actual closure before any expansion. A separate reviewed amendment is required to add each exact dependency.

## Subsequent gate A0 — trust and runtime admission (independent decision)

Before any verifier execution, independently establish the **out-of-band** original TUF fingerprint and threshold/rotation chain, trusted UTC/skew/age/rollback cutoff, per-object immutable verifier/runtime/dependency manifest and source attestation under an independently approved root, signer SAN/OIDC, Fulcio/CT/Rekor/time/revocation policy, one measured-sealed-byte handoff mode, and an exact fixed-argv network-denied execution plan. Submit the resulting `A–F` evidence dossier for fresh independent review and **separate explicit T5B-0 admission and execution approval**. Any missing item is `T5B0_ADMISSION_REFUSED_INCOMPLETE`.

Only after that approval may T5B-1 run a real Sigstore verification test under the admitted exact tool/root/config with positive signed synthetic fixture and hostile RED; do not equate prior OpenSSL Ed25519 GREEN with Sigstore signed-time/root/log verification. The actual Mac `.pkg/.sigstore`, B0b Apple Installer checks, provisioning, UID502/APFS, staging and Linux Slice C each remain separate gates.

## In-scope acceptance of *this* documentation slice

- Public claim table has exact repository/tag/workflow/wheel digest and sources, clearly distinguishes observed GitHub ref from unverified PyPI attestation claim.
- Enumerates A–F individually missing independent proofs, their responsible authority and fail-closed status, and does not mark any T1–T9 as accepted.
- C0 decision is **precise and isolated**, requires further exact URL/object/host approval before collection and cannot accidentally authorize T5B-0 execution, T5B-1, macOS host, test runner or real package.
- No code, CI, package, trust root, verifier or Mac filesystem change. Docs link check, exact-HEAD hosted CI and independent whole-project/security review are required before an independently authorized docs merge.

**NEXT OPERATOR DECISION, pending:** approve *only* writing/reviewing an exact finite C0 inert-object collection manifest and separately consenting to the listed off-host collection after it passes review, OR supply an independently authenticated OOB root and clock witness first, OR retain HOLD. None of these is automatic from this plan's merge.
