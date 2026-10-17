# B0a synthetic cryptographic proof — scoped implementation plan

**Status:** DRAFT; operator approval required for verifier selection and any production trust policy. **No real package, Mac host, roots, network, installer, or privileged action authorized.**

## Goal and existing boundary

PR #270 introduced shape-only B0 policy preflight. The existing `gate_b0_source_verification.py verify-synthetic` deliberately refuses because T5 verifier policy is unapproved. This feature must add a **real positive cryptographic proof**, plus paired hostile RED, without changing that production-facing refusal or asserting B0a authorization. A signed test payload is not a Sigstore bundle, Fulcio certificate, Rekor entry, or source approval.

## Proposed independently usable operator capability

A distinct test-only `b0a_synthetic_signature_proof.py` CLI verifies an **Ed25519** signature over a domain-separated, length-prefixed test payload with a test-only public key, producing `SYNTHETIC_ONLY` on valid proof and `B0A_SYNTHETIC_REFUSED`/exit 2 on tampering. The verifier implementation and source must be pinned for any acceptance claim; do not silently use ambient PATH or unapproved crypto libraries. Never accept a caller-provided key as a trust anchor, or claim the signature is Sigstore release-manager verification. Keep input and output bounded, nonblocking/no-follow, no special files, no networking, no private key in product tree, and no root/installer execution. A generated disposable test key is allowed only within the isolated test fixture and must never be used as production authority.

## Acceptance plan (RED → GREEN)

1. Verify clean main baseline and exact-main CI evidence (pending CI recorded honestly).
2. Add CLI adversarial tests first: signed known fixture GREEN expected; altered equal-length payload RED; altered signature RED; wrong public key RED; malformed input, FIFO, oversized JSON, deep JSON RED; timeout and no traceback. Confirm RED against missing feature.
3. Implement minimal isolated synthetic-only verifier, with immutable test fixture and bounded parsing; pin test verification implementation as a separate explicit review gate.
4. Demonstrate GREEN and paired RED on the **same cryptographic verifier**, and that original `verify-synthetic` still refuses. Report key/verifier provenance and platform limitations accurately.
5. Update evidence, roadmap, usage, and `progress.md`; run targeted tests, Ruff, hosted exact-head CI, independent whole-project/security review. Do not promote Ready until actual proof works and reviewer accepts it.

## Approval boundary / decision required

The project T5B gate requires a separately approved **exact Sigstore-compatible verifier executable/version/hash**, signer/OIDC issuer, trust roots/log IDs, time/revocation/offline freshness policy and approved digest-vs-sealed-FD handoff. A local OpenSSL test-key proof cannot satisfy those requirements. **Before selecting a test-only crypto implementation or introducing dependencies, obtain explicit review/approval of the synthetic verifier approach; before actual B0a source verification, obtain separate T1–T5 approvals.** Real package/bundle downloads, installation, UID502/APFS and Linux Slice C are excluded.

## Approved implementation decision (2026-10-17)

Operator approved **OpenSSL CLI for synthetic Ed25519 proof only**. Do not treat the ambient Homebrew OpenSSL at `/usr/local/bin/openssl` as a trusted Mac executable: it is a symlink in a historically group-writable Homebrew tree. For this feature, prefer **CI-hosted Ubuntu `/usr/bin/openssl`** with exact executable provenance recorded as test evidence, and refuse if a verified fixed executable is unavailable. The fixed test public key is pinned by SHA-256 in the verifier; a one-time generated test signature and length-prefixed payload are committed as immutable synthetic fixtures, with private key discarded. A test harness may generate an alternate disposable private key for wrong-key RED only. No test private key is committed. The hosted verifier remains a *test tool*, not an independently approved production T5B verifier.
