# ADR 0019 Gate B0 — CPython macOS source-trust policy research (PROPOSED / UNAPPROVED)

**Research date:** 2026-10-15 (America/Toronto)
**Baseline:** main `85b2009a5869758f6d2b29c21e894565c91bae6a` ([PR #260](https://github.com/zhangyuz/ssh-over-mcp/pull/260)), [Issue #259](https://github.com/zhangyuz/ssh-over-mcp/issues/259).
**Authority:** **NONE.** This is a read-only review dossier for an operator/security decision, NOT approved artifact retrieval, signature verification, B0a code implementation, Mac installation, fixture execution or product launch.

**Governing design:** [Gate B signed-source decision](../superpowers/specs/2026-10-15-adr19-gate-b-macos-interpreter-source-decision-design.md) and [approved *written* B0 verification plan](../superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md). Its independent trust/signer/revocation/effects operator gates remain mandatory.

## Source-backed facts (public upstream metadata only)

| Subject | Publicly published observation | Primary source | Evidence boundary |
| --- | --- | --- | --- |
| Candidate release | CPython **3.13.16**, release date 2026-09-30 | https://www.python.org/downloads/release/python-31316/ | No actual archive bytes measured |
| Exact macOS installer name | `python-3.13.16-macos11.pkg` | https://www.python.org/ftp/python/3.13.16/ | Exact basename alone is not identity |
| Published SHA-256 | `30666509020b4da0dd8bc2e773255f34d76b7bb80b66960a928d5f6daa0192d7` | https://www.python.org/downloads/release/python-31316/ | Published digest, NOT independently approved or measured |
| Published package size | **70,394,335 bytes** in the public artifact index | https://www.python.org/ftp/python/3.13.16/ | Listing metadata only; future B0a AND B0b must measure full actual bytes and bind digest, size, policy |
| Available detached materials | `python-3.13.16-macos11.pkg.sigstore` (listed 7,305 bytes), plus corresponding `.crt`, `.sig`, `.asc` | https://www.python.org/ftp/python/3.13.16/ | Listing presence proves neither signed artifact authenticity nor trusted signer |
| CPython 3.13 *release-manager* Sigstore identity guidance | `thomas@python.org`, OIDC issuer `https://accounts.google.com` | https://www.python.org/downloads/metadata/sigstore/ | **Candidate only**: must not infer that this specific macOS `.pkg` was signed by this exact identity |
| Python.org macOS Developer ID installer identity guidance | Python Software Foundation, Apple Developer ID Team `BMM5U3QVKW` for versions since 3.11.4 / 3.12.0b1 | https://www.python.org/downloads/ | Expected **separate Apple Installer** identity; does NOT establish present package's leaf CMS cert, expiry, notarization or revocation |
| Legacy OpenPGP signing distinctions | Python.org notes Ned Deily keys for macOS binaries; Thomas Wouters key applies to 3.12/3.13 **source files and tags** | https://www.python.org/downloads/metadata/pgp/ | Do not generalize a source-release signer to every macOS binary or confuse GPG, Sigstore and Apple signing systems |
| Sigstore offline root semantics | `--offline` disables trust-root refresh; cached/embedded root can be stale or omit revocations. An independently supplied trust config is a documented option. | https://sigstore.github.io/sigstore-python/advanced/offline/ | **Offline does not mean fresh or independently authentic**; pending root distribution/freshness decision |
| Sigstore digest-only proof / standalone verifier | Python.org documents `sha256:<digest>` verification with sigstore-python **3.3.0+** and recommends `cosign` if standalone binary needed | https://www.python.org/downloads/metadata/sigstore/ | Version floor is NOT a pinned trusted verifier binary or its provenance; CLI compatibility with immutable sealed bytes must still be proven |

No package, signature bundle, certificate, trust root, transparency checkpoint or verifier binary was downloaded or executed during this documentation slice. No underlying Mac filesystem or interpreter identity was measured. These rows deliberately do **not** elevate the chosen package to `B0_VERIFIED`.

## Candidate verification architecture and alternatives for independent approval

1. **A — pinned independently authenticated verifier + immutable bytes (preferred to evaluate, NOT approved).** A separately trusted, hash-pinned verifier capable of validating a Sigstore bundle or digest, fixed signer/OIDC policy, pinned trusted roots and offline transparency/timestamp proof receives the SHA-256 of the *same sealed byte snapshot* that has been hashed and is custody-bound to B0b. A digest-only CLI interface must never skip actual-byte hashing, approved root/time checks, bundle-to-digest binding or immutable ingestion proofs. Need an explicit test of exact verifier version, binary dependencies, trust-root digest and `memfd`/descriptor input semantics.
2. **B — independently pinned standalone `cosign`** (source guidance's fallback): avoid executing a Python verifier whose own interpreter might lack independent trust, but still requires static binary/loader provenance, digest, compatible bundle verification, trust-root configuration and freshness. This is an evaluation candidate, not permission to install or run it.
3. **C — STOP / remain `B0_UNVERIFIED`** if neither method can prove trustworthy signer policy, root freshness, same sealed immutable bytes or a safe cross-stage handoff. Do not use `pip install`, curl-pipe-shell, user-controlled PATH, embedded cached roots of unknown freshness, self-reported approval booleans, or the unapproved CPython itself to bootstrap trust.

The existing B0 plan is the binding constraints document. This dossier does **not** select tools, signers or anchors on the operator's behalf.

## Decision ledger — every unresolved item is a fail-closed gate

| Decision ID | Required evidence / approving party | State |
| --- | --- | --- |
| T1: Artifact-specific Sigstore identity | Operator/security independently approve the exact binary's certificate SAN/email, OIDC issuer and expected signing role; distinguish observed bundle identity from normative expected signer | **UNRESOLVED** |
| T2: Independent expected artifact | Independently approve immutable release ID, full SHA-256 and **70,394,335-byte published size** as a comparison policy, separate from retrieval channel; on later authorized handling, measure actual bytes | **UNRESOLVED** |
| T3: Sigstore trust anchors | Independently approve exact Fulcio/Rekor roots/log IDs, signed trust-config/TUF provenance, digests, exact allowed roles and rotation rules. Reject an installer-/bundle-supplied root | **UNRESOLVED** |
| T4: Expiry, signing-time and revocation | Fix explicit offline maximum staleness/clock skew, historical signing-time proof, root/leaf/log validity, transparency inclusion, expiry/revocation evidence and how unavailable checks refuse | **UNRESOLVED** |
| T5: Verifier supply chain | Choose exact standalone/pinned verifier artifact revision/hash, trusted bootstrap execution dependencies and hermetic network-disabled mode; demonstrate correct `sha256:` + `.sigstore` semantics on synthetic fixtures before any real use | **UNRESOLVED** |
| T6: B0a source snapshot & B0b custody | Verify writer isolation, sealed immutable original bytes before digest; exact verifier byte binding; immutable cross-host transfer and **full digest + length + policy revision** equality join; reject restored-write and mismatched-package attacks | **UNRESOLVED** |
| T7: Apple Installer proof | Independently approve Developer ID Installer team/leaf chain, notarization/ticket and cert-purpose/timestamp/revocation validation, OS tooling/trust roots on separate isolated Mac | **UNRESOLVED** |
| T8: Package script/effects policy | Enumerate nested receipts, scripts, BOM, symlinks, global PATH/LaunchServices/hooks and allowlist allowed paths/operations; reject unknown/unreviewed effects before B0 source approval | **UNRESOLVED** |
| T9: Execution authorization | Separate written approvals for B0a code, any actual package/bundle retrieval, B0b Mac-only inspection, B1 provisioning, B2 trusted collector, B3 original UID502 nine-row fixture and B4 staging/release | **UNRESOLVED** |

**Important policy distinction:** `thomas@python.org` (3.13 Sigstore release-manager table) and `BMM5U3QVKW` (macOS Apple Installer Team) are **not competing values for one check**. They live in separate cryptographic trust schemes. The artifact-specific Sigstore identity **still needs evidence**; neither identity may be inferred merely from the published index and neither substitutes for B0b CMS verification.

## Next smallest authorized step

Obtain independent security/operator review of this metadata-only dossier; the reviewer should challenge the assumed binary Sigstore identity, offline trust-root freshness and inability to hand off sealed bytes to a concrete verifier. After written trust-policy selection/approval, prepare a **separate exact-code TDD slice** with red/green synthetic adversarial fixtures, without actual candidate retrieval, Mac host use or positive release authorization. The executable B0 verifier is **NOT** implemented by this PR.

All B0–B4 remain **UNVERIFIED**, original nine-case UID502/APFS acceptance is **not run**, and existing Homebrew UID501/GID80 group-writable ancestry is **BLOCKED**. Linux Slice C remains deferred under [Issue #256](https://github.com/zhangyuz/ssh-over-mcp/issues/256).
