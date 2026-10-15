# ADR 0019 Gate B0 — offline signed-package verification plan (REVIEW DRAFT)

> **Execution boundary:** This document is a proposed RED→GREEN implementation plan, **not permission to implement it**, retrieve packages, install software, execute privileged Mac commands or run UID502. Review and approve the plan separately before code.

**Date:** 2026-10-15 (America/Toronto)
**Status:** PROPOSED; design/source-candidate decision merged in [PR #258](https://github.com/zhangyuz/ssh-over-mcp/pull/258), main `257792ec41c66b74b3b4d39fd23b51afd84b896f`.
**Tracking:** [Issue #259](https://github.com/zhangyuz/ssh-over-mcp/issues/259).
**Source of truth:** [Gate B trust design](../specs/2026-10-15-adr19-gate-b-macos-interpreter-source-decision-design.md), [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md), [macOS blocker matrix](../../evidence/2026-10-15-macos-native-release-blocker-inventory.md), [development methodology](../../development-methodology.md).

## Goal, result semantics and scope

Produce an **independently repeatable, non-executing B0 source-verification procedure** for the one candidate `python-3.13.16-macos11.pkg`, using **actual supplied bytes** only after future explicit B0 implementation/artifact-use approval. An initial future **B0a** code slice can prove the artifact digest and independently verified Sigstore bundle on an isolated, credential-free, non-privileged verifier. A distinct **B0b** approval/evidence step is required to assess Apple Installer CMS signing, notarization/revocation policy and *all* package effects. Only an operator-reviewed combination may support an **artifact-source decision**. Neither B0a nor B0b provisions an interpreter, attests installed files, runs UID502, or makes the SOM product macOS-ready.

- In this **docs-only PR**, **no artifact bytes, signature bundles, verifier binaries or package contents are downloaded, read or executed**.
- Future B0 verification must run **off the trusted native orchestrator** in a disposable non-privileged environment. Any Mac-only verification requires a separately approved isolated inspection host, not `Yuz.local`'s persistent E2E runner. Do not bootstrap an untrusted Mac Python to prove itself.
- There is **no automatic authority bit**: B0a output is at most `B0A_EVIDENCE_COLLECTED_UNAPPROVED` and `B0A_REFUSED`; a signed/human approval decision is a separate evidence record, not a caller-provided bool. Gate A statuses and UID502 preflight stay unchanged.

## Locked artifact and independently reviewed trust policy

Candidate *published metadata*, **not an independently verified actual artifact**:

| Field | Pinned candidate |
| --- | --- |
| Project/release | CPython 3.13.16, 2026-09-30 |
| Archive name | `python-3.13.16-macos11.pkg` |
| Published SHA-256 | `30666509020b4da0dd8bc2e773255f34d76b7bb80b66960a928d5f6daa0192d7` |
| Release URL | https://www.python.org/downloads/release/python-31316/ |
| Artifact index | https://www.python.org/ftp/python/3.13.16/ |
| Detached Sigstore material | `python-3.13.16-macos11.pkg.sigstore`; `.crt`, `.sig` and `.asc` appear in the public index; presence is **not** verification |
| Target eventually | Trusted macOS **x86_64** orchestrator; NOT Ubuntu guest or managed host |

Published signing *candidates* to independently confirm and pin in a **separate operator-approved trust-policy record** before an implementation may grant even B0a evidence:

1. Python.org's [Sigstore identity guidance](https://www.python.org/downloads/metadata/sigstore/) lists CPython **3.13** release manager `thomas@python.org`, OIDC issuer `https://accounts.google.com`. This **must not be assumed** to be the exact identity in this **macOS installer bundle**: inspect and independently approve the artifact-specific certificate subject, issuer, issuer URL, trust root(s) and identity policy. A bundle authenticating a different identity remains **REFUSED/PENDING REVIEW**, even if otherwise cryptographically valid.
2. Python.org's [macOS installer signing guidance](https://www.python.org/downloads/) publishes Python Software Foundation Apple Developer ID team `BMM5U3QVKW` for newer macOS installers. This is an **expected candidate, not a measurement** of this package's Developer ID Installer certificate, signing chain, notarization or active trust. Independently verify exact certificate purpose, leaf identity/team, intermediate/root, temporal validity and revocation policy in B0b.
3. **Independent trust establishment is mandatory**: record who pinned expected release/hash/identity/roots, from what reviewed source/channel, at what revision/time, with operator signoff. Downloading an artifact and its checksum/signature/trust-policy JSON from the **same** untrusted endpoint is not two independent trust roots. Do not trust installer-supplied certificates as anchors. If trust roots are unavailable, expired, unexpectedly rotated, contradictory or cannot be authenticated, **refuse**.
4. Decide and document the Sigstore verification implementation **before coding**: independently trusted verifier binary/package + exact version/digest, offline verification API, immutable tested Sigstore root/TUF metadata and expiry/freshness limits, certificate identity and OIDC issuer checks, transparency-log inclusion and signed-time validation. No transparent network fallback if offline proof or revocation/freshness cannot be established. A valid signed bundle with stale or unavailable trust information is **not sufficient**.
5. B0b explicitly records Apple macOS Installer CMS/Gatekeeper/notarization checks and revocation/time failure behavior. If offline verification cannot establish the required Apple assurance, retain `B0_UNVERIFIED` and obtain separate approval for a safe online independent verification environment; never silently skip it.

**Required unresolved decisions before implementation approval:** exact signer policy for this macOS `.pkg.sigstore` (including any binary-builder identity difference), independent expected-digest evidence, trusted verification tool and root provenance, offline freshness/revocation cutoff, full Installer operation policy. Record each in the PR review; **do not auto-fill** by accepting observed metadata.

## Threat model and hard refusal rules

Treat the downloaded or fixture package bytes, filename, URL, CMS certificate, Sigstore material, package scripts/BOM, path metadata and evidence files as **untrusted** until validated by independent pinned policy. Refuse:

- Incorrect or absent bytes, hash/version/name mismatch; any mismatch between independently approved digest and full **streamed actual bytes**.
- Same-digest self-reported strings without measured bytes, malformed signatures, wrong cert identity/OIDC issuer or Apple team/purpose, expired/revoked/unverifiable chain, missing offline trust root or valid log inclusion/time, old or forged verification results.
- Symlink/alias/TOCTOU input replacement, re-opened mutable artifact, changed size/mtime/inode while streaming, partially read file, truncated/overlong data; select a pinned original regular-file descriptor or verified immutable snapshot. Reject if the pinned bytes cannot also be the signature-verifier input; no basename-only reopen of attacker-controlled paths.
- Parser bombs, oversized XML/JSON/bundle metadata, duplicate/conflicting fields, unsafe compression expansion, traversal/absolute paths, escapes, special files or unknown nested installer payloads. Bound bytes, depth, counts and runtime **before** any recursive evaluation, sorting, or comparison on arbitrary attacker objects.
- Package installation scripts with unreviewed shell/network, application-launch, privilege escalation, global symlink/PATH changes, package receipt changes, update hooks, uncontrolled writes or postinstall behavior. **Listing** scripts is not approving them. A package with incomplete or uninspectable operations remains refused.
- Unsafe verifier acquisition or unpinned dependencies; hidden network calls; any `curl | sh`, `pip install` on the target Mac, `installer` invocation, chmod/chown, root/UID502 invocation, dynamic execution of package scripts, provider/runner changes, or running the candidate Python itself.

A package's authentic signature does **not** imply a safe system-wide installation. Package signing, content/effects approval, installed provenance and point-of-use loader closure are four distinct proofs.

## Proposed execution slices (each separately authorized)

### Slice B0a — bounded offline source proof, **future code PR only**

**Allowed paths in a later approved implementation PR (proposal, not permission):**
- `ops/live-e2e/gate_b0_source_verification.py` — one narrow offline artifact verification entrypoint using an **independently approved** verifier, not candidate Python; no download/install, no Mac runner integration.
- `tests/ops/test_gate_b0_source_verification.py` — hostile synthetic tiny package/signature fixtures and controlled verifier results.
- `docs/evidence/2026-10-15-adr19-gate-b0-source-verification.md` and `docs/development-plan.md` — measured results and precise UNVERIFIED states.
- No `.github/workflows/**`, native guest/provider paths, `src/**`, installed interpreter paths, GitHub secrets/permissions, Gate A or UID502 preflight changes.

**Task 1 — input/type/budget boundary (RED→GREEN):** define exact immutable release policy and artifact-byte descriptor contract with bounded primitive-only fields. Reject forged/oversized/duplicate fields, symlinked or mutable inputs and mismatched identity labels before downstream work. Test missing bytes and malicious objects; RED on absent module, GREEN on minimal refusal path. No signed output yet.

**Task 2 — actual-byte SHA and artifact binding (RED→GREEN):** stream **pinned original bytes** with bounded size/time; reject short read/drift and digest mismatch. Pass that exact measured byte identity to the independently trusted Sigstore verifier; never verify a second pathname read. Include deliberate race/rename/hardlink tests and same-name-different-bytes failure. RED before implementation, GREEN with refusal + measured digest. Do not output `SOURCE_VERIFIED` from hash alone.

**Task 3 — actual Sigstore proof under pinned policy (RED→GREEN):** evaluate artifact+bundle against independently approved expected identity/issuer, roots, transparency/time/revocation-freshness contract, and exact verifier version, with network strictly disabled. Test good *test-key* fixtures only, bad cert/issuer/roots, valid crypto with mismatched identity, stale/expired root, missing log proof, bundle swap, disconnected tool and ambiguous verifier output. **Test-key success must say `SYNTHETIC_ONLY`; actual source remains `UNVERIFIED`.** No caller-reported `signature_verified=True` accepted.

**Task 4 — audit/status, docs and focused regression:** produce deterministic bounded evidence (digest, signer identity, OIDC issuer, root/verifier pin, log/time witness, policy revision, refusal reason) with no credentials or copied bundle/payload in public artifacts. Fail on missing witness, prevent stale decision replay, do not promote provisional outputs to B0 approval. Validate full lint/format/type/build, focused hostile tests, both hosted Python versions, docs links, exact changed-file allowlist, and independent security review. After exact-head hosted CI green, merge only on operator decision. Ordinary CI cannot prove *actual official* bytes unless source retrieval is separately authorized.

**B0a exit condition:** executable verification logic tested on small *non-official* fixtures, and, **only after separate artifact-use authorization**, candidate bytes independently hashed and Sigstore-verified under approved roots; evidence retained as **B0a-only/unapproved**. Either missing stage → `B0A_REFUSED` / `B0_UNVERIFIED`; this is never `HOST_PROVENANCE_VERIFIED` or automatic UID502 approval.

### Slice B0b — Apple Installer signature, effects inventory and operator source decision (**separate plan/PR**)

Before any actual package handling, separately review an isolated inspection-host execution plan. Using independently trusted macOS tools/environment, authenticate the **Installer** signature/Apple Developer ID chain and notarization under approved time/revocation policy. Enumerate all nested packages, BOM/payload paths, symlinks, pre/postinstall scripts, installer choices, global/system changes and dependencies without running scripts or installing. Reject incomplete inventories and unallowlisted writes, network or executable side effects. Record exact original package hash and evidence provenance. An operator decides source suitability only after **both B0a and B0b**, and explicitly rejects or approves package effects; otherwise B0 remains UNVERIFIED.

**Stop here.** B1 install-root/provisioning, B2 native FD/APFS/Mach-O/dyld attestation, B3 original-code UID502/APFS nine-row acceptance and B4 protected staging/release each require their own independently reviewed operator gate. Do not equate a clean old native Level-3 run or synthetic Gate A with any of them. [Issue #256](https://github.com/zhangyuz/ssh-over-mcp/issues/256) Linux Slice C remains deferred until operator-confirmed macOS full-feature launch and separately approved portable B2.

## Plan-review questions / approval checklist

- [ ] Confirm B0a's trust policy from an **independent channel** and identify its approving operator; no source identity accepted merely because a bundle or webpage says so.
- [ ] Resolve Sigstore **exact** artifact-specific identity, trusted root/update/expiry, transparency/time and offline revocation policy; select/pin independently trusted verification tool.
- [ ] Define what constitutes the *same byte sequence* across SHA and signature verification, and fail-closed mutable-input tests.
- [ ] Confirm Apple package validation **cannot be replaced** by Sigstore or checksum; B0b isolated host, package effects and decision remain separately gated.
- [ ] Review bounded parser/time/resource abuse, evidence provenance, retry/replay and refusal semantics.
- [ ] Agree on separate future B0a **implementation** authorization; no artifact retrieval, CI dispatch, persistent Mac operations or installer is approved merely by merging this plan.
