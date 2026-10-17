# Issue #259 / T5B-0 — C0 inert candidate-object collection allowlist (approval request, NOT authorization)

**Status 2026-10-17:** `C0_COLLECT_HOLD`; all fields below are proposed, not an operator-approved manifest. Governing [T5B-0 admission dossier](2026-10-17-adr19-t5b0-exact-material-admission-dossier.md) and [C0 gate plan](../superpowers/plans/2026-10-17-adr19-t5b0-candidate-admission-next-gate.md). A published SHA is a *publisher assertion*, not an independent trust anchor. No bytes were downloaded, installed, imported, parsed or executed to prepare this document.

## Fixed candidate object register (do not wildcard)

| ID | Exact object and permitted origin | Published digest / admission limit | Intent / disposition |
| --- | --- | --- | --- |
| C0-W1 | `sigstore-4.3.0-py3-none-any.whl` at [PyPI 4.3.0 release](https://pypi.org/project/sigstore/4.3.0/) — **resolve exact files.pythonhosted.org URL and independently verify before permission; NOT YET APPROVED TO FETCH** | PyPI-listed SHA-256 `0f60c46c92fd4e871fbec979c9ae2aa381d7a93fbb774e49c9964550e5e16856`; exact byte length and per-object cap **UNRESOLVED** | Candidate only; cannot use as executable or as verifier runtime |
| C0-P1 | PyPI 4.3.0 provenance metadata for C0-W1, obtained via **exact immutable PyPI attestations API URL not yet established** | Exact byte hash, size, signed attestation identity, media type and per-object cap **UNRESOLVED** | Candidate attestation bytes only; not independent origin trust |
| C0-R1 | `sigstore/root-signing` initial TUF root history, [repository landing page](https://github.com/sigstore/root-signing) | Exact Git object/tag/ref, root version, object URL, bytes/digest, maximum size and historical signature chain **UNRESOLVED** | Study candidate only; never import/promote root |
| C0-T1 | `tuf-repo-cdn.sigstore.dev` initial/rotated signed root metadata, [Sigstore root signing docs](https://github.com/sigstore/root-signing) | Exact numbered root path/version, metadata bytes/digest, threshold proof and per-object cap **UNRESOLVED** | Study candidate only; CDN is NOT an independent anchor |

**Important fail-closed constraint:** No `C0-W1/P1/R1/T1` network request is permitted while the exact URL, original-byte length, per-object size ceiling, immutable revision and source policy are unresolved. The PyPI release page, GitHub repository landing page, or CDN hostname is *not* a URL allowlist. Do not use redirects, `latest`, globbing, tags as mutable selectors, dependency resolvers or any auto-fetch. A future finite manifest amendment must specify every object separately with exact immutable URL, expected size, maximum size, SHA-256, acceptable redirect policy (default: none), and source custody. If an object cannot be pinned from independent preflight metadata, omit it rather than broadening access.

**Explicitly excluded from C0:** actual `python-3.13.16-macos11.pkg` and `.pkg.sigstore`, CPython installer, sdist, all transitive verifier dependencies, Python interpreter/loader/runtime acquisition, installed/embedded trust config, Docker image pulling, release API pagination, Git clone, execution/import/install, privileged Mac, UID502/APFS, staging, and Linux Slice C. The sdist's published hash is recorded in the parent dossier solely for cross-reference, not an allowlisted collection object.

## Proposed isolated custody contract (requires separate operator approval)

1. **Operator-supplied environment identity is MISSING:** designate a new disposable unprivileged Linux machine/VM by exact OS-image digest and architecture, with no production/CI/Mac secrets, no privileged container socket, no persistent home or mounted repo credentials. The environment must be provisioned by a separately reviewed procedure; this document does not create one. No real Mac/UID502 use.
2. **Tool closure is MISSING:** pin exact acquisition client binary/loader/runtime digests and a non-shell fixed argv/FD map. Disallow package manager execution, code evaluation, Python wheel import and dynamic dependency resolution. A downloader itself is executable code and cannot be silently trusted.
3. **Network contract:** allow only exact preapproved scheme+host+path object URLs, HTTPS with independently reviewed TLS policy; no automatic redirect, DNS fallback to arbitrary hosts, proxy/credential discovery or unlimited retry; per-object hard byte cap and 30-second connection/120-second total timeout *proposed numeric limits, not approved*. Fail closed on DNS/TLS error, redirect, oversized/chunked overflow, truncated body, MIME mismatch, unexpected response code or changed digest/length. Network is **not** enabled under this PR.
4. **Inert capture only:** stream to pre-created private regular files with `O_NOFOLLOW|O_CREAT|O_EXCL` under a disposable owner-only directory; bound length while streaming; hash the exact original bytes without extracting, deserializing, evaluating, installing, importing or interpreting them as policy. Use independent host clock observation only as a **collection timestamp**, not trusted signing-time evidence.
5. **Custody evidence:** record ID, exact URL, request method, response status, TLS peer certificate/connection metadata, UTC receipt time+clock provenance, expected vs observed SHA-256 and byte count, immutable file identifier/path and permissions, acquisition tool/OS-image digest, refusal logs and per-object approver. Mark output `UNTRUSTED_CANDIDATE_BYTES`. On error quarantine/reject, never reuse partial bytes or update an approved digest from fetched data.
6. **Retention and independent check:** no automatic trust-root promotion or runtime path mounting; retain read-only inert evidence only for a separately approved bounded duration (duration **UNRESOLVED**) and dispose by separately approved procedure. Reviewer must inspect full manifest, logs, negative cases, and independent OOB root/time proof before any later T5B-0 admission.

## Gate decision checklist

- [ ] Independent OOB first TUF root fingerprint/threshold and separately trusted UTC witness identified, or explicit declaration that collection is **research-only** without source admission.
- [ ] Exact immutable HTTPS URL, byte size, per-object cap and published SHA for **each** included object; no unresolved values.
- [ ] Fixed designated unprivileged off-host environment image digest, no secrets/privilege, network ACL and trusted downloader closure.
- [ ] Fixed transport, no-redirect, byte/time/MIME bounds, original-byte capture and custody/retention policy.
- [ ] Separate named operator consent to **this exact manifest revision and objects** (not inferred from PR merge/CI).

**Decision now:** `C0_COLLECT_HOLD_INCOMPLETE`. This PR may be merged as a **documented, auditable refusal and next-step specification only**. It does not authorize collection. Independently signed trust anchors, T5B-0 verifier runtime, T5B-1 and real Mac acceptance remain HOLD.
