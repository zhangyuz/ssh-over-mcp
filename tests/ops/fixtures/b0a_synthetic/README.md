# B0a Sigstore conformance material — UNAPPROVED CANDIDATE ONLY

These two **unchanged upstream files** are inert public data for deterministic, **offline syntactic envelope and sealed-artifact-digest mismatch tests only**. The tests **do not validate cryptographic signatures, signer SAN/OIDC, Fulcio/CT/Rekor roots, inclusion proofs, timestamps, revocation, executable provenance, or T5B policy approval**. No test may return `SYNTHETIC_ONLY` or a source-trust authorization based on them.

**Provenance:** [sigstore/sigstore-conformance at Git commit `e241c4ea6c83b4d8f03461e825f056b2c5eba3ed`](https://github.com/sigstore/sigstore-conformance/tree/e241c4ea6c83b4d8f03461e825f056b2c5eba3ed/test/assets/bundle-verify). Source files copied verbatim:

| Local file | Upstream path | Exact SHA-256 | Length (bytes) |
| --- | --- | --- | ---: |
| `sigstore-conformance-a.txt` | `test/assets/bundle-verify/a.txt` | `a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf` | 109 |
| `sigstore-conformance-rekor2-bundle.sigstore.json` | `test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json` | `3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd` | 10,123 |

Bundle format is Sigstore v0.3 `messageSignature`, with archived Rekor v2 hashedrekord and RFC3161 timestamp **claims that have NOT been authenticated in this PR**. The bundle's declared digest statically matches the first file; the negative test mutates only a copied, private sealed artifact (same length), keeping the archived bundle unchanged.

**Never treat bundled or same-origin trust roots as independently authenticated.** These files are **NOT** the operator-approved T5B test-key fixture, root or verifier. Their only current use is to test the failure-safe *preflight* of `gate_b0_sigstore_adapter.py`; a matching preflight field proves **no** external trust.

Real Sigstore offline GREEN plus adversarial RED requires explicit independent T5B signer/root/tool/loader/clock/revocation/FD-mode policy approval, a network-denied guest, and genuine cryptographic verification on the exact approved bytes. Real macOS installer/source checks, B0b, UID502/APFS and release authority remain prohibited.
