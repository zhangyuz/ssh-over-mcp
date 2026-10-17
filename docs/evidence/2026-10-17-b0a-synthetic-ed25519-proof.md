# B0a test-only Ed25519 proof — scope and usage

This PR adds a **synthetic cryptographic signature test**, not Sigstore verification. It uses the fixed `/usr/bin/openssl` executable on hosted Linux, a generated disposable Ed25519 private key, and test-supplied public key. The positive status `SYNTHETIC_ONLY` proves only that the provided signature matches the provided key and test payload. It **does not authenticate the key** or certify signer identity, OIDC issuer, Fulcio roots, Rekor log, timestamps, revocation, trust-config, offline verifier provenance, package source, or macOS B0/B1–B4. Production `gate_b0_source_verification.py verify-synthetic` continues to refuse.

Run on Linux with `/usr/bin/openssl` and pytest:

```bash
python -m pytest -q tests/ops/test_b0a_synthetic_signature_proof.py
```

The test generates disposable Ed25519 key material in pytest's temporary directory, signs a domain-separated test payload, invokes `ops/live-e2e/b0a_synthetic_signature_proof.py --payload PATH --signature PATH --public-key PATH`, then tests equal-length payload tampering, signature tampering and wrong public key. The CLI refuses on non-Linux systems and on missing/special/oversized inputs, with exit 2 and `B0A_SYNTHETIC_REFUSED`. On macOS tests skip actual positive crypto verification; this does not certify Homebrew OpenSSL. The fixed Linux executable is a reproducible CI test runner choice, **not** an independently attested T5B verifier. No network, production trust root, installer or privileged host action.

The key is intentionally caller-supplied because this feature proves only a mathematical signature relation, not a trusted test root; never promote the positive status to source authorization. Real Sigstore signed-digest verification and exact pinned verifier policy require independent approval.
