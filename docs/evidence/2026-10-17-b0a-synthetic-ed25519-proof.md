# B0a test-only Ed25519 proof — scope and usage

This PR adds a **synthetic cryptographic signature test**, not Sigstore verification. It uses the fixed `/usr/bin/openssl` executable on hosted Linux, a one-time generated test-only Ed25519 fixture whose private key was discarded, and an exact pinned public-key SHA-256. The positive status `SYNTHETIC_ONLY` proves only that the provided signature matches the provided key and test payload. It **does not authenticate the key** or certify signer identity, OIDC issuer, Fulcio roots, Rekor log, timestamps, revocation, trust-config, offline verifier provenance, package source, or macOS B0/B1–B4. Production `gate_b0_source_verification.py verify-synthetic` continues to refuse.

Run on Linux with `/usr/bin/openssl` and pytest:

```bash
python -m pytest -q tests/ops/test_b0a_synthetic_signature_proof.py
```

The checked-in fixture contains a fixed public key, a 4-byte big-endian length-prefixed domain-separated test payload, and its Ed25519 signature; the private key is not committed. The test verifies the fixed vector, invokes `ops/live-e2e/b0a_synthetic_signature_proof.py --payload PATH --signature PATH --public-key PATH`, then tests equal-length payload tampering, signature tampering and wrong public key. The CLI refuses on non-Linux systems and on missing/special/oversized inputs, with exit 2 and `B0A_SYNTHETIC_REFUSED`. On macOS tests skip actual positive crypto verification; this does not certify Homebrew OpenSSL. The fixed Linux executable is a reproducible CI test runner choice, **not** an independently attested T5B verifier. No network, production trust root, installer or privileged host action.

The CLI accepts a public-key path but refuses any key whose full SHA-256 differs from its fixed test-only pin; even the pinned test key is not an approved production trust root. The test also generates a different disposable key/signature pair and verifies refusal. Never promote the positive status to source authorization. Real Sigstore signed-digest verification and exact pinned verifier policy require independent approval.
