# B0 T1–T5 offline policy preflight (non-authorizing)

This developer-only tool identifies **missing policy decision fields** before an operator/security review. It cannot authenticate sources, signatures, package bytes, trust roots, verifier binaries or Mac hosts. Its best outcome is `B0_POLICY_CANDIDATE_ONLY`, **never** `B0_VERIFIED` or approval. Placeholder values may satisfy field presence but are **not evidence**. Real T1–T5 remain unresolved.

Run `python3 ops/live-e2e/b0_policy_preflight.py path/to/untrusted-candidate.json` using a manually prepared local JSON candidate. Exit 2 means incomplete/unreadable. Exit 0 means field presence only, and must never advance a trust gate. No package, verifier or root downloads, installations, UID502/APFS or privileged actions are authorized. Refer to `2026-10-15-adr19-b0a-artifact-trust-approval-checklist.md` for independent approval requirements.

This is an efficiency-first **placeholder for expensive cryptographic/host verification**, not a substitute for it. Future approval must pin and verify actual bytes, roots, clock/revocation policy and exact verifier runtime independently.

The CLI rejects absent/empty and common placeholder markers, malformed SHA-256 shapes, non-positive artifact sizes, invalid numeric freshness/skew bounds, and unknown handoff modes. Passing means **shape-only**; arbitrary correctly shaped strings remain untrusted and must not be consumed as approvals. This tool does not validate signer/OIDC syntax, actual root/log authenticity, signed timestamps, revocation or binary provenance. The remaining high-cost verification is explicitly DEFERRED and must be completed at the separately approved B0 trust gate.

Input handling is bounded: no-follow and nonblocking open, `fstat` regular-file check, maximum 64 KiB bytes, maximum JSON depth 32, and refusal on malformed or special-file inputs. These checks prevent FIFO stalls and unbounded JSON parsing; they do not authenticate an input policy or protect against a concurrent writer changing a regular file. Such input remains advisory and non-authorizing.
