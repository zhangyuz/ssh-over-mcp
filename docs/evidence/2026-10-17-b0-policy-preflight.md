# B0 T1–T5 offline policy preflight (non-authorizing)

This developer-only tool identifies **missing policy decision fields** before an operator/security review. It cannot authenticate sources, signatures, package bytes, trust roots, verifier binaries or Mac hosts. Its best outcome is `B0_POLICY_CANDIDATE_ONLY`, **never** `B0_VERIFIED` or approval. Placeholder values may satisfy field presence but are **not evidence**. Real T1–T5 remain unresolved.

Run `python3 ops/live-e2e/b0_policy_preflight.py path/to/untrusted-candidate.json` using a manually prepared local JSON candidate. Exit 2 means incomplete/unreadable. Exit 0 means field presence only, and must never advance a trust gate. No package, verifier or root downloads, installations, UID502/APFS or privileged actions are authorized. Refer to `2026-10-15-adr19-b0a-artifact-trust-approval-checklist.md` for independent approval requirements.

This is an efficiency-first **placeholder for expensive cryptographic/host verification**, not a substitute for it. Future approval must pin and verify actual bytes, roots, clock/revocation policy and exact verifier runtime independently.
