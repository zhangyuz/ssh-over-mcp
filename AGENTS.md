# Agent instructions

This repository is security-sensitive infrastructure. Automated coding agents must treat `/docs` as the source of truth.

## Required workflow

1. Read `docs/README.md`, `docs/security-model.md`, `docs/policy-spec.md`, and `docs/mcp-api.md` before changing behavior.
2. Do not weaken a documented security invariant to make a test pass.
3. Any behavior change affecting authorization, command execution, host identity, credential handling, approvals, audit semantics, or network exposure must update the relevant document in the same change.
4. Architectural changes require a new ADR under `docs/decisions/`.
5. Deny rules override allow rules. Default policy remains deny unless an ADR explicitly changes it.
6. Never introduce a generic unrestricted shell path into a low-privilege role.
7. Never accept host address, SSH username, SSH key, or host-key trust material directly from model-supplied tool arguments.
8. Never set `StrictHostKeyChecking=no`, disable host-key verification, or silently trust a changed host key.
9. Never make `NOPASSWD: ALL`, Docker socket access, host PID namespace, or equivalent root escape mechanisms part of a normal profile.
10. Tests must cover both allowed behavior and bypass attempts.

When code and docs differ, stop and resolve the discrepancy rather than silently choosing one.
