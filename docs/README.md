# Source of truth

This directory is the canonical behavioral and security specification for `ssh-over-mcp`.

## Document hierarchy

1. **Security invariants** — [`security-model.md`](security-model.md)
2. **Threat assumptions and abuse cases** — [`threat-model.md`](threat-model.md)
3. **System boundaries and component responsibilities** — [`architecture.md`](architecture.md)
4. **Policy semantics** — [`policy-spec.md`](policy-spec.md)
5. **MCP surface** — [`mcp-api.md`](mcp-api.md)
6. **Remote enforcement** — [`ssh-host-agent.md`](ssh-host-agent.md)
7. **Edge/auth deployment** — [`cloudflare-deployment.md`](cloudflare-deployment.md)
8. **Approvals and audit** — [`audit-and-approvals.md`](audit-and-approvals.md)
9. **Development methodology** — [`development-methodology.md`](development-methodology.md)
10. **Implementation sequencing** — [`development-plan.md`](development-plan.md)
11. **CI execution topology** — [`ci-hosted-primary.md`](ci-hosted-primary.md); manual hardened Docker validation — [`self-hosted-runner.md`](self-hosted-runner.md)
12. **Normative design changes** — [`decisions/`](decisions/README.md)
13. **Worktree-local agent handoff template** — [`templates/progress.md`](templates/progress.md)
14. **Current MVP delivery entrypoint** — [`mvp-status.md`](mvp-status.md) (two mandatory deployment modes confirmed: single-engine E2E and per-host multi-engine Compose; remaining ADR approval pending)

**MVP offline subtree-visibility operator preview** — [synthetic per-path allow/deny dry-run](runbooks/mvp-subtree-visibility-preview.md) (not an authorization or deployed FS capability).

**SSH-container privilege boundary proposal** — [ADR0022](decisions/0022-proposed-compose-ssh-privilege-domains.md) (NOT accepted/authorized).

**Mode A SSH image/ForceCommand feasibility (review candidate)** — [proposed runtime handoff contract](superpowers/specs/2026-10-24-mode-a-ssh-runtime-handoff-review.md); no approved image/bootstrap, Linux Engine, or release authority.

**MVP offline artifact consistency operator CLI** — [topology + rendered Compose bundle preflight](runbooks/mvp-compose-bundle-preflight.md) (static only; no deployment authorization).

**M1a static Mode A multi-SSH Compose overlay** — [offline render-only runbook](runbooks/mvp-mode-a-compose-render.md) (no Docker deployment/startup authorization).

**Mode A disposable VM definition preflight** — [read-only VM gate](runbooks/mvp-mode-a-vm-offline-gate.md) (does not authorize boot; host/LAN egress remains unverified).

**Mode A OCI/SSH trust proposal** — [per-role and directional network proof matrix](superpowers/specs/2026-10-24-mode-a-oci-privilege-and-network-proof-matrix.md) and [concrete same-node PID, separate-manager OCI execution/no-NIC QEMU Level-2 design](superpowers/specs/2026-10-25-mode-a-runtime-execution-contract.md) (offline review only, P1 executable runtime authority HOLD).

**Mode A C1–C4 trusted source proposal** — [Canonical Ubuntu OCI manifest pins, fail-closed SSH image candidate, disconnected import and test-only key lifecycle](superpowers/specs/2026-10-24-mode-a-ssh-source-and-offline-transfer.md) (public metadata/offline design only).

**Mode A C5 signed distro metadata** — [Ubuntu 26.04 GPG signature and Packages.xz hash-chain offline verification](runbooks/mvp-mode-a-ubuntu-package-index-offline.md), 10 candidate packages only; no `.deb` bytes or complete install lock.

## Three-layer agent collaboration

- [`../AGENTS.md`](../AGENTS.md) is the concise operational contract for agents and approval boundaries.
- [`development-methodology.md`](development-methodology.md) is the normative development and acceptance method.
- Root `progress.md` in **each active worktree** is a local, Git-ignored handoff. Copy the [template](templates/progress.md); it records current facts, evidence, unresolved approvals, and the next action. It is not a security specification or PR artifact.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative requirements in these documents.

## Change rule

A pull request that changes externally visible behavior or security semantics MUST update these documents or include an ADR explaining why no documentation change is required.

## Current baseline

The initial baseline is a policy-enforced SSH control plane with:

- MCP Streamable HTTP ingress;
- Cloudflare MCP Portal as the preferred front door;
- Managed OAuth for interactive clients and service tokens for machine clients;
- server-side host inventory;
- RBAC and capability profiles;
- default-deny allow/deny policy evaluation;
- structured SSH execution as the normal path;
- separate privileged raw shell capability;
- remote `ForceCommand` enforcement;
- pinned SSH host keys;
- OS permissions as a final security boundary;
- risk scoring, approvals, and complete decision audit events.
