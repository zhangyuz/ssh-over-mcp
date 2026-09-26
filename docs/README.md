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
9. **Implementation sequencing** — [`development-plan.md`](development-plan.md)
10. **Normative design changes** — [`decisions/`](decisions/README.md)

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
