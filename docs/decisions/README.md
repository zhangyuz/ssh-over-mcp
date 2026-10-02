# Architecture Decision Records

ADRs capture deliberate changes to the source-of-truth architecture.

Format:

```text
NNNN-short-title.md
```

Each ADR contains status, context, decision, consequences, and security impact.

Current ADRs:

- [0001 — Policy-first SSH control plane](0001-policy-first-control-plane.md)
- [0002 — Structured execution plus privileged raw shell](0002-structured-exec-and-breakglass-shell.md)
- [0003 — Cloudflare MCP Portal as preferred front door](0003-cloudflare-portal-front-door.md)
- [0004 — Separate containment management from workload privilege](0004-containment-manager-privilege-separation.md)
- [0005 — Forked child performs the one-way workload identity drop](0005-workload-identity-drop.md)
- [0006 — Full local E2E uses a dedicated operator-owned privilege fixture](0006-full-e2e-trust-model.md)
- [0007 — ForceCommand host-agent capability handoff uses a fixed launcher](0007-host-agent-capability-launcher.md)
