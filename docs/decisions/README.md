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
- [0006 — Full local E2E runs capability-bearing code only in a disposable Linux guest](0006-full-e2e-trust-model.md)
- [0007 — ForceCommand host-agent capability handoff uses a fixed launcher](0007-host-agent-capability-launcher.md)
- [0008 — Level-3 E2E guest has no virtual network device](0008-level3-e2e-no-network-guest.md)
- [0009 — Security Ledger systemd sandbox](0009-ledger-systemd-sandbox.md)
- [0010 — Authenticated offline native E2E toolchain](0010-offline-native-e2e-toolchain.md)
- [0011 — Incident-bound E2E staging recovery (proposed)](0011-incident-bound-e2e-staging-recovery.md)
- [0012 — Owned diagnostic-child lifecycle for incident inspection (written design approved; implementation pending)](0012-owned-diagnostic-child-lifecycle.md)
- [0013 — GitHub-hosted ordinary CI and self-hosted native E2E](0013-hosted-ci-self-hosted-e2e.md)

- [0014 — Exact residual forensic inspection](0014-exact-residual-forensic-inspection.md)

- [0018: Approved historical residual disposition](0018-approved-historical-residual-disposition.md) — implemented; approved incident recovery and exact-main native E2E/cleanup verified. See the [acceptance record](../evidence/2026-10-13-native-provider-recovery-acceptance.md).

- [0019 — Protected native E2E staging namespace](0019-protected-native-e2e-staging.md) — first dormant shared inspection implemented (PR #243); owned workspace lifetime and actual protected-placement activation remain unimplemented and separately gated.

- [0020 — Trusted PR native E2E admission (proposed; not activated)](0020-trusted-pr-native-e2e-admission.md) — staged default-branch identity gate, no present workflow changes.
