# M1a Mode A — two-SSH Compose declaration overlay (render-only)

**Status: STATIC DECLARATION DELIVERABLE, NOT STARTUP/DEPLOYMENT AUTHORITY.** This feature adds `deploy/compose/compose.dev-ssh.yaml`, an offline-renderable *Mode A only* overlay for one disposable Linux Engine with one MCP control project and `node01`/`node02` SSH service descriptions. **Do not run `docker compose up`, `pull`, `build`, or supply production credentials/real host-key assets based on this feature.** The host-level privilege, cgroup delegation, approved SSH target image, ForceCommand/sshd bootstrap and authenticated host keys are not yet implemented or independently verified; Mode A `A01`–`A03` and Mode B `A15`–`A18` remain `NOT_RUN/HOLD`.

## Reproducible static operator action

The operator must supply digest-pinned image *references* out of band for the control stack and two future SSH image assets. The included [`reference.mode-a.env.example`](../../deploy/compose/reference.mode-a.env.example) is intentionally **not runnable**: image digest fields contain invalid `DO_NOT_DEPLOY` markers, and file paths are placeholders, not real credentials. Do not populate this checked-in file with secrets. Use only synthetic, non-sensitive test paths and reviewed OCI reference strings when testing offline.

A purely offline render command (do not append `up`, `pull` or `build`): **use a cleared process environment**. An inherited `COMPOSE_ENV_FILES`, `COMPOSE_PROFILES`, `COMPOSE_FILE`, exported image variable or local `.env` can silently change what Compose renders; an explicit `--env-file` is not sufficient proof of input provenance. In the example, only PATH/HOME are retained for CLI plugin discovery, and the Docker host points to a nonexistent socket:

```sh
env -i PATH="$PATH" HOME="$HOME" COMPOSE_DISABLE_ENV_FILE=1 \
  DOCKER_HOST=unix:///nonexistent-som-mode-a.sock \
  docker compose \
  -f deploy/compose/compose.yaml \
  -f deploy/compose/compose.dev-ssh.yaml \
  --project-name som-mode-a-synthetic \
  --env-file /operator-owned/private/synthetic-mode-a.env \
  config --format json > /operator-owned/private/rendered-mode-a.json

python3 ops/mvp/compose_config_preflight.py \
  --mode dev-e2e \
  --control-json /operator-owned/private/rendered-mode-a.json

python3 ops/mvp/bundle_preflight.py \
  --topology-json /operator-owned/private/synthetic-mode-a-topology.json \
  --control-json /operator-owned/private/rendered-mode-a.json
```

The command requires Docker Compose **2.33.1+** (both `!override` and the base file's `gw_priority`; tested with v5.5.1), but **does not require or contact a Docker Engine** for `config` output. Never paste rendered Compose output containing interpolated paths/config/secret references into tickets or logs. The topology JSON is independently provided, including both distinct node aliases and *synthetic* SSH host-key fingerprint syntax; syntax/consistency checks do not establish trust. All image variables — `SSH_OVER_MCP_IMAGE`, `SSH_OVER_MCP_NODE01_IMAGE`, `SSH_OVER_MCP_NODE02_IMAGE` — must be explicitly set; the overlay rejects missing values rather than falling back to the control project's mutable historic `phase6b` image tag. A syntactically well-formed digest string still **does not prove image contents, signature or provenance**.

## Isolation represented by the YAML (not yet proven in running containers)

- Overlay **replaces**, not appends, MCP network attachments: `origin_internal`, `node01_ssh` and `node02_ssh`. The baseline unbounded `ssh_egress` is removed from this Mode A render, not from the historical production Compose file; no implicit default bridge or SSH-node-to-node shared network is intended.
- `node01` attaches only to its dedicated internal network `node01_ssh`; `node02` only to `node02_ssh`. Each has separate named data and SSH host-key volumes. SSH host keys are mounted read-only; operator-owned secure provisioning and runtime image contract remain an explicit prerequisite.
- No host `ports`, Docker socket bind, `privileged`, host PID/net namespace, extra capabilities, arbitrary user/entrypoint overrides or writable cgroup/host root. Both future SSH targets are declared `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`. These fields **are not evidence that a real sshd, authorized launcher, manager or cgroup delegation can function** with these constraints. No root exception is silently granted.
- The MCP service mounts operator config, credential references, SSH secret directory and origin bearer file read-only with `bind.create_host_path: false`. Ledger DB/admin/exec named-volume boundaries are preserved; control-plane `ledger-init` remains the already-reviewed distinct initialization privilege domain.
- `cloudflared` and `approvalctl` stay in existing opt-in profiles; no public origin/SSH host port is published by the overlay. Compose bridge isolation alone is **not** a host firewall, egress ACL or Mode B private network proof.

## SSH runtime handoff review candidate (not an executable deployment)

The [SSH bootstrap/privilege proposal](../superpowers/specs/2026-10-24-mode-a-ssh-runtime-handoff-review.md) documents the exact incompatibility between the current `cap_drop: ALL` + `no-new-privileges:true` and ADR0007's privileged fixed ForceCommand handoff. The candidate [`sshd_config.proposed`](../../deploy/ssh-target/sshd_config.proposed) is intentionally **not mounted, built, started or accepted** by the Compose overlay; it contains only an E2E-only fixed SSH account and has no trusted container sudo/UID/cgroup/image/authorized-keys assets. There is **no authorized workaround** based on adding host capabilities, weakening NNP or mounting the host cgroup root. Static tests of this proposal do not reduce the existing A01–A03/HOLD gates.

## Required distinct next approvals / acceptance

Before any live test on a disposable **authorized Linux Engine**, independently review and approve: immutable digest **source**, exact SSH image Dockerfile/build provenance, OpenSSH `sshd_config`/ForceCommand/authorized keys, SSH host-key generation and pin trust source, manager/host-agent identity and **minimal CAP_SETUID/CAP_SETGID/UID bootstrap** compatibility, safe cgroup v2 delegation, per-request typed FS containment and resource limits, and actual network ingress/egress deny evidence. If `no-new-privileges` or `cap_drop: ALL` makes secure sshd startup impossible, do **not** weaken confinement ad hoc; revise ADR0021/plan with a separately authorized privilege model and independent security review first.

M1a `A01`–`A03` are reserved for actual live Mode A positive plus hostile lateral network/data/host-key/restart/manager-outage tests on the same accepted image/source SHA. The existing Native Level-3 and hosted CI runs do not substitute for these. Mode B requires separate **three distinct Linux Engines** and `A15`–`A18`; this overlay is intentionally **not** a Mode B deployment template. The static preflight and bundle check always report `deployment_ready=false`, all host/image/ACL/runtime/live-E2E flags false.

See [MVP status](../mvp-status.md), [ADR0021](../decisions/0021-private-compose-rw-mvp-release-track.md), and [M1a plan](../superpowers/plans/2026-10-23-private-compose-rw-mvp.md).
