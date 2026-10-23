# Offline Compose configuration preflight (static-only)

This **operator CLI** checks bounded, already-rendered Docker Compose JSON descriptions for the proposed SOM dual-mode MVP. It is an early configuration-review/refusal tool, **not** a Docker deployment, runtime attestation, image trust, host-key verification, firewall verification or permission to proceed.

## Inputs

Use `docker compose ... config --format json` only in your own authorized operator environment to produce a **local** configuration document. That rendering operation does not start containers, but it can interpolate sensitive environment and mount paths: keep the resulting files private, never paste them into tickets/logs, and **do not upload real credentials**. The checker itself never invokes Docker/SSH/network, reads secrets referenced by the input or echoes source bytes. Each input must be one non-symlink regular file, no more than **16 KiB**; same-open-FD file mutation checks and duplicate JSON key refusal are inherited from the previously reviewed topology preflight.

For **Mode A**, provide one rendered Compose JSON project containing the control services (`ledger-init`, `ledger`, `mcp`) and two separate SSH target services (`node01`, `node02`); optional `approvalctl`/`cloudflared` services may be included. Each target must have its own internal `node01_ssh` or `node02_ssh` network, and separate named data and SSH host-key volumes. The MCP service must attach to `origin_internal` and both target networks; it cannot prove that these connections have firewall egress controls.

```sh
python3 ops/mvp/compose_config_preflight.py --mode dev-e2e \
  --control-json /private/operator/mode-a-compose.json
```

For **Mode B**, provide three independent Compose *document inputs*: the control-plane project and **one per-target project** on each separately operator-owned SSH Engine. Both SSH project descriptions use service `ssh-target`, with their own local `ssh-data` and `ssh-keys` named volumes and internal `ssh_private` network. The control project uses `origin_internal` and `private_ssh_egress` network names. It is an **explicitly non-authorizing structural declaration**: separate input paths do not establish that there are three physical/virtual Docker Engines or a privately routed network.

```sh
python3 ops/mvp/compose_config_preflight.py --mode multi-host \
  --control-json /private/operator/control01-compose.json \
  --node01-json /private/operator/ssh-host01-compose.json \
  --node02-json /private/operator/ssh-host02-compose.json
```

A syntactically accepted description prints a one-line JSON report with `static_compose_shape_valid=true` and **always** `deployment_ready=false`, `host_identity_verified=false`, `network_acl_verified=false`, `image_trust_verified=false`, `runtime_verified=false`, and `live_e2e_verified=false`. Failure exits nonzero and emits only a fixed refusal code; no user input or secret data is included.

The validator rejects unpinned or malformed image references, privileged/host-namespace/unreviewed Compose fields, host-published ports (including seemingly private bindings), missing read-only/capability/NNP protections (including additional unconfined security options), raw Docker socket and cgroup mounts, noncanonical host bind paths, shared target/admin volumes, duplicate resolved network/volume names and external volumes, missing host-key volume and target lateral network attachments. Control-plane read-only operator bind mounts are allowed with restricted lexical paths. It **does not** infer actual SSH host keys, container cgroup delegation, runner identity, image provenance, IPv4/IPv6 Docker NAT or forwarding policy, Compose/host isolation or durable mutation semantics. Real environments may need additional capabilities that this intentionally restrictive preflight refuses; such changes require design/security review rather than a permissive bypass.

The existing `deploy/compose/compose.yaml` is **not** an accepted hardened MVP description: its default control-plane image is still mutable `ssh-over-mcp:phase6b`, its SSH egress is not destination-allowlisted, and it does not provide either actual SSH target Compose deployment. This CLI does not change that source file or silently upgrade it.

## Verification

```sh
python -m pytest -q tests/ops/test_mvp_compose_config_preflight.py
python -m ruff check ops/mvp tests/ops/test_mvp_compose_config_preflight.py
python -m compileall -q ops/mvp
```

The tests execute the **real CLI** against Mode A and Mode B synthetic positive structures and adversarial refusals; their success is not proof of real `docker compose config` output, deployed SSH services, authorized Linux Engines or production acceptance. A01–A18, M1a/M1b and all actual Docker/SSH/privileged/network/read-write E2E gates remain **NOT_RUN / HOLD**. See [current MVP status](../mvp-status.md), [ADR0021](../decisions/0021-private-compose-rw-mvp-release-track.md), and [the MVP plan](../superpowers/plans/2026-10-23-private-compose-rw-mvp.md).
