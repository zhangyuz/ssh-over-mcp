# Offline Compose configuration preflight (static-only)

This **operator CLI** checks bounded, already-rendered Docker Compose JSON descriptions for the proposed SOM dual-mode MVP. It is an early configuration-review/refusal tool, **not** a Docker deployment, runtime attestation, image trust, host-key verification, firewall verification or permission to proceed.

## Inputs

Use `docker compose ... config --format json` only in your own authorized operator environment to produce a **local** configuration document. That rendering operation does not start containers, but it can interpolate sensitive environment and mount paths: keep the resulting files private, never paste them into tickets/logs, and **do not upload real credentials**. The checker itself never invokes Docker/SSH/network, reads secrets referenced by the input or echoes source bytes. Each input must be one non-symlink regular file, no more than **16 KiB**; same-open-FD file mutation checks and duplicate JSON key refusal are inherited from the previously reviewed topology preflight. Standard rendered service networks may use `{\"node01_ssh\": null}` for attachments without options; list and map forms are both supported. Resolved named-volume identities, not merely logical source keys, are screened against reserved admin volumes.

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

The validator rejects unpinned or malformed image references, privileged/host-namespace/unreviewed Compose fields, host-published ports (including seemingly private bindings), unapproved network drivers (only the default/bridge driver is allowed), missing read-only/capability/NNP protections (including additional unconfined security options), rootful or rootless Docker sockets and cgroup mounts (including read-only binds of enclosing directories), noncanonical host bind paths, cross-role Ledger/admin/exec socket volume mounts, duplicate resolved network/volume names and external volumes, missing host-key volume and target lateral network attachments. Control-plane bind mounts are allowed only as read-only, non-relabeling inputs to the fixed MCP config/credential/SSH-secret/origin-bearer targets or to the Cloudflared token target; unreviewed mount options, automatic host-path creation, container-runtime socket sources, Docker-managed storage roots, and arbitrary bind destinations refuse. **Every bind mount MUST explicitly declare `bind: {create_host_path: false}`**, even when `read_only: true`; the option's omission can retain Compose's legacy behavior of automatically creating a missing host directory. The preflight refuses missing/empty bind option maps and `create_host_path: true`, but it still does not stat the referenced host directory or prove its existence on the deployed Engine. Lexical refusals also cover conventional dockerd-managed containerd sockets beneath `/run/docker` or `/var/run/docker`, and conventional rootless runtime storage beneath `/home/USER/.local/share` and `/root/.local/share` without banning an ordinary `/home/USER/config.yaml` file. They do **not** discover custom runtime paths or XDG_DATA_HOME, symlinks or bind mount aliases and are not a substitute for host-side trust checks. Accepting a declared source path does not attest its symlink resolution, ownership or trusted contents on the real Engine. It **does not** infer actual SSH host keys, container cgroup delegation, runner identity, image provenance, IPv4/IPv6 Docker NAT or forwarding policy, Compose/host isolation or durable mutation semantics. Real environments may need additional capabilities that this intentionally restrictive preflight refuses; such changes require design/security review rather than a permissive bypass.

### Service participation and entrypoint safety

Mandatory control services `ledger-init`, `ledger` and `mcp` (plus Mode A `node01`/`node02`, and both Mode B `ssh-target` services) must **not** have opt-in `profiles`. An absent field or an explicitly empty list is accepted; nonempty or malformed values are refused so required services cannot silently disappear on the default Compose startup. Optional `approvalctl` and `cloudflared` may use their **reviewed** profile names `admin` and `cloudflare`, respectively.

The control stack's declared UID:GID and exact entrypoints are checked against the existing `deploy/compose/compose.yaml` contract: `ledger=10002:10002` with supplementary groups `10003,10005` and `ssh-over-mcp-ledger`; `mcp=10001:10003` with `ssh-over-mcp-server`; `approvalctl=10004:10005` with `ssh-over-mcp-approvalctl`; optional `cloudflared=65532:65532` with the exact tunnel token-file command. **Only** `ledger-init` is permitted the narrowly reviewed `0:0` bootstrap identity, exact `ssh-over-mcp-ledger-init` executable and `CHOWN,DAC_OVERRIDE` capabilities, on a `network_mode: none` service. No general root exception is granted.

The future SSH target image has **no reviewed bootstrap/UID/ForceCommand execution contract yet**. Accordingly, neither Mode A nor Mode B accepts caller-supplied SSH target `user`, `group_add`, `entrypoint`, `command`, or other executable overrides. The absence of overrides **does not prove** an image's default UID, non-rootness, command, sshd or ForceCommand behavior. Any necessary SSH privileged startup/bootstrap exception requires a separate explicitly approved design and real two-mode validation, not a silent preflight waiver. Successful CLI output still means static structure only, **never deployment readiness**.

### Ledger endpoint and secondary execution boundaries

For `ledger-init` and `ledger`, the checker now requires the **complete reviewed control-plane environment contract**: database/HMAC-key paths, Ledger service UID/GID and **distinct exec/admin socket paths, GIDs, modes and peer UID/GID mappings**. The MCP `ledger-exec` socket path and matching Ledger service identity are fixed; optional `approvalctl` uses only the reviewed admin endpoint. A swapped exec/admin endpoint is refused even if the declared named volumes remain separate. The MVP `rw-operator` profile and known config/credential/token-file paths are pinned as static declarations; any additional environment/loader override is refused rather than silently widening authority. None of these checks proves that an image processes environment variables as expected or that the live socket peers have those identities.

The optional MCP healthcheck, if declared, must use exactly the existing `CMD python -c` loopback `/readyz` probe; all arbitrary shell or other healthcheck commands are refused, as are healthchecks on other unreviewed services. Unreviewed `tmpfs` replacement, logging driver/export, hostnames and process ulimit overrides are refused as secondary execution/authority pathways. This is a **conservative partial Compose contract**, not a full deployment attestation; any change to these reviewed pins needs an independent security review.

The existing `deploy/compose/compose.yaml` is **not** an accepted hardened MVP description: its default control-plane image is still mutable `ssh-over-mcp:phase6b`, its SSH egress is not destination-allowlisted, and it does not provide either actual SSH target Compose deployment. This CLI does not change that source file or silently upgrade it.

## Verification

```sh
python -m pytest -q tests/ops/test_mvp_compose_config_preflight.py
python -m ruff check ops/mvp tests/ops/test_mvp_compose_config_preflight.py
python -m compileall -q ops/mvp
```

The tests execute the **real CLI** against Mode A and Mode B synthetic positive structures and adversarial refusals; their success is not proof of real `docker compose config` output, deployed SSH services, authorized Linux Engines or production acceptance. A01–A18, M1a/M1b and all actual Docker/SSH/privileged/network/read-write E2E gates remain **NOT_RUN / HOLD**. See [current MVP status](../mvp-status.md), [ADR0021](../decisions/0021-private-compose-rw-mvp-release-track.md), and [the MVP plan](../superpowers/plans/2026-10-23-private-compose-rw-mvp.md).
