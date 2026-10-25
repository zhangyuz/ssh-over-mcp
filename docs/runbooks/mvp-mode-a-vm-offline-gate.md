# Mode A disposable VM — offline safety preflight

**Status: config inspection only; VM BOOT / Docker / SSH / LAN access HOLD.**
Operator selected an independent Ubuntu 26.04 x86_64 VM on `yuz.local` and delegated B environment planning. The previously created, stopped `som-mode-a-ubuntu2604` definition is preserved. This runbook does **not** authorize using that instance or its disk as a trusted workload or container image.

## Offline read-only check

```sh
python3 ops/mvp/mode_a_vm_offline_preflight.py \
  --config "$HOME/.lima/som-mode-a-ubuntu2604/lima.yaml"
```

The utility reads a bounded, regular YAML file, rejects duplicate keys,
symlinks, unexpected provisioning/network/forwarding/mount fields, a different
Canonical image digest, or increased VM resources. It cannot authenticate
the actual guest OS, verify the downloaded image or disk, query a running
VM, or prove network isolation. Its only successful output sets
`host_lan_isolation_verified=false`, `vm_execution_authorized=false`,
`docker_runtime_verified=false`, `deployment_ready=false`.

## Network decision — not yet safe to boot

The reviewed stopped VM uses Lima **2.2** with `vmType: vz`, `plain: true`,
no host mounts, and no dynamic published ports. `plain` limits shared
features but **does not disable the default user-mode networking**.
Lima's default slirp networking has guest-to-host and outbound reachability.
Even newer Lima's `networkOpts.hostLoopback: false` (introduced in v2.3)
only blocks one host-loopback route; it does **not** block the host's LAN
address or arbitrary outbound connections.

Before executing guest code or starting a Docker Engine, choose and
independently verify an isolation boundary that fails closed for *all*
host, LAN and production addresses. A physically network-disconnected
guest (no emulated NIC) with offline reviewed install media is a candidate;
an externally enforced guest-specific deny-all egress policy would require
its own host security review. Neither is implemented or authorized by the
checked-in YAML. Do not infer safety from absence of `networks:`, from
`internal: true` Compose bridges, from `plain`, or from a Docker daemon
running as a non-root user.

## Next acceptance evidence (not supplied)

Record an exact VM boot configuration, no-network/egress enforcement and
negative host-loopback/LAN reachability tests; guest resource bounds,
approved Docker API and cgroup-v2 delegation, no shared host paths/sockets,
the approved ephemeral per-node key lifecycle and verifiable destruction.
Only then request a *separate* runtime-start and image-use decision.
C (Docker Hub base provenance, signed final SSH image, package source and
per-node test keys) and D (real A01–A03, exact-head Native Level-3 and
independent review) retain their own HOLDs.

References: Lima official user networking and plain-mode documentation.
This checklist is static evidence, not a container or network firewall.
