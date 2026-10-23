# Offline multi-SSH Compose topology preflight (static only)

This operator CLI checks the **declared shape** of either MVP topology before any host, Docker Engine, SSH credentials or network is touched. It is a small, independently usable safety filter, **not a deployment installer, provenance verifier, network scanner, host-key attestation or release gate**. Success always reports `deployment_ready: false`, `network_verified: false`, `runtime_verified: false`, `trust_verified: false`, and `live_e2e_verified: false`.

```sh
python3 ops/mvp/topology_preflight.py --topology-json ./my-topology.json
```

Create `my-topology.json` locally, with exactly these keys (substitute operator-observed identifiers/digests/pins, never secrets):

```json
{
  "schema": "som-mvp-compose-topology-v1",
  "mode": "multi-host",
  "control": {
    "engine": "control01",
    "image": "registry.example.test/control@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "targets": [
    {
      "alias": "node01",
      "engine": "ssh-host01",
      "image": "registry.example.test/target@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "host_key_pin": "SHA256:BVvG5WHOVKd3mWq7qaDkdgqEbLY0z+u5vxqpddXt2B4"
    },
    {
      "alias": "node02",
      "engine": "ssh-host02",
      "image": "registry.example.test/target@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "host_key_pin": "SHA256:JHM4dTXo9fWZGq7UXjio3SlRF5mi4t9tfFc6c326ry8"
    }
  ]
}
```

The example above is **synthetic and NOT deployable**; these strings are not trusted image/SSH-host-key evidence. For developer E2E Mode A, choose `"mode": "dev-e2e"` and set `control.engine` and both `targets[].engine` to one declared engine ID such as `lab01`. For actual multi-host Mode B, the control and each target need three distinct declared engine IDs. **Declared IDs are operator-entered labels and the check cannot prove they correspond to different physical Docker Engines.**

The input must be one regular, non-symlink JSON file of at most 16 KiB. The reader rejects input changes detected by byte length or same-open-FD identity, size, mtime and ctime comparisons before/after reading; it does not provide immutable or cryptographic evidence. The checker uses one bounded read; rejects duplicate/unknown fields, malformed JSON, extra or missing targets, duplicate SSH host-key pins, mutable/unpinned image references, malformed OCI repository components (including `..`, empty segments and invalid registry ports), or wrong mode/Engine layout. Registry hostnames, explicit TCP ports and bracketed IPv6 registry names are accepted with digest-only references; tags are deliberately refused. It never parses private keys or contacts Docker/SSH/network, and does not echo untrusted input on refusal. A successful single-line JSON report only establishes that the supplied labels and digest/fingerprint *syntax* match the proposed MVP inventory requirements.

**Still required before any deployment:** independent verification of actual image digest/provenance and SSH host-key pins, two-host/three-Engine ownership, M1a/M1b container and cgroup/manager safety, private network ingress/egress and Docker NAT ACLs, real signed policy schema, all typed FS approvals/audit/UNKNOWN protections, and exact-head Native Level-3 plus real Mode A/B E2E. See [MVP status](../mvp-status.md), [ADR0021](../decisions/0021-private-compose-rw-mvp-release-track.md) and the [implementation plan](../superpowers/plans/2026-10-23-private-compose-rw-mvp.md). None is certified by this CLI.
