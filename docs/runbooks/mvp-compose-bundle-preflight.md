# MVP topology + rendered Compose bundle preflight (offline-only)

This operator command validates **a single bounded set of mutually consistent static declarations** across the existing topology manifest and Mode A/Mode B *rendered* Compose JSON descriptions. It is an offline helper, **not** proof of deployment, image provenance, host-key identity, private network isolation, actual Docker Engine separation, or permission to deploy. Successful output always says `deployment_ready=false`.

## One user-facing operation

Render the relevant Compose projects with `docker compose -f ... config --format json` using only authorized synthetic/operator-controlled inputs, and keep the rendered files private. Compose rendering can interpolate credentials, so **do not upload secrets or paste rendered documents in tickets**. The bundle validator itself does not execute Compose, Docker, SSH, HTTP or host mutations.

**Mode A — one declared Linux Engine with two SSH target services:**

```sh
python3 ops/mvp/bundle_preflight.py \
  --topology-json /private/operator/mode-a-topology.json \
  --control-json /private/operator/mode-a-rendered.json
```

**Mode B — independently declared control / node01 / node02 project documents:**

```sh
python3 ops/mvp/bundle_preflight.py \
  --topology-json /private/operator/mode-b-topology.json \
  --control-json /private/operator/control-rendered.json \
  --node01-json /private/operator/ssh-host01-rendered.json \
  --node02-json /private/operator/ssh-host02-rendered.json
```

The manifest's validated `mode` alone determines the accepted file layout, so an operator cannot accidentally ask the CLI to check a different mode. Argument presence is checked independently of document contents: a supplied `null` node JSON file is **not** silently treated as an omitted flag. In Mode B, the `node01`/`node02` flags associate files with **declared** aliases; they are not verified bindings to actual host identities. The tool rejects missing/extra per-node files and repeated lexical input paths, but even multiple distinct files do **not** prove independent Engines or immutable, coherent cross-file snapshots.

The unified static checker invokes the existing, independently tested **topology** and **Compose-rendered config** shape validators, using their 16 KiB per-input race-guarded regular-file reader (no leaf symlinks, FIFOs or duplicate JSON keys). It then requires these **literal OCI digest reference strings** to agree:

| Manifest field | Rendered Compose services required to match |
| --- | --- |
| `control.image` | control project's `ledger-init`, `ledger`, `mcp` and optional `approvalctl` |
| `targets[node01].image` | Mode A `node01`; or Mode B `--node01-json` project's `ssh-target` |
| `targets[node02].image` | Mode A `node02`; or Mode B `--node02-json` project's `ssh-target` |

`cloudflared` is separately validated by the underlying Compose checker but uses its **own image**, not `control.image`. A target manifest may intentionally declare the same image digest for both SSH targets; this still does not prove that those targets are separate machines. Host-key fingerprints are validated for *syntax and uniqueness* by the topology checker but **cannot** be compared against live SSH keys or image contents here. The check does not validate that the image registry actually contains the digest, that Compose would start, or that an operator-generated manifest represents a trusted source.

A positive report includes `schema=som-mvp-compose-bundle-preflight-v1`, `static_artifacts_consistent=true`, `topology_shape_valid=true`, `compose_shape_valid=true`, and `image_declarations_match=true`. It **always** reports `deployment_ready=false`, `host_identity_verified=false`, `network_acl_verified=false`, `image_trust_verified=false`, `runtime_verified=false`, `live_e2e_verified=false`. Failure returns nonzero with only a fixed reason code such as `IMAGE_DECLARATION_MISMATCH` or an inherited existing static-validator code. It does not echo document contents, reference strings, paths or secret bytes.

## Security boundary and verification plan

This is a static consistency check for **declarations read sequentially**; it does not authenticate an operator, check source provenance, bind a manifest to an Engine, prove the identity of a live SSH server, atomically snapshot multiple files, or verify network reachability/firewall/host cgroup and filesystem policy. All previously documented M1a/M1b Mode A/B A01–A18 live acceptance gates remain **NOT_RUN/HOLD**, and no host privilege, trust root or deployment approval is implied.

Test-first implementation must show RED for the missing CLI, then GREEN for both modes; additional adversarial regressions cover digest mismatch by service/target, swapped node associations, malformed host-key pins, hardening deviations, mode/file errors, same path, oversize, symlink/FIFO and no input reflection. For a real operator example, render harmless **synthetic** Compose documents with the offline `config --format json` command, feed the results to the bundle CLI and confirm it prints `deployment_ready=false` in both modes. Never treat that as an actual Docker or SSH E2E acceptance.

The underlying individual validator guides remain authoritative: [topology](mvp-topology-preflight.md), [rendered Compose](mvp-compose-config-preflight.md). See [MVP status](../mvp-status.md) and [ADR0021](../decisions/0021-private-compose-rw-mvp-release-track.md).
