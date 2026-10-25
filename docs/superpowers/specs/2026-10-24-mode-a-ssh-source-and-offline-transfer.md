# Mode A SSH target source, image, offline import, and ephemeral SSH keys

**C1–C4 operator decision:** [PR342 approval #6392167263](https://github.com/zhangyuz/ssh-over-mcp/pull/342#issuecomment-6392167263) authorizes **public registry manifest metadata + offline source/key design only**. No VM boot, images/keys, Docker Engine, host/cgroup/network changes, privilege exceptions, Ready or merge. This is an unapproved build-design proposal. The existing stopped Lima `som-mode-a-ubuntu2604` must stay untouched.

## Public provenance and immutable metadata

- Repository: `docker.io/library/ubuntu`, Docker Official Image maintained by Canonical, official listing https://hub.docker.com/_/ubuntu .
- Official-images declaration: https://github.com/docker-library/official-images/blob/master/library/ubuntu . For the 26.04 / resolute 2026-10-06 `linux/amd64` source it points to Launchpad ubuntu-base commit `d5b48b3b44d98cf4a7f5fcf570c5a2acfdf7b723`, `dist-resolute-amd64-20261006-d5b48b3b`. Docker Hub states Ubuntu 26.04+ rootfs is assembled by Rockcraft rather than older livefs paths. Listing and source reference are **documentation**, not a cryptographic attestation of the downloaded layers.
- Public Registry HTTP API v2 `/v2/library/ubuntu/manifests/26.04`, `Accept: application/vnd.oci.image.index.v1+json`: observed and separately SHA256-checked *response bytes* against `Docker-Content-Digest` `sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944`.
- Exactly one descriptor for `linux/amd64`: OCI platform manifest `sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a` (size 1,392 bytes). Independent GET manifest by digest matched both declared byte length and HTTP content digest. Config **descriptor** `sha256:b9e485d4a3bc6efa60fc5150444a82f3d96991fdcec7caa1d0f3e7a0b5859321`; two layer **descriptors**; no blob/config/layer content retrieved or verified.
- Immutable **candidate** base reference for a future independently reviewed build: `docker.io/library/ubuntu@sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a` specifically `linux/amd64`. It is neither the Docker image built by SOM nor an approved trusted binary. Mutable tag `ubuntu:26.04` is not accepted for build/launch.
- Registry metadata checked 2026-10-24 under C4, in an ordinary isolated metadata-only HTTPS request from the connected development workstation, **not the guest**, with transient anonymous bearer token; no OCI blob endpoint and no Docker daemon access. Tag can move: any new digest requires its own traceable review; do not silently replace the pinned one.

Use the new **offline, no-network metadata verifier** on independently captured OCI index and platform JSON:

```sh
python3 ops/mvp/oci_manifest_offline_preflight.py \
  --index /path/to/verified-index.json \
  --platform-manifest /path/to/verified-amd64-manifest.json \
  --expected-index sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 \
  --expected-platform sha256:42527649dbc4f9197a6073f426f488cbff0e9cc9f2afce32d91c383e4875634a
```

The CLI checks bytes, references, unique architecture and strict finite metadata only. It **does not claim any repository source** for caller-supplied bytes: `repository_provenance_verified=false` is mandatory even for self-consistent synthetic manifests. It also always reports `publisher_signature_verified=false`, `image_use_authorized=false`, `deployment_ready=false`, and `image_layers_downloaded=false`. The separate live HTTPS registry response and official-images listing are externally observed contextual provenance and must never be inferred from the offline CLI's hash consistency. Even a valid hash from untrusted file data is **not signature verification** or container runtime authorization.

**C5 signed APT metadata candidate (SOURCE ONLY):** [Ubuntu 26.04 GPG-verified pocket receipts and 10 direct package suggestions](../../runbooks/mvp-mode-a-ubuntu-package-index-offline.md) were derived from official `resolute`, `resolute-updates` and `resolute-security` `InRelease` + `main/binary-amd64/Packages.xz` metadata using the separately trusted Ubuntu Archive Key fingerprint `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Candidate direct package versions/digest claims appear in [JSON metadata snapshot](../../../deploy/ssh-target/ubuntu-2604-amd64-metadata-candidates.json). Package payload bytes and transitive dependency closure remain unverified; no build/install permission is inferred.

## Proposed locked package/build graph (C2 HOLD before any execution)

`deploy/ssh-target/Dockerfile.proposed` pins the independently observed base platform digest and **deliberately exits before installing anything**. It is not referenced in any Compose service, cannot produce the final SSH image and must never be used as a workaround for operator approval.

Before removing the explicit STOP guard, independently review and freeze all of:

| Source | Freeze requirement | Current status |
| --- | --- | --- |
| Ubuntu base | official-images Canonical lineage, OCI index+amd64 digest, signature/registry-auth and revocation | metadata byte consistency only; binary authenticity HOLD |
| Ubuntu 26.04 distro packages | exact `openssh-server`, `sudo`, `python3`/runtime, libc/NSS/CA and dependency versions + architecture; trusted mirror `InRelease` signature, signing key fingerprint, immutable `Packages` checksums and every `.deb` SHA256 | **not collected/locked**; no `apt update` or package fetch |
| SOM Python application | exact commit `b288f28...` as initial reference **until build candidate is re-pinned to latest reviewed HEAD**; locked wheels and transitive SHA256, hashes via `pip --require-hashes`, wheel builder provenance | project currently allows version ranges; reproducible lock missing |
| Privileged launcher | trusted source `ops/live-e2e/ssh-over-mcp-host-agent-launcher.py` with exact installed binary/source hash, immutable root ownership, tested env cleaning and fixed sudoers/no-argv invocation | accepted ADR0007 native scope, **OCI NNP/sudo exception unapproved** |
| SSH admission/manager | `sshd_config.proposed`, manager UID/cgroup/FD/IPC manifest, per-node provenance, no shell/port forwarding, fail startup if missing trust | ADR0022 proposed, not an accepted OCI privilege plan |
| Final project SSH image | deterministic source+packages+toolchain build, SBOM (SPDX/CycloneDX), signed provenance/attestation, digest and independent reviewer, separate image digest for artifact used by each node | **does not exist**; do not insert synthetic digest in `SSH_OVER_MCP_NODE*_IMAGE` |

Build-source design must use offline verified packages and wheel archives; never `apt-get update`, an unpinned public APT repository or runtime `pip install` against the internet. The initial unresolved OCI `cap_drop:ALL` and `no-new-privileges:true` versus fixed sudo launcher conflict **blocks** a buildable runtime Dockerfile until independently accepted process-level privilege design. No `CAP_SYS_ADMIN`, host cgroup-root mount, broad sudo, host PID/network namespace or Docker socket.

## Fetch → verify → transfer → import plan (requires new separate approvals)

1. **External fetch host / review station:** only after explicit source and egress approval, acquire OCI manifest, config and blobs **by independently approved immutable digests**; acquire immutable Ubuntu package `.deb` archive + `InRelease`/package indices and pinned wheel artifacts. The C4 public manifest-only action performed so far does **not** cover blobs, packages or build inputs.
2. **Verify before copying:** strict transport TLS, cryptographically verify actual blob bytes and each descriptor's digest, expected architecture/media type, source signatures/key fingerprints and offline package `InRelease` chain; reject mismatches, revoked publisher, duplicate identity, unbounded data, unsupported redirects or extra files.
3. **Bundle in a reviewable offline layout:** canonical, bounded manifest listing each artifact path, actual SHA256, size, source URI, signer/authority and version; envelope signed by separately approved operator. No raw secrets in the bundle; no mutable tag as authority. Fail if source metadata or signed manifest is missing.
4. **Transfer through an operator-reviewed, non-shared, one-way medium** into a **disconnected** guest. Re-verify byte hashes and trusted signatures inside the guest before any privileged installation or OCI import. No Lima host mount, forwarded TCP/SSH port, shared clipboard, Docker socket or ad hoc outbound internet. A disconnected NIC plus reviewed data media is preferred over the unverified default Lima 2.2 user-mode network.
5. **After separate B/C/runtime authorization only**, install `deb`/wheels with no network and audit each; import immutable OCI archive to the guest's isolated Engine, verify resulting manifest/platform digests, then build attested project image from locked context and record exact digest, SBOM, creator and immutable source HEAD.
6. **On any unknown state or mismatch:** stop without fallback to network, mutable tags, unverified host images, test credentials or privileged scripts. Preserve audited evidence and revoke any ephemeral test grants; never claim A01–A03 PASS from offline metadata.

No guest/host image/package medium, snapshot, cloud network, VM boot or Docker installation has been executed or authorized by this design.

## Ephemeral SSH key plan (C3 design only)

- **After independent B isolation + guest privilege approval and separate C key-generation authorization:** generate **three independent nonproduction keypairs** using a reviewed guest-local trusted CSPRNG: ED25519 SSH host key for `node01`, distinct ED25519 SSH host key for `node02`, and client authentication keypair held only by the control-plane identity. Never generate them during this design phase. Never read/copy workstation identity files or production keys.
- Each SSH node's private host key: root-owned `0600` and containing directory `0700`, mounted **read-only** at its own `/etc/ssh/hostkeys/ssh_host_ed25519_key`; never share the two hostkeys named volumes. Node's `authorized_keys` is a separate reviewed, root-owned `0644` public-only file in `/etc/ssh/authorized_keys/%u`, under nonwritable parent. No `authorized_keys` shared with host private key volume; no unreviewed authorized-command options or model input.
- Client private key: unique nonproduction control-plane secret under dedicated non-root read-only mount with `0600` file and bounded secret directory. No keys in build context, OCI layers, Git, CI secrets/logs, PR comments, Docker ENV/ARG, or transferred manifest.
- **Pin before first connection**: separately fingerprint each host public key using `ssh-keygen -lf` SHA256 output and build exact alias-bound known-hosts pins for `node01` and `node02` with strict host key checking. Changes/refusals must fail closed, not TOFU. Verify node host keys distinct and only the reviewed client public key grants `ForceCommand` for `mcp-v1`.
- **Rotation/revocation:** revoke existing approvals and sessions, stop targeted node, rotate one test host key out-of-band, update pinned trust only by explicit operator reapproval, prove old pins reject; destroy both node private keys and control client private key on VM teardown after authorized destruction and capture nonsecret audit receipt. No snapshot rollback may reinstate a revoked key/approval.
- **Hard negative evidence**: wrong host key, swapped node keys, reused client key in an unapproved identity, invalid file ownership/permissions, leaked FD/volume, unauthorized shell/PTY/tunneling, manager/socket identity mismatch and restart/cleanup fail startup/connection.

**Unsigned artifact refusal:** any unsigned image provenance, untrusted signer, missing package-index signature, reused SSH key or partial key destruction must remain a hard startup refusal, regardless of hash syntax. **Status:** no key bytes or signer objects created. Existing `som-mode-a-ubuntu2604` stopped and untouched. A OCI privilege plan, B network isolation/guest access, C image/package/signer/key runtime trust and D live A01–A03/Native Level-3 remain HOLD.
