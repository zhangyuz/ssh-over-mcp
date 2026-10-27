# MVP #342 OpenSSH OCI offline image handoff — TEST ONLY

**Status:** artifact transport candidate, **not a signed release**. The
`som342-openssh-fs.docker.tar.gz` produced by the dedicated GitHub-hosted
Ubuntu build is a Docker image archive (not an OCI-layout directory).
Its image still has the reviewed **STOP78 entrypoint**. Do not publish,
start, retag for production, or load on the shared Yuz.local Docker Engine.

## Getting a reproducible artifact

The `MVP #342 OpenSSH OCI hosted test and offline handoff` job is restricted
to the same-repository PR #342 and Ubuntu 26.04 GitHub-hosted runners.
It builds the pinned OpenSSH-only source image, actually tests two isolated
OCI `sshd` nodes, and only **after all tests pass** exports the **same**
container image using `docker save | gzip -n`. It records the compressed
archive's SHA256 and proves `docker load` restores the original image ID
with the STOP78 entrypoint. The resulting GitHub Actions artifact contains:

- `som342-openssh-fs.docker.tar.gz` — image content, with **no** host/client
  SSH private keys generated during tests (those are synthetic, external
  read-only binds and `/tmp` tmpfs);
- `OFFLINE_IMAGE_SHA256SUMS`, `PROVENANCE.txt`, `SOURCE_SHA256SUMS`
  — image SHA, PR source/merge SHA, image build IDs, source hashes and
  explicit unsatisfied gate flags.

Retained only three days. Access must stay limited to repository-authorized
operators because the image embeds application source. The GitHub artifact
digest and source commit must also be checked against the workflow run.
SHA256 alone ensures integrity *relative to the receipt*, not authenticity.

## Offline verification (inside a separate, disposable Linux guest ONLY)

After independently verifying the guest **has no NIC**, no host paths,
no Docker socket sharing, adequate disk, a private dedicated Engine with
user-namespace remapping and signed artifact identity, unpack the artifact
into a fresh private directory **inside that guest**:

```sh
sha256sum -c OFFLINE_IMAGE_SHA256SUMS
gzip -t som342-openssh-fs.docker.tar.gz
gzip -dc som342-openssh-fs.docker.tar.gz | docker load
docker image inspect som-mvp-fs-privsep:local \
  --format '{{.Id}} {{json .Config.Entrypoint}}'
```

Compare the *full* image ID with `FS_PRIVSEP_IMAGE_ID` in
`PROVENANCE.txt`, and require the entrypoint to be
`["/usr/local/libexec/ssh-over-mcp-image-hold"]`. **No `docker run`
yet.** This import is a test-only provenance/transport step, not an
approval to turn off STOP78. Do not use Docker Desktop or the running
GitHub Actions runners for this experiment.

## Still blocking live service

1. Independently authenticated/signature-verified image promotion and a
   userns-remapped dedicated Linux Engine (never daemon-wide changes on the
   shared Yuz.local Docker Engine).
2. Same image's root OpenSSH hostkey custody, UID2201/NNP/cap0, real
   two-node typed FS protocol and denied cross-node actions under the
   **actual no-NIC VM and final Compose networks**.
3. Real MCP control + central approval/Ledger, per-node SSH inventory pinned
   to the internal **2222** port, one-use FS writes and network egress
   negatives; independent whole-PR security review and rollback evidence.

All nonessential exec/manager/cgroup/Mode B functionality remains TODO.
Until then: **deployment HOLD; PR Draft; Yuz.local not live.**
