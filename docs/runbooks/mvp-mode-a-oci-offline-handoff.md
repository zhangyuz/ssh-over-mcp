# MVP #342 OpenSSH OCI offline image handoff — TEST ONLY

**Status:** GitHub OIDC/Sigstore-attested *test archive* available;
**not a signed runtime image or production release**. The
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

## Verified GitHub OIDC/Sigstore archive handoff (host-side, TEST ONLY)

The public repository's PR-only build signs the compressed test **archive**
using the pinned official GitHub `actions/attest` action *after* normal
and separate userns Engine central Ledger E2E succeeds. Its OIDC certificate
binds the producing workflow identity to the archive SHA256. On an
operator-controlled host, before bringing bytes into an isolated guest:

```sh
umask 077
dir=$(mktemp -d /tmp/som342-attested-handoff-XXXXXX)
gh run download <EXACT_GREEN_RUN_ID> --repo zhangyuz/ssh-over-mcp \
  --name mvp-342-openssh-oci-source-build --dir "$dir"
(cd "$dir" && sha256sum -c OFFLINE_IMAGE_SHA256SUMS)  # Linux; use shasum -a 256 on macOS
grep -Fx "PR_SOURCE_SHA=<EXACT_APPROVED_PR_HEAD_SHA>" "$dir/PROVENANCE.txt"
grep -Fx 'TEST_ARCHIVE_GITHUB_PROVENANCE_ATTESTED=true' "$dir/PROVENANCE.txt"
gh attestation verify "$dir/som342-openssh-fs.docker.tar.gz" \
  --repo zhangyuz/ssh-over-mcp \
  --signer-workflow zhangyuz/ssh-over-mcp/.github/workflows/mvp-342-oci-source-build.yml \
  --deny-self-hosted-runners --format json > "$dir/attestation-verified.json"
# Same signer identity and exact merge-source digest are mandatory for BOTH.
merge_sha=$(sed -n 's/^TEST_MERGE_SHA=//p' "$dir/PROVENANCE.txt")
gh attestation verify "$dir/REMAPPED_IMAGE_TEST_RECEIPT.json" \
  --repo zhangyuz/ssh-over-mcp \
  --signer-workflow zhangyuz/ssh-over-mcp/.github/workflows/mvp-342-oci-source-build.yml \
  --source-digest "$merge_sha" --deny-self-hosted-runners --format json \
  > "$dir/remap-receipt-attestation-verified.json"
# After both attestations succeed, compare the signed JSON claims to
# independently downloaded manifest and archive, never only to CI output.
python3 - "$dir" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
r = json.loads((p / "REMAPPED_IMAGE_TEST_RECEIPT.json").read_text())
sha = hashlib.sha256((p / "som342-openssh-fs.docker.tar.gz").read_bytes()).hexdigest()
assert r["source_archive_sha256"] == sha
assert r["schema"] == "som342-userns-test-only-v1"
assert r["production_signed_runtime_id"] is False
assert r["production_deployed"] is False
assert r["entrypoint"] == "/usr/local/libexec/ssh-over-mcp-image-hold"
PY
```

**Actually verified on Yuz.local:** workflow
[#40539689998](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40539689998),
exact source SHA `f7a931a4644be812bd5493808d8613a7ef7a57ec`,
archive SHA256 checked, `gh attestation verify` returned one
cryptographically valid SLSA provenance statement with the pinned
workflow identity. GitHub attestation guarantees provenance of **these
archived bytes**, not security or signature of the remapped Docker
runtime image ID. The **historical f7a931a test archive** did not embed
the native no-sudo launcher; it used a separate test bind mount, and
is **NOT a deployable production image**. New test source bakes the
exactly generated native launcher and sshd config as root-owned immutable
files inside a derived review-only image. Require a fresh archive containing
`NATIVE_NOSUDO_CODE_BAKED=true`, its exact `FS_NATIVE_REVIEW_IMAGE_ID`,
both central Ledger passes, and its own GitHub attestation. The new image
remains a candidate; `STOP78` is still enforced.

### 2026-10-27 exact-head host-side verification (test media only)

For PR source `154880cc0cfa9fea756a863e07c63d4c84384760`, downloaded
[run #40569048733](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40569048733)
to a private temporary directory on `yuz.local` **without Docker load or
execution**. Verified `OFFLINE_IMAGE_SHA256SUMS`; independently checked
**both** GitHub OIDC attestations against the exact pinned workflow and
`TEST_MERGE_SHA=3fd850681bc0843cc41a808acdfcdb5570ff4242`:
[archive #60536842](https://github.com/zhangyuz/ssh-over-mcp/attestations/60536842),
[remapped receipt #60536862](https://github.com/zhangyuz/ssh-over-mcp/attestations/60536862).
Each verification returned one trusted statement.

Read the *compressed test archive*, without extraction/`docker load`, and
independently hash-check its embedded OCI descriptors: top-level `index.json`
selects test source OCI index `sha256:ce126ce7d228825ab4805707fd731390f6c1bdd89939a7a3c5670092218fb2ef`;
its **unique `linux/amd64`** manifest points to config
`sha256:32783927f2394afa34ce29cd25d7995513052ae8f92f8ddd24b25fb0baa43fd0`.
This config digest equals the separately signed receipt's *test-only*
`remapped_runtime_image_id`; `manifest.json` points to that config too.
The config entrypoint is still
`/usr/local/libexec/ssh-over-mcp-image-hold` (**STOP78**).
The archive is a Docker-save tar which includes both `manifest.json` and
`oci-layout`/`index.json`/`blobs/sha256` entries; do not assume legacy-only
`<image-id>.json` archive paths. OCI descriptor consistency is **not** an
Engine package signature or a production deployable image approval.
The handoff requires an independently signed final runtime image and the
same checks **inside the actual no-NIC guest** before deployment.

The hosted userns test now records `REMAPPED_IMAGE_TEST_RECEIPT.json` **only after** its real two-node central MCP/Ledger, SSH privilege and directional ACL probes succeed. The receipt links the archive SHA-256, original test image ID, observed post-import image ID, subordinate UID/GID bases, PR HEAD and merge SHA. GitHub separately attests the JSON file with the same pinned workflow. An operator must verify **both** attestations, require the exact approved PR HEAD and merge source digest, and independently compare the JSON archive SHA-256 with the downloaded archive. This only authenticates a **CI test observation**, not the final guest OCI image or its startup permission. Any missing or mismatched receipt must fail closed.

Do not confuse `TEST_ARCHIVE_GITHUB_PROVENANCE_ATTESTED=true` with
`SIGNED_IMAGE=true`; the provenance receipt explicitly keeps
`SIGNED_IMAGE=false` and `SIGNED_RUNTIME_ID=false`. The JSON likewise records `production_signed_runtime_id=false` and `production_deployed=false`. Never execute
an unsafely imported archive because its checksum or attestation passed.

## Ubuntu 26.04 offline Engine prerequisite (one-shot authorized; execution blocked)

The prior one-shot signed APT Engine media builder [#40357097647](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40357097647) failed **before** `apt-get update`, download, or installation; it remains deliberately disabled. [Read-only diagnosis #40551154239](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40551154239) showed the hardcoded direct Ubuntu `URIs:` predicate is false, even though the Ubuntu archive-keyring and `Signed-By` checks are true. The initial diagnostic's Ubuntu release false was a **probe bug** caused by refusing the standard `/etc/os-release` symlink; the probe now uses Python's freedesktop OS-release reader and reports a bounded URI *class*, never raw source contents. [Exact-head diagnosis #40552177535](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40552177535) confirmed `UBUNTU_2604=true`, `UBUNTU_MIRROR_LIST`, expected archive keyring and signer; normal and remapped OCI FS/ACL checks also passed. The disabled one-shot script now accepts Ubuntu's standard signed mirror-list URI while continuing to require Ubuntu `resolute` suites, the expected keyring, non-insecure source options and signed APT verification. **It is still disabled**; no Engine `.deb` package closure has been downloaded or installed by this change. Ordinary disposable OCI CI now runs `ops/mvp/mode_a_hosted_apt_probe.py`, a **read-only** check that reports individual old preflight predicates (`UBUNTU_2604`, `X86_64`, `NON_ROOT`, archive keyring, Ubuntu source URI, keyring signer) without printing source contents, changing APT or fetching dependencies. An all-true result establishes **only** suitability for a separately reviewed signed-APT dependency-media attempt; it never establishes a trusted Engine, an offline guest execution, or release authorization. `OFFLINE_ENGINE_MEDIA_BUILD_AUTHORIZED=false` is always emitted. The operator subsequently gave a bounded one-use media-attempt authorization on 2026-10-27 ([decision](https://github.com/zhangyuz/ssh-over-mcp/pull/342#issuecomment-6450082397)). **Authorization is not execution:** the enabled-workflow commit/push was blocked by execution safety controls ([checkpoint](https://github.com/zhangyuz/ssh-over-mcp/pull/342#issuecomment-6450125086)). The source retains an explicit GitHub Actions `&& false` job guard, so neither that authorization nor a normal PR synchronization runs APT or acquires any `.deb` bytes. A separate, directly permitted one-shot execution and independently verified offline artifact remain unfulfilled; do not work around the blocked action by another channel. After any permitted single attempt, disable the job before further normal development pushes.

## Offline verification (inside a separate, disposable Linux guest ONLY)

After independently verifying the guest **has no NIC**, no host paths,
no Docker socket sharing, adequate disk, a private dedicated Engine with
user-namespace remapping and signed artifact identity, unpack the artifact
into a fresh private directory **inside that guest**:

```sh
sha256sum -c OFFLINE_IMAGE_SHA256SUMS
gzip -t som342-openssh-fs.docker.tar.gz
gzip -dc som342-openssh-fs.docker.tar.gz | docker load
docker image inspect som-mvp-fs-native-review:local \
  --format '{{.Id}} {{json .Config.Entrypoint}}'
```

Compare the *full* image ID with `FS_NATIVE_REVIEW_IMAGE_ID` in
`PROVENANCE.txt`, and require the entrypoint to be
`["/usr/local/libexec/ssh-over-mcp-image-hold"]`. **No `docker run`
yet.** This import is a test-only provenance/transport step, not an
approval to turn off STOP78. Do not use Docker Desktop or the running
GitHub Actions runners for this experiment.

## Still blocking live service

1. Independently authenticated/signature-verified image promotion and a
   userns-remapped dedicated Linux Engine (never daemon-wide changes on the
   shared Yuz.local Docker Engine).
2. Same image's root OpenSSH hostkey custody and approved FS kernel
   boundary (candidate currently NNP1, four capability sets zero,
   exact nonzero `CapBnd`, **not** yet approved five-zero), real
   two-node typed FS protocol and denied cross-node actions under the
   **actual no-NIC VM and final Compose networks**.
3. Revalidate real central MCP + one-use Ledger using **the same baked
   image**, per-node internal port **2222**, directionally denied node→MCP
   traffic, independent whole-PR security review and rollback evidence.

All nonessential exec/manager/cgroup/Mode B functionality remains TODO.
Until then: **deployment HOLD; PR Draft; Yuz.local not live.**
