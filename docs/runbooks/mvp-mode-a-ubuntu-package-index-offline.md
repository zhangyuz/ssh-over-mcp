# Mode A / C5 — signed Ubuntu package-index preview (metadata only)

**Approval:** C5 read-only public Canonical APT `InRelease`, official archive key and `Packages.xz` metadata on the **development workstation only**, accepted in conversation after [request #6392292586](https://github.com/zhangyuz/ssh-over-mcp/pull/342#issuecomment-6392292586). Not authorization for `apt update`, `.deb`/wheels, Docker, guest VM, SSH keys, package install, cgroup, image build or deployment.

The **non-executable candidate evidence** is [`deploy/ssh-target/ubuntu-2604-amd64-metadata-candidates.json`](../../deploy/ssh-target/ubuntu-2604-amd64-metadata-candidates.json). It stores 3 signed-pocket manifest observations and **10 direct package candidates** (not their transitive dependency closure). No executable packages, OCI blobs, or private keys were obtained.

## Verification chain

- Official signer documentation: <https://documentation.ubuntu.com/security/software-integrity/archive-verification/> and <https://documentation.ubuntu.com/security/software-integrity/image-verification/>. The archive public keyring came from `https://archive.ubuntu.com/ubuntu/project/ubuntu-archive-keyring.gpg`. **Independently trusted fingerprint**: `F6ECB3762474EDA9D21B7022871920D1991BC93C` (Ubuntu Archive Automatic Signing Key 2018). Keyring bytes SHA256: `80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31`. A self-provided key without the independently trusted fingerprint is not sufficient.
- HTTPS `InRelease` files came from `archive.ubuntu.com/ubuntu/dists/{resolute,resolute-updates}` and `security.ubuntu.com/ubuntu/dists/resolute-security`. Only these three pockets and component `main`, architecture `amd64` were read.
- For **each** `InRelease`, local `gpgv --keyring <verified Ubuntu archive keyring> --status-fd 1` succeeded with an exact `VALIDSIG` matching the above fingerprint. The signed `SHA256` table's unique `main/binary-amd64/Packages.xz` entry provided the compressed length and digest. Files were read via `.../main/binary-amd64/by-hash/SHA256/<digest>` on the same canonical HTTPS origin and their actual bytes matched signed length + SHA256. Compressed index reads were bounded to 4 MiB, expanded plaintext to 25 MiB. Nothing from the `pool/` package paths was fetched.
- The operator-facing verifier `ops/mvp/ubuntu_package_index_offline.py` repeats **offline** byte, signature/fingerprint and hash/index checks on locally supplied metadata. It refuses symlinks/special files, invalid signatures, wrong pocket/architecture, missing or duplicate index entries, malformed chosen package metadata, and oversized/trailing compressed input. It has **no network or APT/Docker import**.

| Pocket | InRelease SHA256 | Main amd64 Packages.xz SHA256 |
| --- | --- | --- |
| resolute | `45f95ce276cdba3e41870516a130e03c58b8b7a79e9546b0efe9e526d255740c` | `ed9ac41cb263efaecc5a06a0742dc56570e2fb5ff94c4f2e4b2fbdcddd73cf24` |
| resolute-updates | `aee81345dd6906d8474a25a6a24e11e8a4e77284e59c5acf83d568778f57590f` | `1cf958eef1b87a29f06430c01fb19b6a10c131b1c9dad806be7d515d90a1a683` |
| resolute-security | `66bf17a6b779051e7fb05ef23d886aa7e0274f642e2a7f0cfd8cfc9aa2361515` | `c9f4f90adfc5fcb1228e0aea6369c868ffa227b005782a1738ecdbb47fc46d56` |

Example of a **purely offline** recheck (only with separately retained, verified public metadata input files; output always has `image_build_authorized=false`):

```sh
python3 ops/mvp/ubuntu_package_index_offline.py \
  --pocket resolute-security \
  --inrelease /offline/resolute-security-InRelease \
  --packages-xz /offline/resolute-security-main-amd64-Packages.xz \
  --keyring /offline/ubuntu-archive-keyring.gpg
```

## Proposed selected direct packages (NOT complete install lock)

Security pocket is preferred when that exact package is present; otherwise updates, then release. This is a **source review proposal**, not a Debian version resolver, and never resolves runtime dependencies, package conflicts, installation effects, or future security updates.

| Package | Candidate version | Signed pocket |
| --- | --- | --- |
| openssh-server and openssh-client | `1:10.2p1-2ubuntu3.8` | resolute-security |
| sudo | `1.9.17p2-1ubuntu3.2` | resolute-security |
| python3 and python3-minimal | `3.14.3-0ubuntu2` | resolute |
| libssl3t64 / openssl | `3.5.5-1ubuntu3.7` | resolute-security |
| libc6 | `2.43-2ubuntu2.4` | resolute-security |
| libpam0g | `1.7.0-5ubuntu3.2` | resolute-security |
| ca-certificates | `20260816ubuntu0.26.04.1` | resolute-security |

The JSON snapshot includes each version, architecture, signed-index-provided `.deb` filename, declared SHA256 and size, plus the pocket's exact InRelease and Packages index hashes. The `.deb` **bytes remain unverified**; cryptographic claims do not transfer from signed metadata to a package we did not retrieve. This is **not a complete dependency/wheel lock**. Preserve raw signed metadata out of band if replay at the exact 2026-10-24 snapshot is needed; a future rolling archive may no longer serve identical `InRelease`. Ubuntu Snapshot is an independently reviewable historical retrieval route, but no snapshot download is authorized here.

## Non-waivable next gates

To make a runnable trusted image, separately approve artifact fetch and verification of full package `.deb` payloads, complete transitive signed package graph, locked Python wheels and builder, immutable OCI config/blobs, verified build provenance/SBOM/signatures, secure offline media import, independently reviewed ADR0022 OCI sudo/NNP/cgroup split, and an isolated B Linux VM with demonstrated host/LAN egress denial. **No runtime image has been built or permitted.** The previously stopped `som-mode-a-ubuntu2604` remains untouched. PR #342 still requires real A01–A03 Level2, exact-head trusted Native Level3 and independent final release review.
