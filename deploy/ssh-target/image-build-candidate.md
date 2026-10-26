# Mode A single SSH-target OCI build candidate — TEST-ONLY, NOT ADMITTED

**Status: build source prepared; not built, not signed, not runtime-approved.**
The operator's fresh conditional authorization covers a one-off **disposable**
test-only packet *after independent exact-source and privilege review*. It
does not approve changing Yuz.local Docker/Lima, any persistent host ACL,
secrets or capabilities, Mode B, or merge.

The original `Dockerfile.proposed` retains its unconditional STOP 78. This
new `Dockerfile.review-candidate` is **not wired into Compose** and has an
independently installed HOLD entrypoint that always exits 78. It is
**not an OCI authorization**. Building it alone will not run sshd and cannot
count as A01–A03.

## Bounded build source

- Base: exact inspected Canonical Ubuntu 26.04 linux/amd64 OCI digest. Merely
  referencing a manifest is not signature or layer attestation.
- Ubuntu 26.04 stock **signed** official APT archive key + deb822 `Signed-By`
  check; normal `apt-get update`, retaining raw signed `InRelease`, package
  index, source definition and keyring under provenance before cleanup.
  Lock OpenSSH server `1:10.2p1-2ubuntu3.8`, sudo `1.9.17p2-1ubuntu3.2`,
  Python `3.14.3-0ubuntu2`, CA certificates `20260816ubuntu0.26.04.1`
  to the existing signed C5 metadata candidates; tentative venv package
  `3.14.3-0ubuntu2` must be confirmed by actual signed APT or STOP.
  Download-only closure, SHA-256 of *each* fetched `.deb`, then install
  the exact same direct versions and record `dpkg-query` inventory.
  Transitive closure is resolved by signed APT and captured in the receipt;
  no unverified PPA/mirror, unsigned source or opportunistic `cap_add`.
- Existing committed `requirements/runtime.lock` verifies each downloaded
  Python wheel by hash; record exact `.whl` SHA-256 and install offline
  from those verified same bytes. Its provenance is Python 3.13; target
  Ubuntu Python 3.14 wheel/ABI compatibility must succeed in the one-off
  builder or STOP; no fallback to unpinned dependencies.
- Copy root-owned, read-only application source, the **OCI-specific** fixed
  no-argv launcher with actual Linux UID/GID/capability syscall adapter,
  the distinct candidate-only ForceCommand sshd config and **one** narrow
  matching sudoers rule. The previously accepted managed-host launcher is
  not copied or modified. The candidate's image ENTRYPOINT **still exits 78**.
  The
  source installer creates no persistent private keys, authorization tokens,
  or host policy grants. Ubuntu OpenSSH package post-install *may*
  temporarily generate default host keys; builder deletes all such files
  in the same uncommitted RUN, verifies zero remain, and must independently
  attest no secret-bearing final layer. Real node01/node02 host/authorized
  keys must be separate ephemeral guest-provisioned volumes.
- Build receipt (not yet produced): exact base image raw digest, official
  signed metadata, complete `.deb` hash list, `dpkg` inventory, wheel hash
  list, exact Git SHA, image output manifest/config/layer SHA256, isolated
  builder job ID and signed external attestation. Verify raw byte/digests
  independently *before* loading into a no-NIC guest.

## Unresolved P1 kernel/identity/runtime gates — STOP

1. The accepted **managed-host** launcher still requires
   `SUDO_UID=2202` and `SUDO_GID=3202`, since those are its host login
   identity. The **proposed OCI** login account is UID **2201**/GID 3201,
   while the proposed OCI trusted agent is UID **2202**/GID 3202. This
   genuine mismatch would refuse the sudo handoff. Do not silently weaken
   the existing launcher to accept either identity. The new OCI-only
   [admission source](../../src/ssh_over_mcp/host_agent/oci_launcher_admission.py)
   now checks 2201:3201 and orchestrates fixed manager self-pidfd ACK,
   root socket close and exact 2202:3202 drop **without** a cgroupfs write.
   The reviewed source now includes a concrete fixed Python `-I -S` OCI
   launcher with Linux capability syscalls and exact candidate-only
   ForceCommand/sudoers integration. Sudo retains *only* the needed SSH
   command variable; privileged Python import refuses bytecode caches.
   **Image ENTRYPOINT still exits 78**. Actual root-owned file/namespace,
   socket mapping, cgroup writer and Linux kernel privilege execution remain
   unproven: no runtime admission or live Mode A claim.
2. The existing accepted launcher writes the **source cgroup** `host-agent-source/cgroup.procs`
   itself. OCI runtime contract **forbids** its writable cgroupfs mount in
   the sshd container; a separate manager must verify peer+pidfd and move
   source itself. Merely installing the managed-host launcher does *not*
   satisfy this requirement.
3. The OCI-only manager process entrypoint `ops/mvp/ssh-over-mcp-oci-manager.py`
   and `oci_manager_runtime.py` now provide a source-only fixed-node
   Unix listener, exact UID/GID and NNP/zero-cap verification, root-owned
   node-id selector and single-operation failure/unknown STOP. They call
   the existing pidfd source handler. **No manager image is built or enabled;
   child attach / scoped workload management remains unconnected.**
   The OCI-specific `oci_source_writer.py` now supplies a node-pinned,
   mount-ID-verified, single-write `cgroup.procs` callback connected to the
   existing self-pidfd manager handler, with explicit post-write UNKNOWN.
   **This is not an accepted kernel-level atomic PID attachment proof.**
   The manager's independently mapped UID/user/mount namespace, delegated
   node-only cgroup common ancestor, pidfd child attach/race, effective
   bounding/NNP/sudo capability matrix and two-direction Docker bridge
   firewall remain **UNPROVEN**. A failure never authorizes `privileged`,
   Docker socket, host cgroup root, broad sudo or new host capabilities.
4. The image may contain a candidate exact sudo rule but runtime startup
   remains disabled. Before any guest sshd boot, independently review the
   trust transition, exact OCI image and guest/no-NIC/destroy plan, then
   explicitly replace the HOLD entrypoint in a reviewed, separately
   approved SHA—not an ad hoc edit of this artifact.

## Narrow next step

Perform an independent read-only security review of these exact source
assets and tests. If review and pinned source provenance PASS, use the
operator-authorized **one** disposable secret-free Linux builder to obtain
real input/output receipts; do not start Yuz.local Docker or boot any guest
outside the independently reviewed no-NIC packet. Stop and record any missing
or conflicting proof. This candidate is intentionally an image-build
**increment**, not a working Mode A runtime or an unlocked Compose stack.
