# ADR 0006: Full local E2E runs capability-bearing code only in a disposable Linux guest

- Status: Accepted
- Date: 2026-10-02

## Context

Phase 7A needs complete product-level evidence through real Linux security boundaries: OpenSSH sshd, ForceCommand, the host agent, authenticated containment-manager IPC, delegated cgroup-v2, workload identity/capability transition, filesystem operations, approvals, and audit.

The ordinary CI runner is intentionally hardened and must remain non-root, without a Docker socket, generic sudo, writable host cgroup authority, or host PID namespace.

ADR 0005 intentionally grants the trusted host-agent process only `CAP_SETUID` and `CAP_SETGID` so its child can transition to the distinct workload identity. ADR 0005 also states that those capabilities are not restricted to the configured workload IDs and that compromise of capability-bearing host-agent code permits impersonation of other identities in the same user namespace.

During Phase 7A planning, a disposable Linux probe confirmed the concrete consequence: after dropping to a non-root UID while retaining effective/permitted `CAP_SETUID`/`CAP_SETGID`, the process can successfully call `setresuid(0, 0, 0)`. Therefore a persistent runner/fixture which executes an unmerged target commit as the capability-bearing host agent would effectively give that target commit root-equivalent authority over the persistent fixture host.

That is incompatible with the intended E2E trust model.

Three designs were considered:

1. run the full E2E directly on a persistent privileged Linux runner;
2. run the full E2E in a privileged/shared-kernel container;
3. keep the persistent orchestrator unprivileged and execute the target commit only inside a fresh disposable Linux virtual machine.

## Decision

Use a fresh disposable Linux virtual machine for every full E2E run.

The persistent orchestrator:
- is a dedicated non-admin/non-root self-hosted account;
- has no generic sudo;
- does not expose a Docker socket to the workflow;
- executes only the trusted-main workflow definition and trusted-main orchestration script;
- never checks out or executes the target commit as a host worktree;
- fetches the exact target commit into a temporary bare Git repository;
- creates a Git bundle from that exact commit and copies the bundle into the disposable guest;
- never passes GitHub tokens, production credentials, or unrelated host secrets into the guest.

The disposable-VM principle in this ADR remains authoritative. The concrete Phase 7A provider is refined by ADR 0008 after review found that Lima/VZ still attaches a reachable user-mode network. The accepted provider is now QEMU/HVF with no virtual NIC (`-nic none`), no host filesystem sharing, read-only seed/payload media, and serial-only result collection.

The trusted Ubuntu 26.04 x86_64 base image and digest remain unchanged.

Inside the guest:
1. the exact Git bundle is cloned/checked out;
2. checked-out HEAD is verified against the requested 40-hex target commit;
3. root/capability fixture setup may execute because the VM is the containment boundary;
4. real sshd/ForceCommand/launcher/host-agent/containment/workload paths are exercised;
5. in-guest cleanup is verified.

The target commit may obtain root-equivalent authority only inside the disposable guest. That is an accepted property of this E2E because the guest contains no host mounts, production secrets, or orchestration token.

After every run, regardless of test result:
- the orchestrator terminates the QEMU guest it created and waits for process exit;
- removes the disposable disk overlay, seed/payload media, serial log, temporary bare repository/bundle, and wheelhouse;
- verifies no stale provider process/artifact remains;
- fails the workflow if guest destruction or host-side cleanup fails.

Unknown stale provider process/artifact state before a run causes fail-closed operator inspection rather than silent reuse.

The trusted workflow is dispatched from `main` with an exact `commit_sha` input. The GitHub workflow run's own `headSha` identifies the trusted workflow revision, not the tested commit. Tested-commit identity is established by the workflow input, bare-repository fetch result, bundle content, guest checkout HEAD, and guest expected-commit value all matching the same SHA.

## Consequences

Positive:
- capability-bearing unmerged code cannot root a persistent host;
- ordinary CI remains unprivileged;
- the E2E still exercises real Linux kernel/service behavior;
- full root/capability failure paths can be tested without pretending they are harmless;
- a whole-VM destruction boundary supplements in-guest cleanup;
- the reference provider is available on the existing Mac x86 host without weakening its ordinary Docker runner.

Cost:
- full E2E is slower and more operationally complex than ordinary CI;
- a dedicated native macOS orchestrator account/runner is required;
- QEMU/image/provider versions become security-relevant infrastructure;
- the target commit cannot use the workflow run `headSha` as its identity proof;
- guest image/network lifecycle requires explicit maintenance.

Deferred:
- live Cloudflare account E2E remains separately approved external-state work;
- ADR 0005's deferred smaller identity-switch boundary may be reconsidered independently if reducing long-lived host-agent capability authority becomes worthwhile.

## Security impact

This ADR changes the outer containment boundary for Level-3 E2E from a persistent host fixture to a disposable VM.

The persistent orchestrator MUST NOT:
- execute target checkout scripts/binaries;
- mount host home/workspace paths into the guest;
- pass repository write tokens, production credentials, SSH credentials, or host secrets into the guest;
- expose generic sudo/root APIs to the target commit;
- reuse a stale guest.

The guest MAY execute the target commit with root/capability authority because it is disposable and contains only test-scoped state.

In-guest cleanup remains part of the product test. Whole-guest destruction is an additional containment requirement, not a replacement for cleanup assertions.
