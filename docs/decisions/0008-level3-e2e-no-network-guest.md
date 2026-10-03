# ADR 0008: Level-3 E2E guest has no virtual network device

- Status: Accepted
- Date: 2026-10-02

## Context

ADR 0006 moved capability-bearing Level-3 E2E code into a disposable Linux virtual machine because ADR 0005's trusted host-agent capabilities `CAP_SETUID` and `CAP_SETGID` are root-equivalent inside the guest user namespace.

The first reference provider used Lima 2.2.0 with the macOS Virtualization.framework (`vz`) driver, no host mounts, no product port forwards, and no secrets copied into the guest.

Further review found that this was not a complete outer containment boundary. Lima 2.2.0's `vz` driver unconditionally attaches its user-mode network when no explicit usernet is configured. That network exposes a slirp/gVisor gateway reachable from the guest. A malicious or compromised target commit which regains guest root could therefore still originate network traffic toward the persistent host or other reachable networks during the E2E run.

Whole-guest destruction removes guest disk/process persistence after the run, but it cannot undo network actions performed while the guest is alive.

Three approaches were considered:

1. retain Lima and rely on guest firewall rules;
2. retain Lima and add host-side packet filtering around its usernet;
3. replace the Level-3 provider with a QEMU/HVF guest that has no virtual NIC at all.

Guest firewall rules are insufficient because the target commit may become guest root and remove them. Host packet filtering would add a platform-specific privileged host control surface and still leave more moving parts than necessary.

## Decision

Level-3 E2E uses a fresh QEMU x86_64 virtual machine accelerated by Apple's Hypervisor.framework (HVF) and started with **no virtual network device**.

The trusted host provider is:

- Intel macOS x86_64;
- Hypervisor.framework available;
- QEMU 11.1.2;
- Ubuntu 26.04 x86_64 server cloud image dated 2026-07-20;
- image digest `sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477`.

The QEMU command line must include:

- `-accel hvf`;
- x86_64 guest;
- `-nic none`;
- no host filesystem sharing;
- no virtiofs/9p;
- no host sockets passed to the guest;
- no USB redirection;
- no display;
- no QEMU monitor;
- serial output to a host-owned result log;
- a writable disposable overlay backed by the pinned read-only base image;
- read-only cloud-init seed and payload media.

The guest receives all required inputs before boot through read-only media:

1. exact target Git bundle created from a host-side temporary bare repository;
2. trusted-main `requirements/runtime.lock`;
3. a hash-verified Python 3.14 linux/amd64 wheelhouse generated from that trusted-main lock;
4. trusted bootstrap metadata/scripts needed to clone the bundle, create the isolated Python environment, and invoke the target guest gate;
5. the exact expected target commit.

The guest does not need apt, PyPI, GitHub, DNS, DHCP, or any other network service.

The pinned Ubuntu 26.04 image already provides the required baseline components for Phase 7A:
- Python 3.14;
- pip;
- `venv`;
- OpenSSH server;
- sudo;
- git.

The persistent host orchestrator:
- remains non-admin/non-root;
- executes only trusted-main orchestration code;
- never checks out or executes the target commit as a host worktree;
- may access GitHub/PyPI/image endpoints only from the trusted host side;
- never copies its GitHub token, production credentials, SSH agent socket, host secrets, or arbitrary host files into the guest;
- creates temporary bundle/wheelhouse/ISO/overlay artifacts with owner-only permissions;
- starts QEMU only with the reviewed fixed argument plan;
- waits for QEMU to terminate;
- accepts success only from an exact, commit-bound serial result record plus successful process exit;
- removes overlay, seed ISO, payload ISO, bare repository, bundle, wheelhouse, serial log, and other temporary state in a `finally` path.

The target checkout may obtain guest root-equivalent authority. The security boundary is the VM process plus the absence of any virtual network or host filesystem/device channel.

## Consequences

Positive:
- a compromised target commit cannot use guest root to reach the persistent host or LAN over a VM NIC because none exists;
- no guest-root-removable firewall is part of the trust boundary;
- the guest still exercises real Linux sshd, sudo, capabilities, cgroup-v2, Unix sockets, and workload identity;
- the host token and dependency/image download authority stay entirely outside the guest;
- runtime dependency installation is reproducible and offline inside the guest;
- whole-VM destruction remains a final containment boundary.

Cost:
- the provider moves from Lima lifecycle convenience to explicit QEMU/cloud-init/media orchestration;
- QEMU becomes operator-managed trusted infrastructure;
- the host must construct a cloud-init seed, payload ISO, wheelhouse, and disposable disk overlay;
- results are collected through serial output rather than interactive SSH;
- provider maintenance includes QEMU and cloud-image compatibility.

Rejected:
- guest firewall isolation, because guest root could remove it;
- Lima VZ usernet, because the provider attaches a reachable user-mode network;
- host-side packet filtering around Lima, because it requires an additional privileged host policy surface and is more complex than removing the NIC.

## Security impact

The persistent orchestrator MUST fail closed if:
- QEMU/HVF is unavailable or not the approved version/provider;
- the pinned base image digest does not match;
- the target commit is not exact 40-hex or bundle verification differs;
- trusted-main runtime lock or downloaded wheels fail hash verification;
- generated QEMU arguments contain any NIC/network backend, host filesystem sharing, socket/chardev not used for the fixed serial log, or mutable host path exposed to the guest;
- a stale QEMU process or fixed provider state from a previous run exists;
- the serial result is absent, malformed, references another commit, or reports failure;
- any temporary host artifact cannot be removed.

The guest MUST fail closed if:
- the payload/seed identity is wrong;
- checked-out HEAD differs from the expected commit;
- offline dependency installation cannot satisfy the trusted lock;
- the target gate fails;
- in-guest cleanup verification fails.

This ADR refines ADR 0006. ADR 0006's disposable-VM principle remains in force; its Lima/VZ provider details are superseded by this no-network QEMU/HVF provider.
