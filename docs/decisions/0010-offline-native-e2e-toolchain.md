# ADR 0010: Authenticated offline native E2E toolchain

- Status: Proposed; written design approval required before implementation
- Date: 2026-10-06

## Context

Phase 7B1 requires native x86_64 syscall canaries. The approved Task 3 requires
an inventory and a separate prerequisite if the pinned guest lacks the tools.
Trusted-main run [37459216524](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37459216524)
evaluated diagnostic target `1e200e37e96f5f8e65aaa34b63fb205bd424ef95` using authority
`9e78f98dc55e1c28f0a57be2ac87324bb6a82f62`. Fixed `/usr/bin/systemctl` existed;
`/usr/bin/cc` was not executable (bounded code 102). Compilation was not reached.
Provider-state absence and checkout authentication/config cleanup passed. This
failed inventory is not product acceptance evidence.

ADR 0008 permits trusted-host acquisition of GitHub, Python and image inputs.
Adding native binary packages introduces another acquisition source and trust
root. An unexplained list of package hashes would establish neither provenance
nor complete compiler composition. Updating the image would require a broader
Phase 7A baseline revalidation; prebuilt canaries would introduce a separate
producer/artifact authority.

## Proposed decision

Retain ADR 0008's exact image, QEMU/HVF provider and no-network boundary. Add one
closed, derived Ubuntu archive input manifest for native E2E tools. This is an
OS-tool input contract, not another Python build lock. Existing
`requirements/build.in`, `requirements/build.lock` and
`requirements/e2e-bootstrap.lock` remain the Python authorities unchanged.

The trusted non-admin host may fetch only the fixed Ubuntu snapshot resources
named by the reviewed manifest. Trust is anchored in the Ubuntu Archive
Automatic Signing Key (2018), fingerprint
`F6ECB3762474EDA9D21B7022871920D1991BC93C`, independently identified by
[Ubuntu's cryptographic documentation](https://ubuntu.com/chisel/docs/v1.3.0/reference/security/).
An operator-provisioned verifier and pinned public key verify signed InRelease
bytes, then their Packages digest/size, then each package digest/size. This
follows [Ubuntu's archive verification chain](https://documentation.ubuntu.com/security/software-integrity/archive-verification/).
No TOFU keyserver, target-selected key, live apt resolver or unsigned fallback.

The initial candidate is snapshot `20261005T000000Z`, resolute main amd64 and
its updates/security pockets, with GCC `15.2.0-16ubuntu1`. The design freezes
historical metadata; it does not claim current patch status. Signature/hash
authentication is already researched; dependency closure, extraction layout
and pinned-guest compile/link/run are still unproved. The complete generated
manifest must receive review before workflow acquisition or enabling the
guest feasibility preflight uses it. Research acquisition does not grant that
authority. Later security-canary use additionally requires successful native
guest proof, the complete legacy matrix and cleanup.

Only already-trusted main prepares payload data, materializes its fixed
read-only guest tree and runs the fixed feasibility helper. No package script,
compiler, canary, target backend or target installer runs as root. Establish
the guest-only core guard first, then verify the fixed non-root identity,
groups, zero capabilities and NoNewPrivs before compiler execution. Record all
compiler components, base-image dependencies, source and output bindings.

New authority lands through small preparatory PRs certified by previously
trusted main. Its first activated proof happens only after the relevant code
is on main. Existing exact-head and merge-main five-fixture Level-3 gates and
cleanup remain mandatory. Tool feasibility earns no systemd/seccomp acceptance
credit; the full Phase 7B1 matrix remains required later.

## Consequences

The guest needs no NIC, apt service, host mount or credential. Native inputs
are reproducible and provenance is explicit. Costs include an operator-managed
GPG verifier, archived metadata, a bounded data extractor, a reviewed layout
manifest, and actual guest compatibility evidence. A closure/layout mismatch
blocks activation rather than triggering package repair or a new image.

Rejected: enabling guest networking; installing a compiler on the persistent
host; root package installation; executing target-selected compiler commands;
trusting a hash list without authenticated derivation; substituting prebuilt
unattested ELF helpers or skipping the syscall criteria.

## Security impact and scope

The design adds a narrow trusted-host download source and native input
authority. It adds no production behavior, approval mutation, MCP operation,
generic privileged RPC or provider recovery operation. URL redirects, signer
rotation, snapshot refresh, package selection and image changes require a
reviewed input update. Unknown package syntax/state, incomplete inventory,
unsafe extraction, writable runtime, surviving writers or missing live proof
fail closed. Provider markers are never auto-deleted.

The [written design](../superpowers/specs/2026-10-06-offline-native-e2e-toolchain-design.md)
defines mandatory contracts; its [draft plan](../superpowers/plans/2026-10-06-offline-native-e2e-toolchain.md)
defines independently gated slices. This ADR does not activate the proposed
authority or certify Phase 7B1.
