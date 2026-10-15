# Issue 256 — OS-neutral provenance safety core and Darwin/Linux profiles

**Status:** PROPOSED for operator and independent security review. No behavioral implementation approved.
**Date:** 2026-10-15 (America/Toronto)
**Roadmap:** [Issue #256](https://github.com/zhangyuz/ssh-over-mcp/issues/256)
**Baseline:** [Merged Gate A PR #255](https://github.com/zhangyuz/ssh-over-mcp/pull/255), main f3a39b3594951defae4b31e6fdcf252b2503a507.

## Intent and current evidence

SOM's managed target, developer/hosted CI, native E2E orchestrator and QEMU guest are independent platform roles. Current Ubuntu CI and Ubuntu VM guests do not imply an Ubuntu native orchestrator; the dedicated macOS x86_64 orchestrator does not imply the product requires Darwin. The merged Gate A module (ops/live-e2e/interpreter_provenance_contract.py) only checks **fabricated Darwin x86_64 / CPython 3.13.16 / Mach-O evidence**. Its positive status, PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED, is not a trust credential or physical UID502/APFS verification.

User-approved direction: preserve current behavior while planning a reusable pure consistency core and explicit Darwin and Linux profiles. This PR proposes the boundaries. There will be no host I/O, new CI workflow, Linux implementation, Gate B attestation, physical UID502 acceptance or change to the existing PR255 code in this documentation-only slice.

## Options and design decision

1. **Recommended: pure shared invariants plus static profile-specific validators.** Share exact-type/budget/canonical-path/manifest/graph safety while requiring a deliberately selected platform profile for ABI and loader semantics. This supports independent future Linux proof checks but introduces a behavior-preservation challenge for the Darwin API.
2. **Single large validator with platform-specific branches.** Smaller immediate diff, but cross-platform role and parser confusion becomes a new attack surface. Not preferred.
3. **Entirely separate, duplicated Darwin/Linux validators.** Strong isolation but duplicate hash/graph/type code will diverge. Fallback if factoring shared behavior proves risky.

## Orthogonal identities (descriptive only)

- execution_role: exactly developer_ci, native_orchestrator, e2e_guest, or managed_target. It does not grant access, authorization or verified provenance.
- os_family: exactly Darwin or Linux; unknown values, aliases, case variants, missing values and mismatched profiles REFUSE.
- machine_arch: initial x86_64. arm64/aarch64 require independently reviewed architecture and extension ABI rules before registration.
- profile_id: an exact allowlisted tuple of OS/architecture/runtime ABI, never a caller-specified importer path, dynamic function name or runtime autodetection.

| Profile ID | Format and claimed ABI | Current disposition |
|---|---|---|
| darwin-x86_64-cpython313-v1 | Mach-O, dyld/framework, cpython-313-darwin, macOS x86_64 | Implemented in current standalone Gate A synthetic contract; behavior frozen |
| linux-x86_64-cpython313-v1 | ELF, ld.so/SONAME, libc flavor, cpython-313 Linux extension ABI | NOT IMPLEMENTED; must REFUSE under proposed Slice B router |

Explicitly separate CI host, orchestration host, guest and managed target in evidence and docs. A Linux/Ubuntu CI runner validating a fictional Darwin object is not itself a Darwin trust source. A selector indicating native_orchestrator is metadata, never a permission to dispatch a real job.

## Common invariant boundary for future Slice B

Shared pure checks only: frozen exact record/primitive type validation before comparisons/serialization, recursive tuple and string budgets, lower-case SHA256 claimed manifest identity, one-to-one canonical declared file/path/kind/digest members, graph edge closure, non-echoing fixed denials, duplicate claimed (dev,ino) and path aliases, forbidden NUL and traversal, restricted privilege bits, bounded fields and no host I/O. Preserve PR255 limits: <=64 nodes/manifest members, <=128 edges, <=64 unique module paths, <=1024 ASCII path bytes and <=64 ASCII approval-label bytes. Caller-controlled coherent hashes remain unauthenticated regardless of platform.

**Darwin profile:** Existing assess_provenance(evidence) API, all observed statuses and all current negative tests must retain their old behavior, including Mach-O binary/framework/dylib relationships, cpython-313-darwin extension tags, UID0/GID0 policy, claimed no-writability, special-bit refusals, NUL refusals, DAG, and finite budgets. Do not change the UID502 inert preflight, protected staging or native E2E workflow.

**Linux profile (not in Slice B):** A later independently reviewed Slice C must specify ELF e_machine, ELF ABI, dynamic interpreter, DT_NEEDED / SONAME and loader search/rpath/runpath, explicit glibc-versus-musl policy, extension SOABI, permission/ACL/mount/namespace semantics and dependency completeness. A Linux-looking record, wrong ELF machine, cross-profile substitution, unknown libc or incomplete dynamic graph must refuse. No real Linux provenance acceptance is claimed here.

**Proposed routing interface for later review:** frozen ProfileSelector(os_family, machine_arch, python_abi, role, profile_id) plus assess_profile_claim(selector, evidence) returning a fixed, non-authorizing ProfileResult. Only a statically registered, reviewed Darwin profile may be routed in Slice B. Linux must fail closed until separately approved Slice C implementation. Do not infer platform from sys.platform, environment, CI labels, guest image names, arbitrary module names or user data.

## Threats and safety boundaries

Threats: cross-profile ELF-as-Mach-O confusion, forged selector types/custom equality methods, ABI and architecture mismatches, nested over-budget records, incomplete dependency closure, relative/path traversal, NUL, symlink/hardlink claims, setuid/setgid/sticky privileges, ambiguous host/guest role claims, fake signed/origin fields. These must refuse with bounded diagnostic constants, without comparisons against malicious objects or revealing secrets.

**Gate A remains UNATTESTED.** Gate B authentic package bytes/signing, real dyld or ld.so imports, immutable provisioning, original no-follow FD/ACL/APFS identity, actual UID502 nine-case physical fixtures, marker/provider cleanup and native orchestration require separate design, operator/security authorization, trusted-main CI and physical evidence. Historical UID501/GID80 group-writable Homebrew Python remains BLOCKED.

## Acceptance and operator decision

- Documentation-only PR; no behavior, CI workflow, operator privilege, cleanup or runner change.
- Proposed future implementation must preserve existing Darwin Gate A API and tests, always refuse unregistered Linux, unknown/profile-spoofed selectors and role authority claims, and keep synthetic positive explicitly unattested.
- Future Ubuntu **native orchestrator** is a separate Linux runner/QEMU/provider/identity/isolation feasibility and security project, never an implication of Ubuntu CI or guest tests.
- Approve architecture and a future pure Slice B TDD scope only after joint operator and independent security review. Code implementation itself requires another explicit operator decision.
