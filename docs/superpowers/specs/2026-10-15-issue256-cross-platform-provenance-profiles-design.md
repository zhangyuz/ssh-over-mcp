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

## Roadmap milestones and the OS-neutral shared invariant boundary

**Decision after review #6191154142: use the smaller B1/B2 decomposition.**
Slice A (this documentation PR) specifies only the roadmap and contracts.
**Slice B1 (next potential code PR) delivers only a strict, static,
Darwin-only profile selector/router** that delegates to the existing
Gate A code; B1 does NOT create or expose a portable OS-neutral common
invariant contract. **Slice B2 (separate, later review/approval) MUST extract
a typed, pure, reusable OS-neutral input/manifest/graph invariant API** and
verify parity of the Darwin behavior against existing and router-mediated
fixtures. B2 is a mandatory dependency of independently reviewed Slice C
(Linux synthetic ELF profile); if no safe extraction is feasible,
revisit architecture before C rather than duplicating unnoticed logic.
**Operator sequencing decision (2026-10-15): macOS-first release.**
Linux **Slice C must NOT start development before the macOS full-feature
implementation has passed its approved release gates and has actually
launched**. The milestone is **not yet achieved**; do not infer it from
a green hosted Ubuntu CI, legacy Level-3, Gate A synthetic evidence or
a merged design PR. Release evidence and operator acknowledgement
must establish the approved macOS feature/release scope, applicable
trusted-host/security review, operational/deployment readiness, and
the real UID502/APFS nine-case acceptance **where required by the
approved macOS scope**. Gate B source/install attestation and native
host testing each retain their own operator approval; this paragraph
does not authorize running them or presume they are already passed.
Starting C requires **both** (1) completed and reviewed B2 parity/
shared-core delivery and (2) documented macOS full-feature launch
confirmed by the operator, plus a **new explicit Slice C approval**.
B1/B2 planning may be retained but must not divert the macOS release
critical path; code work needs separate authorization. Linux native
orchestrator Slice D also remains deferred to a later distinct approval.

Slice D (Linux native orchestrator) and real Gate B are separate,
independently gated projects. No B1/B2/C/D implementation is authorized
by the current docs-only PR.

**Future B2 common invariant boundary — NOT delivered by B1**

Shared pure checks only: frozen exact record/primitive type validation before comparisons/serialization, recursive tuple and string budgets, lower-case SHA256 claimed manifest identity, one-to-one canonical declared file/path/kind/digest members, graph edge closure, non-echoing fixed denials, duplicate claimed (dev,ino) and path aliases, forbidden NUL and traversal, restricted privilege bits, bounded fields and no host I/O. Preserve PR255 limits: <=64 nodes/manifest members, <=128 edges, <=64 unique module paths, <=1024 ASCII path bytes and <=64 ASCII approval-label bytes. Caller-controlled coherent hashes remain unauthenticated regardless of platform.

**Darwin profile:** Existing assess_provenance(evidence) API, all observed statuses and all current negative tests must retain their old behavior, including Mach-O binary/framework/dylib relationships, cpython-313-darwin extension tags, UID0/GID0 policy, claimed no-writability, special-bit refusals, NUL refusals, DAG, and finite budgets. Do not change the UID502 inert preflight, protected staging or native E2E workflow.

**Linux profile (not in B1 or B2; C deferred until macOS full-feature launch):** After BOTH approved B2 and an operator-confirmed full-feature macOS release, a separately reviewed and approved Slice C may specify ELF e_machine, ELF ABI, dynamic interpreter, DT_NEEDED / SONAME and loader search/rpath/runpath, explicit glibc-versus-musl policy, extension SOABI, permission/ACL/mount/namespace semantics and dependency completeness. A Linux-looking record, wrong ELF machine, cross-profile substitution, unknown libc or incomplete dynamic graph must refuse. No real Linux provenance acceptance is claimed here.

**B1-only routing interface:** frozen
ProfileSelector(os_family, machine_arch, python_abi, role, profile_id);
assess_profile_claim(selector, evidence) returns a frozen ProfileResult.
Static adapter is the sibling ops/live-e2e/interpreter_provenance_contract.py
resolved from the fixed router source location (never an untrusted
caller path, profile string or user-selected import). The existing
assess_provenance(evidence) remains unchanged, callable separately and
the sole Darwin schema checker. Ordinary fixed import of trusted source
code is not a host-provenance or physical-file attestation.

Selector fields MUST be exact built-in strings and nonempty ASCII;
check lengths before comparisons, regex, hashing or examining evidence:

| Field | Maximum ASCII bytes | Exact B1 allowlisted values |
|---|---:|---|
| os_family | 6 | Darwin |
| machine_arch | 6 | x86_64 |
| python_abi | 18 | cpython-313-darwin |
| role | 19 | developer_ci, native_orchestrator, e2e_guest, managed_target |
| profile_id | 31 | darwin-x86_64-cpython313-v1 |

These are hard upper bounds, not a prefix-match policy. Allowed values
are compared case-sensitively, with no aliases, omissions, subclasses,
runtime OS inference or fallback. Invalid selector returns exactly
ProfileResult(status="PROVENANCE_REFUSED",
violations=("EVIDENCE_INVALID",)) WITHOUT invoking the Darwin checker.

For a valid selector, the router returns a new frozen ProfileResult with
status AND violations exactly equal to direct legacy
assess_provenance(evidence), including every bounded fixed refusal
reason. Never truncate, normalize or replace valid-delegation results;
passing a role is only contextual metadata, never authorization.
The original API is preserved, and Linux remains unregistered in B1.

## Threats and safety boundaries

Threats: declared cross-profile contradictions, forged selector
types/custom equality methods, ABI and architecture inconsistencies,
nested over-budget records, incomplete dependency closure, traversal,
NUL, symlink/hardlink claims, setuid/setgid/sticky modes, host/guest
role confusion and fake source signatures. Declared inconsistencies
must refuse without malicious comparisons or attacker text echoes.
Exactly test these B1 synthetic pairs:

- Linux os_family / Linux profile_id + internally coherent Darwin Gate A
  evidence: REFUSE at selector; B1 has no Linux registration.
- Valid Darwin selector + evidence ArtifactClaim.platform="Linux":
  REFUSE using the unchanged Darwin claim validator.
- Valid Darwin selector + evidence arch="arm64" or extension ABI wrong:
  REFUSE using the unchanged Darwin validator.
- Darwin profile_id + os_family="Linux" (or mismatched arch/ABI):
  REFUSE *before delegation*, no automatic profile fallback.
- All selector and package/manifest/ABI claims coherently fabricated
  as Darwin: may return **PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED**.
  The actual unobserved bytes might be ELF; B1 cannot detect or
  authenticate that discrepancy, and MUST NOT claim to.

Only separately approved Gate B can inspect actual ELF-versus-Mach-O,
package bytes/signatures and real loader/host identity. Never claim a
synthetic router can detect an undisclosed real format.

**Gate A remains UNATTESTED.** Gate B authentic package bytes/signing, real dyld or ld.so imports, immutable provisioning, original no-follow FD/ACL/APFS identity, actual UID502 nine-case physical fixtures, marker/provider cleanup and native orchestration require separate design, operator/security authorization, trusted-main CI and physical evidence. Historical UID501/GID80 group-writable Homebrew Python remains BLOCKED.

## Acceptance and operator decision

- Documentation-only PR; no behavior, CI workflow, operator privilege, cleanup or runner change.
- B1 only provides an explicit Darwin selector; B2 is the required
  OS-neutral shared core extraction, not delivered/approved by B1.
  Slice C is **deferred until macOS full-feature release and launch**
  confirmed by the operator, AND independent B2 parity/review and
  separate explicit Slice C approval. No pre-launch Linux C work.
- A future B1 router must preserve every Darwin Gate A direct status
  AND violations through the new router, reject declared inconsistencies,
  unregistered Linux and role authority claims, and preserve coherent
  fabricated Darwin evidence as UNATTESTED, never REAL_FORMAT_VERIFIED.
- Future Ubuntu **native orchestrator** is a separate Linux runner/QEMU/provider/identity/isolation feasibility and security project, never an implication of Ubuntu CI or guest tests.
- Jointly review B1/B2/C milestones and B1 contract, then require an independent operator approval for each later code PR; no docs merge authorizes B1, B2, Slice C/D or Gate B.
