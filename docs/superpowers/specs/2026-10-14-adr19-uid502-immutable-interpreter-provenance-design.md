# ADR 0019 — Immutable UID502 Python provenance (design proposal)

**Date:** 2026-10-14 (America/Toronto)
**Status:** PROPOSED — operator joint review with [implementation plan](../plans/2026-10-14-adr19-uid502-interpreter-provenance-contract.md). Neither implementation nor host change authorized.
**Proposed next delivery:** Reviewable documentation PR following merged [PR #253](https://github.com/zhangyuz/ssh-over-mcp/pull/253).

## Why this matters now

SOM's [ADR 0019 protected staging](../../decisions/0019-protected-native-e2e-staging.md)
requires a real trusted-main, dedicated UID502 macOS x86_64 verifier. The merged
[UID502 inert contract](../../../ops/live-e2e/uid502_preflight_contract.py)
from PR #253 verifies **synthetic untrusted claims**, defaults to refusal and
accepts a **fictional** root-owned `/test-only/uid502-pinned/python3.13` witness
only for schema testing. It has **no host collector, workflow, authority token
or original-code nine-row physical acceptance**. The existing real no-network
Level-3 PASS on main proves the *legacy path*, not actual ADR0019 UID502/APFS.

Independent read-only inspection of Yuz.local identified actual candidate
`/usr/local/Cellar/python@3.13/3.13.16/Frameworks/Python.framework/Versions/3.13/bin/python3.13`:
`/usr` and `/usr/local` UID0:GID0 0755; **`/usr/local/Cellar` UID501:GID80
0775, group-writable**; interpreter UID501:GID80 0755. The original
[PR #250 broader fixture plan](../plans/2026-10-14-adr19-trusted-main-uid502-postmerge-fixture-verification.md)
describes this as a candidate requiring operator trust; **that is NOT an
approval**, and a one-owner/no-group-write provenance rule would necessarily
reject it. Treat this prior read-only observation as historical, not a fresh
filesystem attestation.

**Goal:** Establish a reviewable, testable *offline provenance decision
contract* defining which installation evidence may eventually be eligible
for a **separate trusted host collector**, without changing current
interpreter permissions or allowing existing operator-owned Homebrew as a
silent fallback.

## Decision and alternatives

1. **Recommended: operator-selected, separately provisioned immutable/read-only
   CPython distribution with reviewed offline supply-chain provenance.**
   An authorized human/platform operator separately identifies a source,
   exact package bytes/sha256, architecture, CPython version and all required
   runtime dependencies (framework, dynamic libraries, stdlib, extensions and
   their search/loading paths). Select and document an *actual* install
   directory only after platform feasibility and access-control review. Owner
   UID0/GID0, no group/world write and no UID502-effective write for the
   interpreter and every relevant directory/file/dependency edge. Require
   original no-follow FD/ACL/device/inode and signer/digest evidence at
   use-time from a later trusted-main adapter. **No installation or approval
   in this docs PR; no assumed root-owned location already exists.**
2. **Alternative requiring new security approval: review the existing UID501
   Homebrew supply chain on a per-component basis.** It includes
   group-writable `/usr/local/Cellar`; accepting it needs complete writer
   set, group/ACL and update-process trust, library-dependency closure,
   signer/digest, TOCTOU and operational drift evidence. It is **rejected as
   the default** and **not silently grandfathered**; keep blocking unless
   another ADR independently approves equivalent isolation.
3. **Defer physical verification.** Retain current test-only inert contract
   and UID502=UNVERIFIED indefinitely; safest without provisioning, but
   blocks ADR0019 real fixture acceptance and protected placement.

Do not confuse “root-owned” with “automatically trusted”: source-package
authenticity, platform compatibility, executable linkage and writable
dependencies must be proven separately. A copied binary without its framework
and loader graph is not a valid accepted installation.

## Two separate trust gates

### Gate A — host-independent provenance schema (proposed bounded code slice)

Add a **pure, immutable, synthetic** provenance contract; do not weaken or
replace current `uid502_preflight_contract.validate_interpreter`, its
fictional test-only policy, or the no-host-I/O invariant. Proposed module:
`ops/live-e2e/interpreter_provenance_contract.py`, tests:
`tests/ops/test_interpreter_provenance_contract.py`.

Caller-supplied records identify: exact source artifact digest (SHA-256
lowercase 64 hex), operator **approval reference as an uninterpreted label**,
CPython pinned version (initial target 3.13.16; architecture Darwin x86_64),
absolute installed binary and `sys.executable` binding, a *bounded* closed
sequence of all ancestor, interpreter, dynamic loader/framework, extension and
stdlib dependency witnesses with exact type/kind/path/dev/ino/uid/gid/mode/ACL,
effective UID502 writability, no-follow canonical identity, and dependency
edge relations. Unknown, unsupplied or dynamically resolvable loader edges,
unexpected `DYLD_*`/Python import environment influences, symlink replacement,
missing **claimed digest fields**, duplicate or aliased items, mutable source,
or inconsistent binary/dependency version all **REFUSE** at the schema level.
There is deliberately **no signed-origin verification or signer PASS field in
Gate A**: genuine source-signature verification is a missing *real attestation*
requirement for Gate B, so a schema-consistent result always remains
**UNATTESTED** even if digest-shaped fields are present. Conservative
quotas cap vertices, edges, path length and diagnostics.

**Important limit:** an untrusted tuple containing “signature valid”, a
SHA-256 string or `approval_ref` is **not an independently verified digest,
signature or operator approval**. Only the **later separately approved
trusted-main host collector** may authenticate provenance and bind the records
to actual installed objects at use-time. The pure module cannot itself
promote synthetic results to execution authorization.

Test-only positives may use a clearly *nonexistent* root-owned path like
`/test-only/uid502-immutable-python/...`; real Homebrew chain and all
missing/hostile evidence must be negative, including custom `__eq__`/
`__ne__` callbacks (no invoked arbitrary equality), absolute lexical path
traversal and type-spoofing in nested records. Output states only
`PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED` and `PROVENANCE_REFUSED`;
**neither** is allowed to be `CONTRACT_ELIGIBLE_FOR_HOST_PROBE`,
`UID502=PASS_CLEAN`, “approval” or a host-dispatch permit.

### Gate B — actual trusted host attestation (future, NOT this iteration)

Requires a *different* security-approved design, exact merged-main-only
workflow, operator authorization of installation/chain and any original
host changes. A trusted non-PR executable would obtain original FD-bound
no-follow/APFS/ACL/code-signing/digest and dependency-loader evidence, pin
the trusted source and library closure, revalidate before use, confirm
UID/eUID502/non-admin and provider+legacy emptiness, and fail closed on drift.
This is **not** implemented, scheduled, or enabled by Gate A. Real operator
provisioning of the immutable CPython and any ACL changes must be a separately
authorized operation, never automated from this PR or invoked from a PR runner.

The existing full nine-row original-code UID502 physical matrix, retained
forensic quarantine, independent disposition for eventual `PASS_CLEAN`,
staging lifetime Slice 2B/3, and ADR0020 PR-native dispatch are still
separately gated.

## Threat model and acceptance

- Threats: malicious/compromised same-user or group writer, package/update
  drift, LD/Python module injection, symlink/path race, alternate framework
  dylib loading, partial dependency inventory, wrong architecture/ABI and
  false “signed” fields, custom Python rich-comparison side effects.
- Non-goals: defending against compromised root/kernel, guaranteeing actual
  macOS binary relocation, selecting vendor/install location without evidence,
  installing packages or touching host paths, running any UID502 fixture,
  changing QEMU/provider lifecycle, changing existing CI/native workflows.
- Mandatory host-independent RED→GREEN: complete fully fictional root-owned
  graph may be **schema-consistent only**; observed Homebrew group-write chain
  and every incomplete/mutable/unknown edge must refuse; hostile inner objects
  must be rejected before comparison; zero filesystem, network or process
  calls; fixed bounded refusal reasons, no arbitrary error-path echo.
- Documentation shall keep **GATE A IMPLEMENTED / REAL PROVENANCE UNVERIFIED**
  distinct. No release test, workflow dispatch or real trust approval is
  claimed by a green hosted CI.
- After operator approves this written design and the separately reviewed
  implementation plan, implement Gate A in an independent code PR, request
  independent security review immediately on PR readiness, require
  exact-head hosted CI and project-wide review before merge. Gate B needs
  a separate human approval **even if Gate A merges cleanly**.

## Operator review decisions

The reviewer is asked to confirm: (1) Gate A *offline schema only* is the
next deliverable; (2) **do not accept existing group-writable Homebrew**;
(3) root-owned immutable supply chain is a **future selection/provisioning
goal, not current observed fact**; (4) Gate B and any actual Mac mutation
require separate future approval. This written proposal does not by itself
authorize creating executable feature code.
