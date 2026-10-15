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

**Review decision 1 (Important): choose option A, synthetic package-to-manifest-to-node binding.**
A source artifact claim includes a 64-lowercase-hex package SHA-256, a declared
manifest SHA-256, fictional installation root, packaging layout, and pinned
CPython 3.13.16 / Darwin x86_64. A finite typed PackageManifest repeats the
same package SHA-256 and lists exactly one ManifestEntry per installed node.
An entry binds node ID, canonical relative POSIX path, role/kind, and per-file
SHA-256 (NOT_APPLICABLE is allowed for directories only). The validator
recomputes the SHA-256 of a deterministic canonical UTF-8 manifest entry
serialization, compares the declared manifest SHA-256 and insists that the
entry and node ID/path/role/digest correspond one-to-one. All installed graph
nodes must be represented by exactly one manifest entry; extra or unknown
manifest members and a changed package digest with an unchanged manifest
association REFUSE. A caller can fabricate both SHA strings and every field
consistently. No claimed hash is measured from real source bytes: this is
only **internal coherence of unauthenticated synthetic claims**.

**Review decision 2 (Important): choose option A, synthetic per-node Mach-O and
Python extension ABI compatibility, with explicit roles and graph semantics.**
This is only consistency among untrusted claimed values, never proof of
real macOS executable compatibility.

- Directory roles are directory, framework_bundle, stdlib_dir and must
  carry a full POSIX directory mode. File roles are binary, dylib,
  framework_dylib, extension, stdlib_file (uncompiled .py only) and must
  carry full POSIX regular-file mode. A framework bundle is a directory,
  NOT an executable library; its framework_dylib node is a regular file.
- Mach-O regular-file roles binary, dylib, framework_dylib, extension
  must declare per-node architecture x86_64; all others use the literal
  NOT_APPLICABLE. Python extension role alone must declare the exact
  synthetic ABI tag cpython-313-darwin and Python major/minor (3,13);
  other nodes must declare NOT_APPLICABLE/null. Thus an arm64-only dylib
  or a CPython 3.12 extension REFUSES even when the global artifact
  claims Darwin x86_64 / CPython 3.13.16.
- Artifact layout is exactly framework or standalone. Require exactly
  one executable binary, at least one stdlib_dir and one stdlib_file.
  Framework layout requires one framework_bundle and at least one
  framework_dylib; every framework_dylib MUST be a strict descendant
  of that unique framework_bundle by canonical path components,
  with a complete chain of direct-parent contains edges from bundle
  to dylib. Root reachability via unrelated macho_load edges does
  NOT suffice. A sibling/free-floating framework dylib must REFUSE.
  Standalone layout prohibits both framework roles. This first
  contract covers only filesystem stdlib sources and a fully self-owned
  graph. Zipped stdlib, external system dylibs and more complex real
  packaging remain UNREPRESENTABLE and REFUSED until a separately
  reviewed compatibility revision. Do not invent a framework requirement
  for standalone CPython.
- DependencyEdge loader kind allowlist is exactly: contains
  (directory, framework_bundle or stdlib_dir parent to direct lexical
  child), macho_load (binary, dylib, framework_dylib or extension
  parent to dylib or framework_dylib child), python_import (binary or
  stdlib_file parent to stdlib_file or extension child). Reject other
  role combinations. Every unique edge points to declared nodes;
  all nodes are connected and reachable from the declared install
  root with a valid containment/declared-dependency structure. Reject
  duplicates, ambiguous paths, cycles in this conservative synthetic
  graph, and graph size beyond 64 nodes/128 edges.
- The actual dyld search path, @rpath/@loader_path expansion,
  imported-module resolution, binary Mach-O slices, true package
  contents and runtime dependency closure are **not observed** by Gate A.
  Actual installations that exceed this toy schema's representation
  or quota are UNVERIFIED rather than allowed through or labelled PASS.
  These assumptions must be revisited based on real candidate evidence
  before Gate B, with a separate security review.

**Whole-record untrusted-input budget (new review #6185643321 Important):**
Before any nested traversal, rich comparison, hashing, regex, sorting,
or canonical JSON serialization, check exact built-in dataclass, tuple,
string and numeric types and constant-time collection lengths. Limits:
nodes <=64, manifest entries <=64, dependency edges <=128 and
runtime.module_search_paths <=64; version tuples must be arity 3 or 2.
Module search paths must be nonempty, all distinct, and count no greater
than the number of unique declared stdlib_dir nodes. Every member must
be a canonical absolute ASCII path <=1024 bytes and match exactly one
such node path. Even within quota, duplicate module paths REFUSE.

ArtifactClaim.approval_ref is 1..64 ASCII bytes from the safe alphabet
[A-Za-z0-9_.:-] (still no actual approval authority); node_id and edge
IDs are 1..64 ASCII bytes from [A-Za-z0-9_-]. All absolute and
manifest-relative path strings (root entry alone may be empty) must
fit <=1024 ASCII bytes. Digest fields are exactly 64 lowercase hex
bytes; finite-token fields (kinds, loader kinds, layout, platform,
architecture, ACL state, ABI and NOT_APPLICABLE) must match explicit
allowlists. Other unbounded strings or sequences are not admitted.
Check individual strings and nested tuple item types and lengths
before any expensive evaluation, set, sort, serialization, logging
or attacker-controlled repr. Oversized/invalid input returns fixed
bounded refusal codes without copying caller content. This is
synthetic-only input budgeting, not package attestation.

Require exact primitive/nested dataclass type validation before rich
comparison, sorting and serialization: never call arbitrary supplied
__eq__/__ne__ methods. Enforce UID0:GID0 non-group/world-write, no
UID502-effective-write, explicit ACL and original identity claims for
every member. Missing membership, drift, symlink/path alias, incomplete
graph or DYLD/Python environment influence REFUSE.

There is deliberately no signed-origin verification or signer PASS field
in Gate A. Any internally consistent self-reported manifest, source digest,
ABI and dependency graph remains **PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED**.
Real package signature, package-byte SHA, installed-file hash, code signing,
actual loader graph, original FD/APFS/ACL and approval are independent
future Gate B requirements.
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
- Mandatory host-independent RED-to-GREEN: a fictional fully owned
  manifest/graph is schema-consistent only when package and manifest
  digests, one-to-one relative paths, node hashes and roles bind
  coherently. Mutating package SHA without matching manifest claim,
  manifest entry/path/digest without matching node, adding a foreign
  entry, an arm64 dylib, or a Python 3.12 extension REFUSES.
  A framework dylib outside its bundle, 65 search-path entries,
  duplicate stdlib search paths even under quota, or an
  approval_ref longer than 64 ASCII bytes must also REFUSE before
  unbounded operations. Tests reject the observed Homebrew group-
  writable ancestor and custom equality callbacks without executing
  them; no host I/O or source authentication is claimed.
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
