# ADR 0019 — macOS Gate B trusted interpreter source decision (design proposal)

**Date:** 2026-10-15 (America/Toronto)
**Status:** PROPOSED — operator/security review required. No approved source, install location, collector, trusted-runner change or UID502 execution.
**Baseline:** merged Gate A PR #255, macOS-first roadmap PR #257 (main 427bf0c6ecaf5057ae4951170b0033d06eb246f3).
**Scope:** choose an independently authenticatable macOS x86_64 CPython 3.13.16 distribution and measurable acceptance policy that can eventually unblock the original-code UID502/APFS fixture. The output of this documentation slice is a source-candidate decision and closed-form review gates, **not actual Gate B passing**.

## Intent and currently verified facts

The desired outcome is to get the existing trusted macOS orchestration host securely ready to exercise the original, already-merged ADR0019 UID502/APFS nine-case matrix and then proceed with protected staging activation and macOS release acceptance. The SOM product/managed target remains distinct from its Mac orchestration host. Do not claim the product has shipped on Mac merely because the native E2E runner works.

Previously recorded **read-only historical** Yuz.local metadata found:
- /usr and /usr/local: UID0:GID0 0755 in that observation.
- /usr/local/Cellar: UID501:GID80 0775, group writable.
- Homebrew CPython 3.13.16 interpreter within /usr/local/Cellar: UID501:GID80 0755.

The Homebrew source is **BLOCKED** by the no-group-write rule. This is an earlier observation, **not a current FD-bound stat or provenance measurement**. Do not silently chmod, chown, trust UID501, change PATH or adopt that installation.

Merged Gate A in ops/live-e2e/interpreter_provenance_contract.py verifies only caller-authored synthetic package/manifest/role/ABI graph consistency; it is not a source signature verification, a real package digest, a trusted interpreter, Gate B, a host-probe eligibility certificate or UID502 acceptance. Its toy <=64-node graph need not represent a full actual Python distribution. The inert UID502 preflight still refuses an unapproved real interpreter.

**Source of external candidate information (public documentation; not host evidence):**
- Python.org CPython 3.13.16 release, 2026-09-30:
  https://www.python.org/downloads/release/python-31316/
- Python.org macOS packaging and trust guidance:
  https://docs.python.org/3.13/using/mac.html
- Distribution index, including package and detached signature-related files:
  https://www.python.org/ftp/python/3.13.16/

## Candidate selection and alternatives

| Candidate | Pros | Security and delivery cost | Decision |
|---|---|---|---|
| **A: python.org CPython 3.13.16 macOS signed installer** (macOS 11 package; universal2) | Same declared CPython patch level as frozen Gate A; published official package SHA-256 and detached signing artifacts; documented signed/notarized installer and Framework layout | Must independently verify upstream identity and package signature, inspect package scripts/BOM before consent, identify resulting files and writable parents, inspect Mach-O slices and dyld/Python import dependencies. Default installer may add shell PATH symlinks and perform actions; **installation cannot be automated by this proposal**. | **Preferred source candidate for operator evaluation; NOT approved for installation or execution** |
| B: internally reproducible pinned CPython 3.13.16 from authenticated source tarball | Can choose private layout and build flags | Must attest toolchain/compiler/build inputs, dependency linkage, deterministic binary outputs, original signed source, rollout/versioning and update policy; much larger trust surface | Fallback only after separate review if candidate A cannot meet policy |
| C: reuse existing UID501 Homebrew install | Fastest superficially | Known group-writable Cellar ancestor, unsafe update/writer set; conflicts with current trust rule | **Rejected / BLOCKED** |
| D: stop and retain UNVERIFIED | No new host attack surface | Physical matrix remains blocked | Safe until the independent operator gate authorizes a real candidate |

**Published release checksum reference ONLY** (not a digest observed on this host):

- Artifact identity: python-3.13.16-macos11.pkg
- Published SHA-256: 30666509020b4da0dd8bc2e773255f34d76b7bb80b66960a928d5f6daa0192d7
- Release channel: Python.org Python 3.13.16 (not an arbitrary URL redirect or unpinned latest)
- Expected guest/host distinction: macOS x86_64 *interpreter on the Mac orchestrator*, not Python inside the Ubuntu guest.

The checksums and signing material displayed on a webpage are **input to independent verification**; the webpage or a matching self-reported string is not proof. Pin a trusted release/signing identity out-of-band in a later reviewed approval record. A valid checksum alone says nothing about unsigned nested libraries or unsafe installed-directory permissions. Never treat this section as a command to fetch/install packages.

## Gate B threat model and separate proofs

### B0 — signed-source decision, still OFF HOST

Only after a new explicit operator authorization may an isolated, credential-free process retrieve a specific artifact and offline verification materials through a pinned download process. Obtain an independent copy of the reviewed expected SHA-256; hash **the actual downloaded package bytes**, compare the exact lower-case digest and release identity, authenticate a trusted upstream signing/notarization chain under separately approved signer/team identities, inspect the package scripts/BOM and reject unreviewed postinstall behavior. Capture signer cert metadata, verification method, trust roots, expected identity, tool versions, artifact hash and operator decision in an immutable reviewable record. **DO NOT infer signers or Apple team ID from the word Python on the file.**

Fail closed for signature absent/invalid/expired/revoked/ambiguous, hash mismatch, unexpected installer scripts/symlinks, unsupported OS/arch, package version drift or inability to verify revocation under the approved offline policy. Distinguish authenticated upstream source, acceptable package operations and operator approval; each is a separate condition. No network install commands in a self-hosted trusted run.

### B1 — independently approved provisioning design (NO INSTALL NOW)

Do not trust default /usr/local/bin symlinks, PATH, previous Homebrew, current working directory or an Apple developer-tools Python. Select the **exact final installed canonical executable path and entire Framework/stdlib dependency roots** only after inspecting the chosen installer on a disposable, appropriately controlled non-production environment, not by guessing the installation layout. The default python.org Framework path under /Library/Frameworks is a **candidate to evaluate, not a proven safe installed root**.

An operator will need to approve an isolated, fixed location and provisioning method, no updates by UID502 or unapproved group/other principals, no writable ancestor/dependency, no undesired system-wide side effects, and a deterministic rollback/upgrade procedure. Never repair a rejected existing interpreter in place. Package scripts may write outside the target: require a complete effects list before any real Mac action. For security acceptance, uid/gid/mode/ACL and effective writability must be measured on each original FD-held ancestor, binary, library, stdlib, importable extension and writable search-path parent; UID0:GID0/no group/world-write is the conservative default unless explicitly revised under a new security decision. An update invalidates previous measurements and requires fresh release approval.

### B2 — actual trust and loader closure at point of use (NEW HOST COLLECTOR, separately approved)

A **bootstrap-trusted, non-PR, trusted-main-only** collector must first establish its **own** identity and inputs without executing the interpreter being investigated or any untrusted Python code. Its frozen binary/native/OS-level dependencies, permissions and source commit require independent prior attestation. A Python script run by an unapproved Python is circular evidence and must never elevate itself.

At use time, an independently reviewed no-follow, original-FD-bound collector must measure:
- Pinned literal executable path, parent chain, APFS filesystem identity, dev/inode, full mode, UID/GID, effective ACL and symlink/hardlink/replacement status; evidence across original held descriptors before and after measurement.
- **Actual package digest and signed upstream source**, then **actual installed file bytes** and a package/installed-manifest membership mapping. A self-consistent Gate A manifest is insufficient. Separate trusted compiler/runtime dependencies and system Apple-supplied sealed libraries from privately installed libraries; do not silently skip third-party runtime libraries.
- Real x86_64 Mach-O slices, code-signing metadata for nested executables/bundles where applicable, LC_LOAD_DYLIB and @rpath/@loader_path resolution, Python home/sys.path and stdlib plus extension imports, ABI cpython-313-darwin, environment injection and dynamically reachable files. A complete real inventory will likely exceed Gate A's synthetic 64-node budget; do NOT truncate to 64 or silently treat unresolved/system paths as PASS.
- Environment/loader trust: no caller-controlled DYLD_* or PYTHON* influence, user-site imports, mutable site-packages, cwd relative import, writable configuration/startup paths, unexpected executable shims or unpinned symlinks. A claim of “environment clean” cannot replace actual inspection.

Evaluate admission only for that measured immutable snapshot, revalidate all relevant original FD identities and trusted bytes as closely as possible **before launching UID502**. State any unavoidable process-launch time-of-check/use assumptions; an attestation report alone is not a general reusable authorization token. Fail closed on measurement error, inconsistent symlink/FD identity, missing dependency, unbounded/unknown closure, ACL uncertainty or drift. Do not touch the provider marker or native E2E workflows until their separately reviewed execution design.

### B3 — original UID502 physical nine-case verification, separately gated

The already drafted UID502 fixture plan at
docs/superpowers/plans/2026-10-14-adr19-trusted-main-uid502-postmerge-fixture-verification.md
still needs its own revised trust interpretation, independent review and explicit operator approval of the **persistent-host workflow**. It uses the exact original Slice 2A code, isolated fixed APFS verification parent, UID/eUID502 and actual ACL/FD checks, not a lookalike test algorithm, and serializes against the native provider/QEMU. All nine original test rows must be observed, including adversarial denies. Expected retained negative evidence may mean BEHAVIOR_VERIFIED_EXPECTED_QUARANTINE, **not PASS_CLEAN**; any manual evidence disposition is a separate approval. Do not use hosted CI or the legacy Level-3 result as substitution for UID502 original physical acceptance.

## Testable release gate and states

A later Gate B implementation must define exactly:
- SOURCE_UNVERIFIED: no independently verified package source/signing/hash and operator approval;
- INSTALLED_SOURCE_UNVERIFIED: source approved but actual installed location, contents or permission/loader closure not independently measured;
- ATTESTATION_REFUSED: any security mismatch, unknown, drift, dependency or failed witness;
- HOST_PROVENANCE_VERIFIED: narrow point-of-use, evidence-bound Gate B success only, **not** UID502 APFS PASS_CLEAN or unrestricted execution.

These names are **proposed future reporting vocabulary**, not existing executable APIs or tokens. Existing Gate A statuses remain unchanged. A narrow future host attestation cannot authorize broader native workflow permissions on its own.

| Release / acceptance gate | Evidence required | Verified status at this PR |
|---|---|---|
| A. Synthetic provenance schema | Gate A existing tests / immutable data checks | IMPLEMENTED; source UNATTESTED |
| B0. Package source and signed release | Verified artifact bytes + upstream signer + approved package effects | **UNVERIFIED** |
| B1. Approved immutable interpreter provisioning | Real reviewed install root, owners/ACL/updates, safe rollback | **UNVERIFIED** |
| B2. At-use native FD/Mach-O/loader attestation | Real measured byte/FD/ACL/ABI/dyld closure and fail-closed evidence | **UNVERIFIED** |
| B3. Original UID502/APFS nine-case physical matrix | All nine original-code trace rows with expected quarantine classification | **UNVERIFIED** |
| B4. Protected staging 2B/3 and macOS release signoff | Separate provider/staging readiness and explicit release authorization | **UNVERIFIED** |
| Legacy native Level-3 QEMU | Trusted-main legacy Linux guest no-network E2E | Has historical green evidence; **not B3** |

No Gate B component, installation, UID502 run, APFS fixture, runner/workflow, production staging or CI dispatch is authorized by this design-only PR. **The first unblocker is an operator-reviewed B0 candidate and non-executing verification/provisioning design, not a silent package install.**

## Sequencing and review decision

1. **This PR:** review source candidates, explicit approval criteria, bootstrap trust, evidence graph, release blockers, testable denies. No new implementation plan or code until operator approves this written architecture.
2. **After separate approval:** draft a small B0 offline artifact-source verification TDD plan and request operator/security review. No trusted-host workflow, install or production action in B0 code without independent permission.
3. Independently plan, approve and implement B1 provisioning, B2 at-use collector and B3 UID502 physical verification, each on its own trusted-main/security gate and with retained evidence. Never collapse multiple approvals into one synthetic positive.
4. After B3 and protected staging 2B/3, define and verify the macOS operational/release acceptance and get explicit operator signoff. Linux Slice C remains blocked until actual macOS release plus accepted B2 portable shared contract from Issue #256 and a new Linux authorization.

**Joint operator decision requested:** accept or revise the preference for Python.org CPython 3.13.16 signed macOS installer as the **source to investigate**, never as automatically trusted installed Python; approve only this proposed Gate B trust architecture and evidence standards. Real source retrieval, installation, host collection and UID502 execution remain individually gated.
