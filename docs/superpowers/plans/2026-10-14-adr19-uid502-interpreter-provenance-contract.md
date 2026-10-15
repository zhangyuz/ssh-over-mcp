# ADR 0019 UID502 Interpreter Provenance — Gate A Implementation Plan (PROPOSED)

> **For agentic workers:** Upon operator approval of both design and plan,
> use Superpowers `executing-plans` or `subagent-driven-development`,
> with strict per-task RED→GREEN and independent whole-project final review.

**Status:** Joint operator review draft, **NOT approved for code, new
persistent-host workflow, interpreter installation, or native UID502 runs**.

**Goal:** Deliver a host-independent, pure, bounded provenance **schema**
for a not-yet-selected immutable CPython candidate. It never authenticates
real installation state, supply-chain approvals or executable authority.

**Architecture:** One inert typed module with immutable input records,
compositional schema validators and fixed non-authorizing result states.
Dedicated hosted-only adversarial tests; documentation truth sync.
**Spec:** [UID502 immutable interpreter provenance design](../specs/2026-10-14-adr19-uid502-immutable-interpreter-provenance-design.md).
**Baseline:** [Merged PR #253](https://github.com/zhangyuz/ssh-over-mcp/pull/253),
main `4d8449a8eec95eb37f33bd8c193cdaf7cf19be61`.

## Files and hard limits

- Create `ops/live-e2e/interpreter_provenance_contract.py`
  (**pure stdlib data + validation only**, no API calling the provider).
- Create `tests/ops/test_interpreter_provenance_contract.py`
  (import actual module by path, synthetic fixtures).
- Update only `docs/development-plan.md` and add a concise new
  `docs/evidence/2026-10-14-adr19-interpreter-provenance-contract.md`
  for concrete Gate A results. All other tracked paths are immutable for
  this implementation iteration, especially `.github/workflows/**`,
  `uid502_preflight_contract.py`, `staging_owned_lifetime.py`,
  `protected_staging.py`, original native 2A and recovery logic.
- No root, sudo, package install, chmod/chown, actual host I/O, spawning
  programs, network, GitHub API dispatch, Mac runner/test fixture, dependency
  lookup, dynamic import/exec, `os.stat`, `codesign` or symlink traversal.
  No operator/user-selected paths used for filesystem operations.
- All fields/collaborators *untrusted*: require exact dataclass identity,
  exact `type(...) is str/int/bool/tuple`, recursively bounded primitive
  tuples before equality/regex/sort/set. Never invoke custom comparisons or
  stringify attacker objects. Require absolute canonical lexical POSIX
  paths (reject `.`, `..`, duplicate `/`, NUL, relative/alias claims).
- Refusal is the default for missing manifest linkage, digest evidence,
  out-of-policy owner/mode/ACL/loader path, wrong runtime/version/arch,
  UID502-effective write, unexpected/DYLD/PYTHONPATH modifiers, incomplete
  transitive dependency graph or unbounded/unknown evidence.
- An `approval_ref` or caller `signature_verified=True` field is only
  text supplied by an attacker. Do not expose actual approval, signature
  verification, valid executable path, host execution, `PASS_CLEAN`, new
  trust grant or simulated operator signature.
- Proof states **only** `PROVENANCE_REFUSED` and
  `PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED`. Returning the latter from a
  fictional fixture does not change real UID502 contract's
  `INTERPRETER_TRUST_UNAPPROVED` outcome. Actual homebrew remains blocked.

## Independent PR #254 review disposition: API choices before implementation

The [independent review #6185298182](https://github.com/zhangyuz/ssh-over-mcp/pull/254#issuecomment-6185298182)
found 0 Critical, 2 Important, 1 Minor at old head 2ac9658.

1. **Important 1, option A chosen:** tie the package SHA to the
   manifest claim and a canonical manifest SHA-256, then map every
   relative-path+role+digest manifest member one-to-one onto a node.
   All inputs are synthetic and self-reported; Gate A can check
   contradictory claims, NOT identify or authenticate real package
   bytes. For the required negative example, changing only the
   package digest must cause a manifest-binding refusal.
2. **Important 2, option A chosen:** declare each node's POSIX type,
   Mach-O architecture and Python extension ABI/major-minor where
   applicable. Explicitly represent framework bundle directories
   versus framework dylib files, optional framework packaging,
   filesystem stdlib files, exact loader edge labels and finite
   role-compatible graph closure. Arm64 dylibs and cpython-312
   extensions refuse under x86_64/3.13.16 artifact claims.
3. **Minor:** directly replace the stale interpreter-source sentence
   in the older UID502 physical fixture plan; keep a single
   conspicuous BLOCKED rule and no chmod/adoption fallback.
4. **Quota limitation:** 64 node/128 edge limits are provisional and
   may reject the actual macOS dependency closure. A too-large real
   candidate remains UNVERIFIED; modifying quotas/role rules needs
   another review, not a silent workaround.

## Locked proof inputs for code implementation (subject to operator review)

Define frozen-slot dataclasses with only tuple-based immutable collections.
No caller-supplied field, even when labelled signed, carries authority.

- ArtifactClaim(package_sha256: str, manifest_sha256: str,
  install_root: str, layout: str, python_version: tuple[int,int,int],
  platform: str, arch: str, approval_ref: str, complete: bool).
  Exactly CPython (3,13,16), Darwin, x86_64. Layout is framework or
  standalone. Install root is absolute canonical lexical POSIX and
  fictional test fixture lives under /test-only; no real location is
  implicitly selected or approved.
- ManifestEntry(node_id: str, relative_path: str, kind: str,
  digest_sha256: str). For the one installation-root directory
  entry ONLY, relative_path is the empty string. Other relative
  paths are slash-separated canonical components, with neither
  dot nor dot-dot nor empty components or NUL; no leading slash.
  File digests are exact lowercase SHA256 strings; directory
  digest MUST be NOT_APPLICABLE.
- PackageManifest(package_sha256: str, entries: tuple[ManifestEntry,...]).
  The artifact and manifest package digests must equal. Entries
  ordered strictly by relative_path (unique paths/IDs); maximum
  64 entries and every graph node must have exactly one member.
- ProvenanceNode(node_id: str, path: str, kind: str, dev: int, ino: int,
  uid: int, gid: int, mode: int, acl_state: str, digest_sha256: str,
  writable_by_uid502: bool, macho_arch: str, python_abi: str,
  python_major_minor: tuple[int,int] | None). A node's path
  must equal install_root for its root member, otherwise
  install_root + "/" + entry.relative_path. All fields are exact
  primitive types before comparison. All nodes claim UID0:GID0,
  full POSIX type/mode, no group/world or UID502 write, verified
  safe ACL, positive dev/inode and no symlink role. Each digest
  and kind equals the corresponding manifest entry.
- Kinds / full-mode mapping: directory, framework_bundle and
  stdlib_dir => POSIX directory (0o040000); binary, dylib,
  framework_dylib, extension and stdlib_file => POSIX regular
  (0o100000). Require stdlib_file names ending .py and
  stdlib_dir descendants (no zip-stdlib format in this version).
  Exactly one binary, >=1 stdlib_dir, >=1 stdlib_file. For
  layout=framework, exactly one framework_bundle and >=1
  framework_dylib are required. For standalone, both are
  forbidden. A Python distribution needing other roles must
  REFUSE as unrepresentable, not be automatically generalized.
- Mach-O/ABI claims: binary, dylib, framework_dylib, extension
  require macho_arch exactly x86_64. All directory/stdlib_file
  roles use NOT_APPLICABLE. Extension alone requires python_abi
  exactly cpython-313-darwin and python_major_minor=(3,13);
  every non-extension requires python_abi=NOT_APPLICABLE and
  python_major_minor=None. A claimed 3.12 extension or arm64-only
  dependency refuses even if global fields claim 3.13/x86_64.
  These are *synthetic* slice/ABI claims, NOT Mach-O inspection.
- DependencyEdge(parent_id: str, child_id: str, loader_kind: str).
  Exactly contains (directory/framework_bundle/stdlib_dir parent
  to **direct lexical child**), macho_load (binary/dylib/
  framework_dylib/extension parent to dylib/framework_dylib),
  python_import (binary/stdlib_file parent to stdlib_file/
  extension). Forbid duplicates, self edges, unknown IDs,
  invalid type combinations and cycles; require reachability of
  every node from installation root via valid edges. A valid
  graph must include parent/child contains edges matching each
  nested filesystem entry; this is claimed structure, not proof
  of real dyld/@rpath resolution or actual imported modules.
- RuntimeClaim(binary_node_id: str, sys_executable: str,
  module_search_paths: tuple[str,...], dyld_environment_clean: bool,
  python_environment_clean: bool, graph_complete: bool).
  The exact binary's claimed path must equal sys_executable;
  search paths must be canonical literal paths present in
  stdlib_dir nodes. All completeness/clean flags must be the
  literal bool True (never bool-int aliases).
- ProvenanceEvidence(artifact: ArtifactClaim,
  manifest: PackageManifest, runtime: RuntimeClaim,
  nodes: tuple[ProvenanceNode,...], edges: tuple[DependencyEdge,...]).
- ProvenanceResult(status: str, violations: tuple[str,...]).
- assess_provenance(evidence: ProvenanceEvidence) -> ProvenanceResult.

**Canonical manifest SHA (exact v1 algorithm):** sort entries by
relative_path strictly (the input tuple itself must already be in
that order). Encode canonical JSON using Python stdlib json.dumps
with ensure_ascii=True, sort_keys=True, separators=(",", ":"),
on the object with exactly these keys:
  schema_version: 1
  package_sha256: Manifest.package_sha256
  entries: array of maps of node_id, relative_path, kind,
           digest_sha256 in manifest tuple order
Serialize as UTF-8 bytes and compute hashlib.sha256(bytes).hexdigest().
Require equality to ArtifactClaim.manifest_sha256. No optional
fields or ambiguous encodings; reject overlong/non-ASCII paths
and IDs, duplicate/ambiguous entries before serialization.
This computes **only the self-reported manifest's** digest; changing
artifact.package_sha256 alone, manifest.package_sha256 alone,
manifest entry path/kind/digest alone, or associated node alone
must REFUSE. Changing all fields coherently **cannot** establish
real package identity, actual source authenticity or signature.

**Refusal and bounds:** Maximum 64 nodes/manifest entries,
128 dependency edges, 1024 characters per path, 32 fixed
distinct codes. Only PROVENANCE_REFUSED and
PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED are outputs.
Do not log user paths/tokens or expose execution/approval APIs;
never permit exception messages or attacker-object repr in output.

**Explicit representation limit:** Claimed loader edges may omit
real dyld, @rpath, OS platform libraries, import paths and
cyclic dependency behavior, which this contract cannot discover.
Real platform dependencies outside the self-owned root, zip
stdlib, code signing and actual file digest verification remain
**Gate B / further reviewed model extension**, never quietly PASS.
An actual runtime exceeding the graph limits is UNVERIFIED.

## Task 1 — Exact evidence types and hostile-value resistance

**Files:** new Gate A module and test only.

- [ ] **RED:** valid fully fictional root-owned standalone layout
  with install-root directory, binary, stdlib directory/stdlib_file,
  compatible dylib and cpython-313 extension, an ordered manifest,
  canonical manifest hash and complete claimed edges returns only
  PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED. Under Gate A, no
  assertion refers to actual source bytes or host execution.
- [ ] **RED hostile inner fields:** insert false-equality / raising
  __eq__/__ne__ trap objects into every node/manifest/edge/digest,
  relative path, ABI, package claim and nested tuple. Assert
  refusal with fixed code and ZERO trap-method invocations.
  Invalid outer records/None/wrong types refuse.
- [ ] Verify genuine RED against missing new production module,
  not an unrelated missing Python dependency; note exact output.
- [ ] **GREEN:** frozen-slot types and recursive exact primitive
  type checks before comparisons, set or sorting. Run focused
  pytest and Ruff; commit typed evidence records with progress.md.

## Task 2 — Synthetic manifest association and ABI-aware graph

**Files:** same new module and test.

- [ ] **RED package binding:** keep valid graph fixed, mutate just
  ArtifactClaim.package_sha256 to a different syntactically valid
  digest, then separately change just manifest.package_sha256,
  manifest entry/node ID, relative path, node digest, entry kind,
  declared manifest SHA, reorder/duplicate manifest membership.
  Each must REFUSE; no proof of real package bytes is claimed.
- [ ] **RED role and compatibility:** require valid standalone
  WITHOUT framework nodes; valid framework WITH bundle-directory
  plus framework_dylib regular-file node. Reject framework absent,
  bundle mislabelled regular, stdlib dir/file mode mismatch,
  zip/unrepresentable stdlib, arm64 Mach-O dependency,
  extension ABI cpython-312-darwin and major/minor=(3,12),
  wrong binary path or missing claimed dependency.
- [ ] **RED graph trust:** absent target/duplicate/cycle/wrong
  loader_kind or illegal role direction, non-direct contains,
  path traversal or alias, missing owned ancestor, detached
  node, group-writable UID501 Homebrew ancestor, unknown ACL,
  uid502 writable, DYLD/Python search injection, false
  completeness, too many nodes/edges/path chars refuse.
- [ ] **GREEN:** canonical JSON manifest digest binding per
  approved specification; finite graph validation with
  role-specific file/mode/ABI checks and hard quotas;
  deterministic bounded fixed errors; no filesystem reading,
  digesting actual package bytes, symbol resolution or host
  environment access. Test and commit separately with
  RED-to-GREEN results in ignored progress.md.

## Task 3 — Non-authority regression, evidence and PR

**Files:** same module/test + permitted docs.

- [ ] **RED:** AST or controlled-import tests prove zero `os`, network,
  subprocess, `codesign`, environment or runner interactions and no
  `run`/`dispatch`/approval/host-token exports. Negative checks
  reject forged `approval_ref` and “signature valid” claims as an
  authorization path. Positive state stays explicitly **unattested**.
- [ ] **GREEN:** close non-authority API and add roadmap/evidence:
  Gate A synthetic *claimed manifest + ABI + topology consistency
  only*; no checked bytes, signer, dyld/@rpath/import trace,
  actual package or immutable interpreter. Gate B remains
  UNVERIFIED / UNAPPROVED; nine-row physical UID502 matrix not
  run, no protected placement and no forensic deletion.
- [ ] Verify entire applicable pytest suite on hosted-safe runner (do not
  count Darwin-host-only Linux `prctl` tests as macOS-green), Ruff,
  compileall, `git diff --check`, relative links and exact changed-path
  allowlist. Compare forbidden workflow/orchestrator/marker sources
  against main to ensure no change.
- [ ] Commit source, tests, roadmap and evidence, push and create a
  **separate implementation PR**. Request independent code/security/docs
  review immediately while exact-head hosted CI runs. Fix findings
  RED→GREEN, obtain new exact SHA CI and independent clean final review
  before merge. After merge check trusted-main native Level-3 and clean
  owned worktree/branches without deleting retained host evidence.

## Required separate future approval

Do **not** install a Python runtime, select an unverified root path,
modify host permissions, run a UID502 test, create a new workflow or
dispatch from this plan. Gate B (actual operator-chosen package, offline
supply-chain and signature verification, macOS/dylib feasibility, immutable
install, trusted-main attestation, original-code nine-row test) **requires a
new design, implementation plan, operator security approval and postmerge
trusted-main evidence**. Merely approving Gate A does not approve Gate B.
