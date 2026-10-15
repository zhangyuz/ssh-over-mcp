# ADR0019 Interpreter Provenance Gate A — synthetic consistency evidence

**Authority:** Host-independent, unauthenticated synthetic evidence only.
PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED confirms that caller-created
package/manifest/digest/ABI/graph *claims* agree, not that package bytes,
signatures, binaries or host files were authenticated. The alternative
result is PROVENANCE_REFUSED. Neither is host admission or UID502 PASS_CLEAN.

## Reviewed source design

- [PR #254 design and plan](https://github.com/zhangyuz/ssh-over-mcp/pull/254):
  exact clean independent
  [review #6185974187](https://github.com/zhangyuz/ssh-over-mcp/pull/254#issuecomment-6185974187)
  at 1813f32130fc004e278dd2dff17ea6283c82568e, with no
  Critical / Important / Minor outstanding.
  Exact-head [CI #38691482224](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38691482224)
  SUCCESS; design merged main ade5b33a7397c1f23844c29a2f61c88e5e6533f7.
- Existing trusted-main no-network native Level-3 validates only the
  LEGACY path; it does not execute original UID502/APFS nine-case fixtures.

## Contract evidence and its limits

- New module ops/live-e2e/interpreter_provenance_contract.py imports
  only standard-library in-memory hashing/JSON/regex/dataclasses; no
  host filesystem reads, environment queries, network, process, provider
  or GitHub calls. No execute, dispatch, approval or trust-token API.
- Frozen inputs represent synthetic package and deterministic JSON
  manifest SHA, exact manifest/node path-kind-digest membership, full
  POSIX kind/mode/UID/GID/ACL/Mach-O/CPython extension ABI, directed
  contains/macho_load/python_import relations and bounded runtime claims.
- Fictional /test-only/uid502-immutable-python fixtures can be internally
  consistent despite a fully forged package, manifest and executable
  checksum. No real package-byte SHA, signer, Mach-O inspection, dyld
  search, Python imports, original FD/APFS/ACL, immutable install or
  operator trust is verified. The existing Homebrew interpreter remains
  BLOCKED by earlier UID502 preflight policy.
- The original [PR #255 security review #6186387240](https://github.com/zhangyuz/ssh-over-mcp/pull/255#issuecomment-6186387240)
  found **0 Critical / 1 Important / 1 Minor** on head 2a9320b.
  Remediation of Important: all *distinct synthetic nodes* must have unique
  (dev, ino) pairs, not just unique IDs and canonical paths. The old
  positive fixture used path-length-derived inode values and accidentally
  aliased its binary and extension. The fixed fictional fixture assigns
  pairwise-unique stable inode numbers. An otherwise fully coherent
  package/manifest with a duplicated claimed object identity REFUSES.
  Intentional hardlinks are not represented by this version; a future
  reviewed schema would be required. **No real stat, APFS or FD identity
  was obtained.**
- The same review's Minor: synthetic device and inode numbers must be
  positive exact Python ints at most 2^64-1, and a synthetic full POSIX
  st_mode must be an exact int in 0..0o177777 with the expected
  regular-file/directory type bits and non-writable policy. Malformed
  out-of-range integers are refused before bitwise graph validation.
  These are finite *claimed-evidence widths*, not actual Darwin
  provenance measurements.
- Negative cases cover hostile rich comparisons, wrong nested types,
  exceeded quotas, duplicate search paths, malformed manifest association,
  framework dylib outside its bundle, wrong architecture or Python ABI,
  mutable/UID501 group-writable nodes, uncertain ACL and synthetic
  DYLD/Python environment influence.
- The limited schema represents a small self-owned directed acyclic
  graph with filesystem stdlib; actual macOS dependencies and any
  unrepresentable package/graph remain UNVERIFIED, not implicitly passed.

## Evidence gates before code PR merge

1. Record RED then GREEN synthetic contract tests in ignored isolated
   worktree SDD ledger.
2. Run focused and relevant protected staging/provider/shadow contract
   regressions, Ruff, compileall, git diff --check and four-path allowlist.
3. Request fresh independent project-wide code/security/docs review and
   verify exact-final-head hosted CI before merge.
4. Postmerge trusted-main native Level-3 remains old-path only and
   cannot stand in for true UID502/APFS fixture acceptance.

This evidence note is not a claim that future independent code review,
exact-head hosted CI or postmerge Level-3 has already passed.

**Release state:** Gate A synthetic-only; real UID502/APFS original 9 cases
UNVERIFIED. Gate B source provenance, immutable interpreter provisioning,
actual dylib/stdlib loader closure, UID502 host execution, protected
placement, forensic disposition and automatic PR-native dispatch require
independent operator/security approvals. No workflow or runner change
is authorized by this PR.
