# ADR 0019: UID 502 trusted preflight contract — design

**Date:** 2026-10-14 (America/Toronto)
**Status:** Written design for operator review. **Not implementation or host-execution approval.**
**Proposed delivery:** The next independently reviewed feature PR (provisionally #252).
**Source:** [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md), [owned lifetime](../plans/2026-10-14-adr19-owned-protected-workspace-lifetime.md), [trusted-main UID 502 fixture verification plan](../plans/2026-10-14-adr19-trusted-main-uid502-postmerge-fixture-verification.md), [development methodology](../../development-methodology.md).

## Intent and current evidence

SOM policy, SSH, host agent, MCP and Ledger paths are implemented, and the reference deployment plus native Level-3 have been exercised. Trusted merged main `23f64a9d26fdaf6d4f6806397fffbb3636f9ddc4` passed [CI #38648215422](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38648215422): eight hosted shards, two aggregates, and an actual no-network Mac/QEMU Level-3 including the read-only final `Verify provider state is absent` step. That is **legacy-path** evidence, not ADR 0019 protected placement or actual UID 502/APFS Slice 2A fixture acceptance.

Slice 2A's `ops/live-e2e/staging_owned_lifetime.py` is merged but live `create_owned_workspace` and `OwnedWorkspace` operations deliberately refuse `unbound`; `protected_staging.inspect_namespace()` is inspection-only. The operator-owned, non-root CPython 3.13.16 binary was previously observed under `/usr/local/Cellar`; it is **a candidate, not an operator-approved executable trust anchor**. [ADR 0020](../../decisions/0020-trusted-pr-native-e2e-admission.md) permits informational shadow admission only, not pre-merge native dispatch.

The operator wants the smallest security-first iteration on the path to real UID 502 validation, without granting new persistent-host execution authority. The agreed PR scope is a **host-independent, fail-closed preflight *contract* and adversarial regression tests**. The goal is to specify exactly what later host evidence must prove, not to claim that evidence now.

## Alternatives and decision

1. **Recommended: inert contract library and hosted tests.** Implement pure predicates for trusted run identity, checkout/credential provenance, candidate interpreter inventory, fixed verification namespace, and marker/QEMU/legacy health *evidence completeness*. Evaluate synthetic evidence in hosted tests, label output only `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` or `CONTRACT_REFUSED`. Neither value is live admission or authority. No direct host I/O and no runner workflow.
2. **Rejected for this slice: immediate self-hosted `workflow_dispatch` and real fixture harness.** It creates a new persistent-host execution surface, needs an explicit interpreter trust decision, and introduces intentional forensic quarantine and separate disposition review. This belongs in a distinct independently approved slice.
3. **Rejected: documentation-only checks.** They cannot enforce the field/edge semantics or prove invalid inputs fail closed by RED→GREEN tests.

## Components and data flow

**One new inert module**, tentatively `ops/live-e2e/uid502_preflight_contract.py`, exposes immutable input schemas and small pure validation functions. An optional composition function collects deterministic violation *codes*, not secrets, and never returns an execution token, authenticated principal, status check, workflow dispatch, or release PASS.

```text
Synthetic/caller-supplied RunIdentity / CheckoutEvidence / InterpreterInventory
                     / NamespaceEvidence / ProviderInventory
                               |
                 Pure field/consistency validators
                               |
     CONTRACT_REFUSED (with reason codes)  or
     CONTRACT_ELIGIBLE_FOR_HOST_PROBE (not acceptance)
                               |
                 No side effect; no workflow caller
```

Inputs and validation contract:

- **Run and checkout:** expected repository exactly `zhangyuz/ssh-over-mcp`, event `workflow_dispatch` only, ref `refs/heads/main` only, lowercase 40-hex `GITHUB_SHA`, exact clean checkout HEAD equality, pinned `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, `ref=github.sha`, `persist-credentials=false`, `clean=true`, `fetch-depth=1`. Reject absent, unexpected, PR/fork/target SHA, unexpected dynamic inputs or an incomplete checkout record. Refuse credential-bearing environment or Git credential helper; never store or print token values. The pure library evaluates provided field values, **not** whether a GitHub runner truly produced them.
- **Runner identity candidate:** account `gha-e2e-orchestrator`, home `/Users/gha-e2e-orchestrator`, real and effective UID `502`, non-admin memberships, macOS x86_64. Missing group/UID evidence refuses. This is not an `id` invocation and must not run on the persistent host in this slice.
- **Interpreter inventory:** reference candidate observed CPython 3.13.16 exact resolved x86_64 path `/usr/local/Cellar/python@3.13/3.13.16/Frameworks/Python.framework/Versions/3.13/bin/python3.13`; require an explicit separately approved immutable path/version and signer/owner trust policy. Without such approval, reject as `INTERPRETER_TRUST_UNAPPROVED` even if synthetic UID/mode fields look correct. When a policy is supplied by unit tests, assert *every* path and symlink ancestor record, owner/group, ACL evidence, mode/write rights, identity, version and `sys.executable` binding; reject UID502, group/world-writable, ambiguous or missing ancestry. No `PATH` fallback, install, network, interpreter execution or mutation. Operator UID501/admin ownership is **not** silently upgraded to root trust.
- **Namespace and marker:** fixed verification-only sibling `/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-uid502-verification-v1`; never production `.../ssh-over-mcp-e2e/staging-v1`, `Library/Caches/ssh-over-mcp-e2e/active-run.json`, `/private/tmp`, or native `DARWIN_USER_TEMP_DIR`. A future trusted host collector must pin every FD edge with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, dev/inode/UID/GID/mode/ACL; evidence of a missing or foreign parent, symlink, replacement, stale fixture/quarantine or ambiguous discovered temp alias refuses. **No mkdir, repair, cleanup or real path discovery** here.
- **Provider and QEMU inventory:** marker absence must be established by no-follow evidence (dangling leaf/ancestor symlink = present/unsafe), verified from original pinned edges; QEMU process enumeration must be complete, error-free and bounded, and absence cannot be inferred from an empty **failed** result. Protected plus both legacy-parent health must be positively observed. Any missing/uncertain entry means refusal, not skip or retry. Do not reimplement the incident-frozen native scanner, marker authority or process enumeration in this slice.

**Trust separation:** client-supplied dictionaries and synthetic test fixtures are unauthenticated. They must **never** be used as permission for host execution. Later trusted-main host-only adapters will collect authenticated real snapshots from the actual UID 502 process and feed them into these predicates after their own independent review. The future host gate must still perform live no-follow revalidation at use-time; passing a synthetic contract never proves filesystem race immunity.

## API and failure semantics

- Immutable typed inputs, explicit required fields, no permissive default for unknown/optional evidence, no environment-driven root selection.
- Deterministic finite violation codes; bounded diagnostic length, no paths from attacker-chosen input echoed, no secrets in reports.
- `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` means only all **provided** attributes satisfy the declared schema/policy; it cannot be mapped to `UID502=PASS_CLEAN` or `BEHAVIOR_VERIFIED_EXPECTED_QUARANTINE`. No `PASS`, `ready_to_dispatch`, native credential, or callable side-effect adapter exported.
- Explicit trust-policy absence and collector/evidence errors fail closed. Checks do not spawn commands, read host filesystem/process tables, make GitHub API calls, create directories, clear the marker or write workflow statuses. No test should need root/sudo, UID switching, QEMU, active Mac provider or protected staging access.

## Adversarial test design and quality bar

**RED→GREEN hosted-only** tests should exercise actual validators on fully synthetic inputs, with at least these classes:

1. Valid schema with **explicit test-only** trust policy returns `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` but cannot authorize native execution; without approved interpreter policy, always refuses.
2. Wrong repo, fork, event, ref, target/HEAD drift, malformed 40-hex, dirty or credentials-bearing checkout, changed checkout SHA/flags, unknown inputs.
3. UID/EUID mismatch, wrong home/account, admin group, Darwin/arch mismatch.
4. PATH interpreter fallback, symlink or ancestor retarget, UID502/group/world-write, ACL uncertainty, wrong owner/signer/version, missing `sys.executable` provenance; no accidental live trust default.
5. Untrusted verification root, descendant/alias of legacy or protected namespace, missing/foreign/changed FD edge, wrong ACL, retained quarantine.
6. Leaf or parent dangling symlink, failed/truncated/incomplete QEMU enumeration, unknown process count, unverified protected or either legacy root; all fail closed.
7. Property-style one-field-at-a-time tamper table, error-code determinism, no path/secret disclosure, no interaction with real home/provider.
8. Existing native Level-3 frozen-authority byte checks and current workflow contract tests remain unchanged and pass; no changes to their pinned hashes in this slice.

Design documents, code and roadmap/evidence must distinguish **inert contract acceptance**, future real UID 502 nine-row *original-code* physical fixture evidence, expected quarantine, independently approved cleanup and eventual `PASS_CLEAN`. None is conflated.

## Deliverable boundary and later gates

**This spec authorizes only a design for the next code PR**, not implementing/dispatching a new persistent-host workflow. Proposed first implementation edits: one inert contract module, its hosted-only tests, and a concise roadmap/evidence correction. No `.github/workflows/*.yml`, `staging_owned_lifetime.py`, `protected_staging.py`, native orchestrator, frozen trust authority, recovery or production deployment change.

Following operator approval of **this written spec**, use Superpowers `writing-plans` to produce a small, reviewed execution plan; after *separate implementation-plan approval* develop in a fresh isolated worktree, preserve `progress.md`, follow RED→GREEN, make an independently reviewed PR without waiting for CI to finish, and merge only on exact-HEAD hosted CI and clean final review. Verify exact merged main CI/native Level-3 and clean branch/worktree afterward.

Subsequent separately approved slices must add the pinned trusted-main-only host collector and workflow, actual original 2A nine-case matrix with independent pre-dispose FD escrow, intentionally retained per-case failure inventories, then a distinct operator-approved identity-scoped manual disposition if `PASS_CLEAN` is required. Real UID 502 evidence and interpreter trust **remain UNVERIFIED/UNAPPROVED** until proven and explicitly authorized.
