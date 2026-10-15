# macOS-native orchestration release blocker inventory — 2026-10-15

**Status:** Evidence inventory for review, not a release attestation. Source-of-truth baseline main 427bf0c6ecaf5057ae4951170b0033d06eb246f3.

This page distinguishes the macOS x86_64 **trusted test orchestrator** from SOM's existing control-plane reference deployment and managed Linux hosts. A green Ubuntu guest, a green hosted CI run or a completed synthetic Gate A schema is not a native macOS full-function launch. The Mac release scope and acceptance signoff still require an operator-defined milestone.

| Order | Dependency | Current evidence | Exit criteria / owner gate |
|---|---|---|---|
| 0 | Product/host launch scope | README describes Phase 5, Phase 6, Phase 7A complete; Phase 7B remains open | Operator defines target macOS orchestrator readiness versus product release and exact required functions |
| 1 | Historic native provider incident | Previously approved forensic disposition and old-path Level-3 verification succeeded | Preserve prior evidence; new native acceptance must not conflate old path with UID502 |
| 2 | Dormant protected staging 2A | Implemented with host-independent contract checks | Original-code UID502/APFS matrix must be observed on trusted Mac before readiness |
| 3 | CPython provenance Gate A | PR #255 merged, synthetic-only | Schema consistent does not authenticate installed binary/package |
| **4 — current P0** | **Gate B trusted interpreter candidate B0 / provisioning B1** | **Real Homebrew group-writable source BLOCKED**; preferred python.org signed package candidate for evaluation only | Independent package-byte digest+signer validation, approved package scripts/layout and future owned, non-UID502-writable provisioned root. No current host proof |
| 5 | Gate B at-use native collector B2 | **NOT IMPLEMENTED / UNVERIFIED** | Trusted bootstrap, exact original-FD and APFS/ACL/code-signing/real dyld/stdlib/ABI closure, immutable snapshot and failure tests |
| 6 | Actual UID502 original nine-case APFS B3 | **UNVERIFIED** | Approved trusted-main native fixture; real UID502, all original call traces and refusal rows, evidence quarantine classification, independent signoff |
| 7 | Protected staging 2B/3 and provider integration | **UNVERIFIED / gated** | Reviewed activation and original path/lifetime/cleanup/provider/marker acceptance, no drift or unauthorized deletion |
| 8 | macOS full-function readiness / launch | **NOT CLAIMED** | Approved release-scope matrix, native evidence, deployment/rollback/operations confirmation and operator signoff |
| Later | Issue #256 B1/B2 portable-profile router/core and Linux C | Linux C intentionally deferred until Mac launch and approved shared B2 | No prelaunch Linux C implementation or inference from Ubuntu hosted tests |

Gate B identifiers above describe trust/evidence work within ADR0019; **Issue #256's unrelated B1/B2 names describe portable-profile router/core work**. Keep the prefixes explicit in future communications to avoid confusing the two programs.

The current detailed B3 fixture plan remains
docs/superpowers/plans/2026-10-14-adr19-trusted-main-uid502-postmerge-fixture-verification.md.
Any older suggestion to trust the already-owned Homebrew interpreter is superseded by the documented UID501/GID80 group-writable /usr/local/Cellar finding. No chown/chmod/PATH/adoption, live installer, new runner workflow or UID502 test is approved by this inventory. Any negative-case expected forensic quarantine needs a **separate approved disposition** before claiming UID502=PASS_CLEAN.

## Current immediate decision

Review the linked Gate B source-selection design and decide whether the signed Python.org CPython 3.13.16 artifact is the appropriate candidate for **independent verification**, not for installation. The next separately approved deliverable would be an inert B0 verification plan/code slice with no persistent-host execution. The real macOS release remains **UNVERIFIED**.
