# ADR 0016: Fixed recovery-root special-node metadata observation

- Status: proposed read-only supplementary evidence; no disposition or cleanup approved
- Date: 2026-10-13 (America/Toronto)

## Confirmed incident

Trust-bound UID-502 [private-tmp run 38392113385](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38392113385) refused the original strict two-pass inventory at `inventory-a-2-probe-symlink`. The second exact catalog root is `ssh-over-mcp-e2e-recover.cc8Del` (device 16777220, inode 186815322, UID 502, mode 0700), beneath root-owned sticky `/private/tmp`. Earlier recovery inspect-only reported a direct `clean` directory in that root. The private contents and the symlink's precise relative entry are still unknown. None of this proves historical provenance.

ADR 0011's strict incident staging eligibility and ADR 0015's strict refusal for symlinks remain unchanged. A symlink cannot be turned into an accepted staging artifact. A separate **non-authorizing metadata observer** is necessary to distinguish stable historical objects from incomplete or changing state.

## Separate, narrow authority

`live-local-e2e-recovery-root-observe.yml` is dispatch-only on trusted `main`, with pinned `github.sha` checkout, pinned actions, read-only token, non-admin macOS x86 UID-502 runner, fixed timeout, and serialized `live-local-e2e` concurrency. No caller-controlled paths or arguments, sudo, signals, guest execution, marker unlink, removal or mode repair.

`observe_recovery_root_metadata.py` pins literal root-owned `/private/tmp` ancestry via ADR 0015's no-follow policy, reuses the fixed marker/cache/owner checks and process snapshot predicates, then pins **only** the catalog's second exact root by literal basename and device/inode/UID/mode. It walks its children using descriptor-relative `stat(..., follow_symlinks=False)`; only verified UID-502 non-world-writable subdirectories are opened with `O_DIRECTORY|O_NOFOLLOW`. Regular files, symlinks, FIFOs, sockets and device leaves are **never opened**, executed or followed. Neither link target text nor any regular file bytes are read. Unsupported leaf types are recorded **as metadata only**, not accepted or traversed.

Two complete bounded observations must match. Every discovered child reserves its entry budget **before** metadata acquisition, including during a large directory scan (a verified regression prevents unbounded child observations). With per-pass depth 12, 4096 nodes, 4096-byte relative paths, 2 MiB artifact, 60 seconds observed per pass and a 420-second outer deadline. Each directory checks names and child metadata and rechecks its descriptor, while the final marker/cache/root/namespace/process predicates are repeated before evidence escapes. Descriptor cleanup uncertainty, identity change, invalid names, foreign/unsafe directories, traversal errors or instability refuse. Only a successful private, seven-day metadata JSON artifact is uploaded; failures exit 70 with a fixed phase and no successful/partial artifact. Raw paths, metadata values, link targets and exception content are never printed to job logs.

Every successful artifact explicitly records `recovery_eligible=false`; the two bounded snapshots do **not** prove exclusive quiescence, authenticity, provenance, or safety to delete. GitHub artifact delivery is not a signed disposition receipt. The previously approved getconf and /private/tmp strict inspectors, recovery marker-only workflow, and Native Level-3 execution remain unchanged.

## Required follow-through

Independently review the complete private artifact and verify all exact identities and old PID/QEMU quiescence under UID 502. Investigate the root-2 symlink identity and every remaining object without following links. Then review first and third catalog roots independently. Propose an exact per-identity disposition with explicit operator approval **before any mutation**. Only after roots are safely resolved and marker-only recovery's guards pass, rerun exact-main no-network Level-3 and validate complete host/guest cleanup. Until then, Native Level-3 is FAIL-CLOSED.

## 2026-10-13 refusal-only phase refinement

The first trusted-main UID-502 manual metadata run
[38394389366](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38394389366)
refused at generic `inventory-a`, exit 70, without producing a partial
artifact. Exact catalog and marker checks had completed; the private contents
remain unknown. To distinguish a safe collector failure from a malformed or
changing entry **without relaxing any check**, the observer adds fixed
phase-only labels on an exception from its already-bounded first or second
metadata pass. Labels describe only an operation class (directory policy,
enumeration, child-stat, entry-budget, directory identity/edge drift, etc.),
not a name, pathname, owner, object identity, file payload, exception string
or raw metadata. They are observations, not evidence of provenance or cleanup
eligibility; any failure still exits 70 with no successful artifact.

## 2026-10-13 fixed entry-path refusal taxonomy

Trusted-main UID-502 [38396725028](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38396725028)
refused at `inventory-a-entry-path` with no artifact. To distinguish
an over-depth relative path from excess encoded path bytes or an invalid
component, the observer now labels an **already-rejected** path with
`entry-path-depth`, `entry-path-bytes`, `entry-path-invalid`,
`entry-path-unavailable` or `entry-path-unresolved` inside the existing
fixed inventory-pass refusal phase. The original `_path_key` validator
still makes every acceptance/rejection decision, and its failure is still
raised. Neither pathname nor individual components, symlink target, raw
metadata or exceptions are logged. This is diagnostic observation only,
not a reason to skip an entry, relax depth/size bounds or dispose of it.
