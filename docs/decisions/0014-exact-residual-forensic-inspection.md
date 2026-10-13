# ADR 0014: Exact residual forensic inspection

- Status: Approved read-only design by the user on 2026-10-12; implementation and live evidence pending
- Date: 2026-10-12 (America/Toronto)

## Context

Hosted CI speed acceptance is complete. Exact-main native E2E run
[38325534351](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38325534351)
at `1bb33571f579cbae1a5fc4c506d52abbab769bc9` fails before guest launch
on stale provider state, exit 70. Fresh trusted-main inspect-only run
[38327646572](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38327646572)
reports the same three UID-502 root identities, but all commit bindings are
missing and previously observed regular artifacts no longer appear.
Their cause and nested contents remain unknown.

ADR 0011's eleven-entry staging layout and expected-commit eligibility
contract refuses these partial trees and excludes the unknown recovery root.
It MUST NOT be relaxed to manufacture provenance or cleanup eligibility.
The user approved a separate read-only inspection of the three exact identities,
with metadata bounds, identity/process checks, independent review and no deletion.

## Decision

Activate only `inspect_provider_residuals.py` through the new manual trusted-main
`live-local-e2e-forensic.yml` workflow, after complete ordinary CI and independent
review. This is a recovery-only authority prerequisite under ADR 0011's sequencing
exception; the blocked native gate cannot certify this authority before merge.
No product, guest, automatic recovery or normal CI behavior changes are included.

The fixed catalog is:

| Basename | Device | Inode | UID / mode |
| --- | ---: | ---: | --- |
| ssh-over-mcp-e2e-i8ow1ni6 | 16777220 | 187176421 | 502 / 0700 |
| ssh-over-mcp-e2e-recover.cc8Del | 16777220 | 186815322 | 502 / 0700 |
| ssh-over-mcp-e2e-w_kn4rus | 16777220 | 186877220 | 502 / 0700 |

There are no caller-selected paths, targets, identities, commands or process IDs.
The workflow is dispatch-only on `main`, uses exact `github.sha` checkout,
matching fixed workflow ref/SHA, read-only token, pinned actions, no persisted
credentials and the non-cancelling
`live-local-e2e` concurrency group. Only already-merged authority executes on the
persistent non-admin Intel Mac orchestrator. Python isolated mode excludes
ambient Python import paths; trusted siblings load from the script directory.

Reuse the existing fixed diagnostic captures and their exact three-document
byte binding at `1ddebe541ee80c0febc4cd35072f3a5046fac5cb`. Preserve those document
bytes, diagnostic lifecycle checks and uncertainty semantics unchanged. This ADR
permits the new forensic caller, including metadata-only observation of the third
root; it grants no new diagnostic command, signal target or cleanup authority.
The existing helper may kill only its exclusively owned diagnostic child under
ADR 0012. Marker-owner observation remains the fixed signal-zero probe; no signal
is delivered to marker owner, QEMU, runner or other pre-existing process.

Derive the account temp parent only from completed fixed getconf. Pin literal
root/cache/temp ancestry and each catalog root through no-follow descriptors.
Read regular-file contents only for the existing fixed marker schema and the
three trusted-checkout diagnostic authority documents. No nested staging file,
commit binding, Git object, bundle, ISO, wheel, package or overlay content is read.

Bracket two complete metadata-only recursive passes with the existing fixed
process snapshot predicates. Both passes must agree byte-for-field for all roots;
recheck marker and namespace identities before returning evidence. Symlinks,
hardlinks, special files, foreign owners/devices, unsafe modes, identity changes,
missing roots, extra process ambiguity and unavailable observations refuse.
Descriptors remain pinned through final checks; failure/uncertain closes prevent
successful evidence. The strict eleven-entry staging collector remains unchanged
at its public interface; the separately named residual collector omits only that
layout requirement and grants no staging eligibility.

Bounds: 4096 entries, depth 12, relative path 4096 bytes, canonical inventory
2 MiB and 60 seconds per root/pass. Accepted combined evidence has at most 4096
entries and 2 MiB including its framing; an accumulated excess refuses. Intermediate
collection/serialization allocations are bounded by the three per-root inventories,
not by the final combined output ceiling. Total observation budget is 420 seconds,
checked between bounded operations; workflow timeout is ten minutes. Kernel calls,
external cancellation and machine failure have no promised hard completion bound.

The successful JSON includes exact authority SHA, workflow/run/attempt, marker
metadata, all catalog root inventories and non-authorizing classification:
`directory-only-residual` or `nonempty-or-unknown`. Every result explicitly sets
`recovery_eligible=false`. No JSON escapes before final descriptor closure and
namespace checks. Failed or partial inspection supplies no successful artifact.
A refusal logs only a fixed, non-sensitive phase label in the private workflow
log, never lower-level exceptions, observed paths, names, metadata, or content.
The label helps separate workflow-context, native ancestry, catalog root
opening versus pinned-identity refusal (by fixed index 1–3), subsequent inventory
and descriptor-close refusals; it does not prove the root cause and confers no
disposition authority. Index labels do not expose observed basenames or metadata.
The workflow writes only a new non-overwriting job-temp output and retains the
successful bounded metadata artifact for seven days. Raw relative paths remain
private investigation data; do not print or broaden their distribution. GitHub
artifact retention/upload is evidence transport, not a signature or cleanup receipt.

## Refusal-only catalog-open diagnosis (2026-10-13)

The first trusted-main live forensic attempt
[38333242069](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38333242069)
refused at `catalog-open-1` before collecting a residual inventory. This
label did not distinguish an absent root from rejected owner/mode, a changed
object or an opening/revalidation failure. No cleanup was authorized.

On *failure only*, the caller now performs one bounded `stat` of the failed
literal catalog entry relative to the still-pinned native temp-parent
descriptor, with `follow_symlinks=False`. The printed label is drawn only
from the fixed set `missing`, `unsafe`, `changed`, `unavailable`,
`unresolved` after `catalog-open-N-`. These are observations made **after**
a failed pin, not atomic evidence of the failed operation. Concurrent
changes can alter their meaning; `unresolved` means the follow-up metadata
matches but the authoritative operation still refused.

The authoritative no-follow descriptor chain, exact catalog identities,
two-pass bounds, marker/process checks and successful evidence contract are
unchanged. No observed name, pathname, owner, mode, inode, exception, file
contents, or lower-level error is logged. A refusal still exits 70 and
produces no successful evidence. In particular, neither `missing` nor
`changed` is permission to unlink the marker or dispose of other roots.
Run the updated workflow only after independently reviewed hosted CI and
merge to trusted `main`; require fresh private artifact review and separate
per-identity operator disposition before any cleanup.

## Limits and recovery sequencing

Directory-only evidence proves only the complete observed metadata contains no
regular files, symlinks or special objects. It does not attribute the tree to a
historical run or explain its earlier changes. Root inode equality is not nested
identity continuity. Two executable-name snapshots are bounded observations, not
exclusive process quiescence: generic shell activity, renamed processes,
same-account ABA and activity between/after snapshots remain outside the guarantee.
Shared workflow concurrency does not exclude manual operator activity.

After live inspection, independently review the entire artifact and its successful
trusted-main run. Only then propose an exact-identity per-directory disposition
with separately explicit operator approval. This ADR authorizes no unlink, rmdir,
rename, permission repair, sudo, target execution, guest launch, provider restart,
marker clearance or deletion retry. Existing marker-only recovery remains unchanged
and requires all blocking temp roots absent. Current-main native E2E and complete
provider/guest/artifact cleanup must pass before calling the issue fixed. A1/B8/N1c
and other native acceptance gates are not closed by this forensic observation.

## Validation

Require test-first disposable fixtures for directory-only and regular-file trees,
content nonaccess, unchanged strict staging refusal, symlink/hardlink/FIFO/mode
refusal, replacement/drift, marker and process failure, count/time/output bounds,
no partial output and unchanged borrowed descriptors. Run existing inventory,
recovery, diagnostic and namespace regressions on native fixtures, full hosted
Python 3.13/3.14 CI, fresh independent review, exact merge-main checks and only
then one manual trusted-main live forensic inspection. Preserve unknown state.
