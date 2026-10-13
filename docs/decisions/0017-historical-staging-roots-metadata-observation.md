# ADR 0017: Read-only metadata evidence for two exact historical staging roots

- Status: proposed observation-only contract; **no cleanup authorized**
- Date: 2026-10-13 (America/Toronto)

## Motivation and evidence

Historical native no-network Level-3 remains blocked by the preserved UID-502
provider marker and three residual roots. The private /private/tmp observer
succeeded twice on historical **root #2**, but cannot substitute for evidence
about **roots #1 and #3**. Its matching inventories comprised 1,332 nodes:
1,326 directories and six symlinks, maximum relative depth 13, all UID-502,
with no regular files. The two evidence inventories matched exactly; neither
establishes root provenance, process exclusivity or cleanup eligibility.

This decision concerns only the other two fixed catalog tuples:
- #1: device 16777220, inode 187176421, UID 502, mode 0700
- #3: device 16777220, inode 186877220, UID 502, mode 0700

Historical content/commit labels (ADR 0011) are **not** sufficient provenance
and MUST NOT be treated as disposition authority.

## Separate trusted-main observation

The manual `live-local-e2e-staging-roots-observe.yml` runs only at exact
trusted `main` with pinned checkout SHA, pinned actions, read-only contents
token, private seven-day artifact, and shared non-cancelling
`live-local-e2e` concurrency. Only the existing non-admin UID-502 macOS
x86 runner can execute it. There are no operator-selected file paths,
catalog indices, remote inputs, sudo or mutations.

The observer pins literal root-owned, sticky `/private/tmp` through
component-wise no-follow descriptors, the exact unchanged provider marker
and its protected cache, then both fixed historical catalog roots. Every
selected root must match exact device, inode, UID, mode 0700 and parent
device. The already-reviewed ADR 0016 metadata collector acquires only
validated directory descriptors with `O_DIRECTORY|O_NOFOLLOW`; symlinks,
special nodes and regular file leaves are recorded through no-follow
metadata only, never opened, read or followed.

The two complete snapshots must match per root. Directory entries are
bounded to 4096 **per root**, aggregate to at most 4096 nodes across the
two fixed roots, with at most 64 components/4096 encoded relative path
bytes per entry, a 60-second observer deadline per root/pass, 420 seconds
overall, and 2 MiB final JSON artifact. The collector's own conservative
enumeration/metadata checks, directory owner/device/mode restrictions,
closure uncertainty refusal and double-pass checks remain unchanged.
The process executable-name snapshot, marker, directory chain, protected
cache and parent are rechecked before any complete artifact escapes.
Failure yields a fixed label, exit 70, and no successful/partial artifact.

Evidence includes **no** symlink targets or regular-file contents; paths
and metadata are restricted to the private artifact, never job logs.
Every successful result explicitly carries `recovery_eligible=false`
and is **non-authorizing**, regardless of whether a root contains a
complete staging layout, a partial tree, a special file or a foreign leaf.
The original staging validator, ADR 0011 recovery proposal, existing
strict inspector, root #2 observer and marker-only recovery remain unchanged.

## Follow-through and non-authority

After independently reviewed exact-head Hosted CI, one trusted-main manual
read-only run may collect root #1/#3 metadata. Review that private artifact
together with two root #2 artifacts; authenticate marker, process quiescence,
each exact identity, and provenance **separately**, noting that bounded
process snapshots are not exclusive proof. Propose an exact per-object,
per-root disposition and obtain **separate explicit operator approval**
before any unlink, rmdir, repair or marker clearing. Only after such a
reviewed approved disposal workflow and complete absence of blocking
residuals may existing fixed marker-only recovery and actual no-network
Level-3 be evaluated. Do not claim native test success from this ADR.
