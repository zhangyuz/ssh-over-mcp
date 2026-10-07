# ADR 0012: Owned diagnostic-child lifecycle for incident inspection

- Status: Proposed; no signal exception approved or implemented
- Date: 2026-10-07
- Amends: ADR 0011 only for the two fixed inspection diagnostic children below

## Context

The approved incident inspection design requires bounded native `getconf` and
`ps` observations. Its proposed child-termination exception is explicitly
unapproved. ADR 0011's no-process-killing rule therefore still applies, even to
dormant implementation. Pure envelope/receipt codecs in #146 add no such power.

An output bound or timeout alone cannot ensure a stalled diagnostic child stops
running. Granting a generic kill helper would unnecessarily widen persistent-host
authority. This proposal separates a narrow lifecycle decision from inventory,
workflow activation, staging disposal, provider recovery and product execution.

## Proposed decision

After separate explicit written approval and an already-main authority binding,
allow the non-admin inspection process to create, collect and reap only:

| Fixed argv | Collection deadline | Live output bound |
| --- | --- | --- |
| `/usr/bin/getconf DARWIN_USER_TEMP_DIR` | 5 seconds | stdout and stderr each 1024 bytes; combined 2048 bytes |
| `/bin/ps -ww -U 502 -o pid=,comm=` | 10 seconds | stdout and stderr combined 65536 bytes |

Use absolute executables, direct argv, no shell, no PATH search, environment
exactly `LC_ALL=C`. In the **child's exec-time descriptor table**, stdin is the
fixed disconnected `/dev/null` source; stdout/stderr are only the owned pipe
write ends. Exclude every other parent descriptor, including pipe read ends and
pinned cache/temp/root/payload handles, even if marked inheritable. This is
child-side descriptor hygiene: the helper MUST NOT close or mutate unrelated
borrowed/pinned descriptors in the parent, including their flags or offsets.
Those provenance handles remain usable in the parent through final namespace
and marker revalidation. Close only helper-owned pipe and `/dev/null` resources
in the parent on their appropriate lifecycle paths.
No caller can choose command, PID, UID,
environment, timeout, output limit, signal, process group or lifecycle handle.
The internal interface chooses one of these two literal diagnostics; it never
accepts a caller-owned process object. This grants no arbitrary command or
application execution. Successful output additionally meets the existing
inspection design's exact parser, empty-stderr and zero-exit requirements.

### Ownership and signal boundary

Each invocation has exclusive ownership of its freshly created child and its
wait status until reaped. Run the inspection as a single-threaded process with
default SIGCHLD disposition, no SIGCHLD handler, no competing reaper and no
`waitpid(-1)` consumer. Refuse unsupported lifecycle conditions before spawning.
Once reaped, a handle is terminal and cannot authorize a later signal.

On a collection deadline, output overflow or collection error, first check the
owned child's status without blocking. If it remains unreaped and running,
permit **one SIGKILL to that exact child only**, then attempt bounded reaping.
No SIGTERM grace phase, signal retry, negative/group PID, descendant traversal or
PID rediscovery is authorized. An unreaped child retains its PID under the
exclusive-parent assumption; a recorded PID or successful `kill(pid, 0)` alone
does not prove ownership. Unknown ownership/status or competing reaping refuses
signalling and makes inspection fail. ESRCH is not proof of a successful reap;
the owned wait result must settle status. Do not signal a PID after reaping it.

This exception never permits signalling the marker owner, QEMU, an orchestrator,
runner, process-inventory row, borrowed child or caller-supplied PID. The fixed
tools are trusted diagnostics and must not create descendants. If an already
exited child leaves pipes open through another process, close owned pipes and
fail; never signal that other process or turn this into process-tree cleanup.

### Deadlines and uncertainty

Use monotonic collection deadlines measured before spawn, bounded nonblocking
pipe reads and bounded waits. No unbounded `communicate`, output capture or
`wait` may occur on success or failure paths. After a collection failure, use a
separate **2-second** cleanup deadline to settle the owned wait status. Close all
owned pipe descriptors on every path. Any collection failure stays a failure
even if cleanup succeeds. Do not retry the diagnostic automatically.

If signalling/reaping fails or cleanup expires, report generic inspection
failure with explicit diagnostic-cleanup uncertainty through bounded safe
metadata; emit no receipt or chunks. Preserve all provider/staging state.
Do not claim the child is absent without an owned wait result. No hard bound on
kernel syscalls, uninterruptible tasks, spawn, externally cancelled workflows or
machine failure is promised. Unknown child state blocks acceptance rather than
being converted into successful inspection or permission for operator killing.

### Later inspections and detectable leftover diagnostics

The next inspection cannot recover the previous parent's exclusive wait
ownership. A process-inventory PID never becomes an owned child or signal target.
Instead, require refusal on detectable leftover diagnostics in **both** bounded
process snapshots before and after inventory collection. Complete and reap this
inspection's `getconf` before taking either snapshot; any validated UID-502 row
whose case-folded basename is exactly `getconf` then refuses inspection.

For each snapshot, allow exactly one `ps` row: the exact freshly owned `ps` child
that produced that snapshot. Capture its PID from this invocation's exclusive
lifecycle before reaping, never from caller input or parsing the snapshot as
ownership evidence. Its row must appear exactly once with case-folded basename
`ps`; a missing or mismatched row refuses. Any other validated UID-502 `ps` row
refuses, including an operator's diagnostic or a prior cancelled/stalled child.
Keep the existing parser bounds, ambiguity refusals and other process exclusions.

Refusal emits no receipt/chunks and preserves provider/staging state; it never
signals the leftover or automatically retries. This adds detection, not orphan
cleanup authority or a durable lifecycle journal. It proves only the absence
of these detectable basenames in successful bounded observations. Renamed,
transient or compromised same-account processes remain outside the stated
quiescence guarantee; historical cleanup or absence after a snapshot is not
certified. Unavailable or ambiguous observations cannot clear uncertainty.

### Authority approval and exact binding

This document is a proposal, not permission to implement signal-capable code.
The written approval must explicitly cover this exception, then the reviewed
ADR amendment must be merged before preflight implementation begins, including
dormant code. Approval of the codecs, inspection design or this proposal's scope
does not substitute for approval of the written authority.

The subsequent implementation plan must record one exact already-main commit
containing the approved ADR 0012 and ADR 0011 amendment, both fixed paths and
their content SHA-256 values, plus the reviewed amended inspection spec's fixed
path and content SHA-256. Preflight and final activation verify that same
three-document binding; a future merge SHA, target-authored replacement, ancestry alone or
caller-selected mapping is insufficient. This proposal deliberately supplies
no fictional future SHA or digest. Approved document bytes may identify approval
evidence independently; any status change requires a new exact reviewed binding.

## Acceptance

Require a separate approved plan, focused RED/GREEN, disposable native macOS
fixtures, full self-hosted Python 3.13/3.14 CI and fresh adversarial review.
Tests must prove fixed argv/env/descriptors, live bounds on both output streams,
monotonic collection and cleanup deadlines, normal exit/reap, nonzero/stderr
failure, stalled/overflow child termination and exclusive wait ownership.
Cover child exit at timeout, already-reaped handles, duplicate cleanup, ESRCH,
signal/wait failure, ambiguous status, retained pipes, unsupported SIGCHLD/reaper
conditions and cleanup expiry. Negative tests must prove no signals to marker,
inventory, borrowed, reused or group PIDs and no successful output on uncertainty.
Disposable test children are test-owned; tests may not signal incident processes.

Native tests must prove parent descriptor preservation on success and every
failure/cleanup path, including a deliberately inheritable borrowed descriptor:
identity, usability, flags and offsets remain unchanged, and the actual executed
child has none of the unrelated/pinned descriptors. A disposable FD probe may
exercise the same launch primitive under test; it must not introduce a
configurable production executable or borrowed-process interface.

Add native adversarial fixtures with a cancelled parent and a still-running or
stalled prior `getconf`/`ps` child. The next inspection must refuse, emit no
receipt, leave state unchanged and send no signal to that orphan. Cover both
snapshot stages, an extra `ps` alongside the allowed fresh child, missing/wrong
own-`ps` identity, mixed-case basenames and unavailable/malformed inventory.
Fixture owners handle their own disposable teardown separately from inspection;
passing tests grant no incident orphan-killing authority.

Document native results separately from supported Linux regression. Exact-head
and exact merge-main ordinary gates remain required. This recovery prerequisite
earns no Level-3 or A1 closure credit while stale provider state blocks E2E.
Workflow activation still requires its independently reviewed already-main
authority; neither this ADR nor a dormant helper activates inspection.

## Alternatives and consequences

1. **Single SIGKILL for the exclusively owned diagnostic (recommended):** one
   fixed signal and no graceful protocol; appropriate because these tools hold
   no application state. Requires careful ownership and uncertainty evidence.
2. **SIGTERM then SIGKILL:** supports graceful shutdown but adds a signal,
   another race and grace-period contract without a diagnostic-state benefit.
3. **Never signal:** preserves the current rule, but a stalled diagnostic can
   outlive its collection deadline and requires separate operator intervention.

The proposed exception is an OS side effect under the existing non-admin account,
not a generic process-control API. It relies on a trusted, exclusive parent and
cannot defend against a compromised same-account process. Existing no-network
guest, trusted-main separation, generic public errors, production authorization
and credential boundaries remain unchanged. Staging deletion, marker clearance,
unknown recovery workspace attribution and N1c activation remain unapproved.
