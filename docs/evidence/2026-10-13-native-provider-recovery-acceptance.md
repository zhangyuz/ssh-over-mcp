# Native provider recovery acceptance — 2026-10-13

The stale native provider incident is resolved. The approved three exact
historical residual trees were disposed, the original marker was recovered
through the existing guarded workflow, and real no-network native E2E plus
cleanup passed on main **53868a714308273e4f3292483ff3e33299193c1e**.

## Exact evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Final PR #240 head eca5d89d65bef97d3632986777398b5d7fd436f2 | Full hosted Python 3.13/3.14 PASS | [38436398396](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38436398396) |
| Trusted-main UID 502 exact inventory inspection | PASS; all three complete pins matched | [38437465574](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38437465574) |
| Approved exact inventory disposition | PASS; 1362 directories and 6 symlinks removed; marker retained | [38437724175](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38437724175) |
| Existing marker-only inspect, expected PID 0 | PASS; original target/owner unchanged, temp_dirs=0 | [38438302841](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38438302841) |
| Existing guarded marker recovery, exact PID 38013 | PASS; RECOVERY_APPLIED for original target | [38438738523](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38438738523) |
| Exact merge-main full CI, attempt 2 | All eight hosted partitions, both Python required gates and native E2E PASS | [38437463320](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38437463320) |
| Native exact-target guest and cleanup | Both guest-run and provider-state absence steps PASS | [native job 115440875093](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38437463320/job/115440875093) |

[PR #240](https://github.com/zhangyuz/ssh-over-mcp/pull/240) merged at
2026-10-13 17:17:28 UTC. The native job ran from 17:30:05 to 17:33:11 UTC
on the dedicated non-admin Intel macOS runner, after guarded recovery.

The first merge-main native attempt ran before marker recovery completed
and correctly refused the still-present historical marker at 17:26:46 UTC.
It did not pass or launch a successful guest. The failed native stage was
rerun only after recovery at 17:27:50 UTC; hosted success from the same exact
main revision remained valid. Do not hide the earlier failed attempt.

## Disposition receipt and scope

All 1368 unique intention keys have matching confirmations in the complete
private journal: 2738 records, six unlink operations and 1362 empty-directory
rmdir operations. Its complete event preserves the marker. Journal SHA256:

`3acfa9ffe828231f25d6b5f0d56808fb8f350e4f2df9f11870af386675b614fa`

The private original remains in the protected UID 502 cache; a separately
verified private copy and all five earlier manifests were preserved by the
developer. No symlink target or historical regular payload was read.
No process was terminated by the disposition tool, no permissions were
repaired, and no privilege escalation occurred. Native orchestration then
owned and verified cleanup of its newly created guest/resources.

This was an operator-approved discard of exact residual inventories despite
incomplete historical provenance. It does not reconstruct deleted regular
files, prove their historical deletion cause, or retroactively certify the
original cancelled target 47531dadb58d365f74089dd5f52ce1b61bb0fdd1.

## Code and regression evidence

The one-incident tool pins complete canonical metadata hashes and marker
identity, rechecks live root/ancestor/journal edges after durable intention,
uses opaque symlink unlink and bottom-up empty rmdir, and refuses automatic
replay or uncertain durability. It never clears the marker itself.

A strict-atime Linux reproduction exposed read-induced directory access
time changes. The separate metadata-only collector now compares exactly
its published fields, excluding unrecorded atime while preserving precise
nanosecond modification/change-time drift checks. Valid RED tests proved
atime-only rejection and raw-tuple-equal nanosecond drift acceptance in the
old code; the minimal comparison correction made both GREEN. The temporary
O_NOATIME test workaround was removed.

133 focused Mac checks passed, including 35 new tests for namespace/journal
replacement, real write/fsync/close failures, process interruption/replay,
symlink target preservation and an actual 1332-entry/depth 13 fixture.
All 35 new tests also passed in a nonroot, capability-free, no-network Linux
container with forced strictatime. Ruff, compilation and diff checks passed.
Independent full cleanup/security/docs review and the scoped metadata
comparison review had no remaining Critical or Important finding.

## Remaining boundaries

The historical disposer is exhausted: its exact old roots and marker are
expected to be absent, and its retained journal prohibits another apply.
Do not invoke it to clean future incidents or delete its journal to bypass
replay refusal.

Future temporary-root alignment remains a separate design task. Python's
selected parent and native getconf still differ under UID 502. This
acceptance does not close A1/B8/N1c or other native roadmap work automatically,
and it does not weaken any normal role or guest isolation contract.
