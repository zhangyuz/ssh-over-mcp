# Fast hosted dual-Python complete-suite experiment

This optional CI experiment compares **six independently scheduled GitHub-hosted
Ubuntu 26.04 x86 workers** with the complete unfiltered GitHub-hosted
two-worker-per-version baseline in PR #215. SOM is a private repository:
standard hosted Linux machines have 2 vCPU and 8 GB RAM and consume paid or
included GitHub Actions minutes. This experiment is intentionally limited to
same-repository `ci/fast-hosted-` pull requests, and never replaces the
self-hosted hardened security or merge-main native Level-3 requirements.

## Strict source-based partition

For **each Python version (3.13 and 3.14)**:
1. `projection-hot` runs four **exact node IDs** from the slowest verified
   source-bound projection tests. These are still genuine, unmodified boundary
   and security tests, not mocks or shortened substitutes.
2. `projection-rest` runs the **whole projection module except those same
   exact four IDs** via `--deselect`; all current and future other projection
   tests execute here automatically.
3. `rest` runs pytest's default testpaths (the entire `tests` tree) with
   only the projection module excluded via `--ignore`.

This is an exact disjoint union of the original test suite: four selected
tests + every other projection test + every other test. The repository
contract verifies the four node IDs exist, that they are selected only in the
hot job, and that the second projection job deselects exactly that list.
Matrix `fail-fast: false` ensures all **six** outcomes are collected.
The always-running gate fails unless all six Python x partition checks
succeed. No `-k`, whole-class selection, missing nodes or weakened
assertions are allowed; default pytest skips are unchanged. Both partitions retain Linux identity checks, project-wide
Ruff/compile, full Git history, and read-only token/security isolation.
Both jobs run as non-root, removing only hosted runner's extra supplementary
groups with the standard `setpriv` syscall tool.

## Measure and decide

Per exact revision, record runner queue, dependency/setup time, source-heavy
projection runtime, rest runtime, gate overhead, Python 3.13/3.14 coverage,
exit codes, historical SHA binding and total end-to-end workflow time.
Explicitly compare against the full-pass hosted baseline
[38294820787](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38294820787):
3.13 8m43s, 3.14 10m57s, end-to-end 12m17s. These are just one baseline
sample, not P95. This experiment needs **both full Python versions PASS**,
zero missing test nodes, stable independent security checks and repeated
P95 **under 10 minutes** to satisfy the fast-hosted goal. Do not confuse
hosted VM success with hardened mac-x86 runner policy or native Level-3.
No production release or required-check promotion is authorized by a single
green Canary.


## First four-job baseline and next hypothesis

The initial 2x2 matrix passed **all four** jobs and final gate in
[run 38297317913](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38297317913),
in **10m08s** end-to-end. Source-heavy Python 3.14 projection alone took
~9m57s while rest shards completed in ~1 minute. This six-job split targets
that source-heavy critical path by moving the longest four tests to their
own hosted VM per Python version. It is a separate experiment to prove
an end-to-end time under 10 minutes with margin, not a guaranteed result.
Private repo billed minutes can increase; do not apply this matrix to every
PR before real CI, test-collection parity and P95 measurements pass.
