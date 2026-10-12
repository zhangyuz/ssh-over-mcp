# Fast hosted dual-Python complete-suite experiment

This optional CI experiment compares **four independently scheduled GitHub-hosted
Ubuntu 26.04 x86 workers** with the complete unfiltered GitHub-hosted
two-worker-per-version baseline in PR #215. SOM is a private repository:
standard hosted Linux machines have 2 vCPU and 8 GB RAM and consume paid or
included GitHub Actions minutes. This experiment is intentionally limited to
same-repository `ci/fast-hosted-` pull requests, and never replaces the
self-hosted hardened security or merge-main native Level-3 requirements.

## Strict source-based partition

For **each Python version (3.13 and 3.14)**:
1. `projection` runs the original **entire**
   `tests/ops/test_live_e2e_staging_projection.py` module, including all
   expensive boundary/forgery cases, without selection filters.
2. `rest` runs the pytest default testpaths (the entire `tests` tree),
   with only the projection file excluded through pytest's own `--ignore`.

This is an exact disjoint union of the original test suite, including
future tests added outside the projection module. Matrix `fail-fast: false`
ensures all four outcomes are collected. The final always-running gate fails
unless **all four** Python x partition checks succeed. No --deselect, -k,
skipping or weakened assertions are permitted; default project skips are
unchanged. Both partitions retain Linux identity checks, project-wide
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
