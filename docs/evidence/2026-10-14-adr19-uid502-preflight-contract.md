# ADR 0019 — Inert UID502 preflight contract evidence

**Status:** Inert implementation development; real UID502/APFS physical
acceptance **UNVERIFIED**. This is **not** an authorization record.

## Proven prior gates

- Joint-reviewed design and plan:
  [PR #252](https://github.com/zhangyuz/ssh-over-mcp/pull/252),
  exact final docs HEAD `f98096b5a32b7a31c2d5eab9e3214b31f0ade496`;
  independent [review #6181972834](https://github.com/zhangyuz/ssh-over-mcp/pull/252#issuecomment-6181972834)
  reported **0 Critical / 0 Important / 0 Minor**.
- Docs exact-head hosted [CI #38662060698](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38662060698):
  **SUCCESS**; documentation merged main SHA
  `1c29ae8e8f8dfdb699d64e5f82285d46160473a6`.
- Existing merged-main [CI #38648215422](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38648215422):
  **SUCCESS** including old-path real Mac/QEMU Level-3 and read-only provider
  marker absence. This evidence **does not** imply new UID502 fixture PASS.

## New implementation contract and non-authority

- File: `ops/live-e2e/uid502_preflight_contract.py`; tests:
  `tests/ops/test_uid502_preflight_contract.py`.
- Run, checkout, job/permissions/concurrency, UID/EUID/numeric GID,
  interpreter, original-versus-current directory identity, provider/marker,
  QEMU enumeration and both legacy namespaces are *synthetic, caller-supplied*
  records. No source module invocation touches the real host or GitHub.
- Without a test-only interpreter policy, explicit
  `INTERPRETER_TRUST_UNAPPROVED` refusal is mandatory. A fictional
  `/test-only/uid502-pinned/python3.13` root-owned complete record can
  be schema-eligible; the actually observed `/usr/local/Cellar` group-writable
  operator-owned CPython ancestry must refuse. Neither record is authenticated.
- Even `CONTRACT_ELIGIBLE_FOR_HOST_PROBE` **cannot authorize native execution**.
  Only a separately approved trusted-main host collector may eventually
  verify real UID502 identity, APFS ACL/FD ownership and trusted interpreter.

## Implementation verification boundaries

Host-independent focused RED→GREEN cases have been run incrementally
and outputs saved in the ignored implementation workspace
`.superpowers/sdd/` (tracked commits are on the implementation branch).
The exact final implementation-head hosted CI, independent whole-project
security review and merged-main native Level-3 evidence must be appended
through the later code PR before the work can be called merged. Do not
mistake this evidence note for a final CI PASS.

**Release state:** UID502=UNVERIFIED. No new UID502 workflow, actual fixture
run, foreign-object cleanup, approved interpreter, protected-staging
placement or automatic PR-native dispatch is provided by this iteration.
