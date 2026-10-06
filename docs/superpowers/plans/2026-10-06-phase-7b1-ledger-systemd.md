# Phase 7B1 Ledger systemd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver and certify one installed Security Ledger service under the approved systemd sandbox, preserving approval, audit, identity and recovery invariants.

**Architecture:** Land narrow trusted guest authority prerequisites before the target unit and acceptance probe. Build/install the target offline as a separate non-root identity, seal the measured runtime, then exercise the actual production command under the canonical profile. Keep the existing five-fixture Phase 7A proof intact and run it after the new Ledger matrix, so STOP_MANAGER remains last.

**Tech Stack:** Python 3.13/3.14; existing Ledger clients/SQLite; Linux systemd and native x86_64 syscall canaries; self-hosted Ubuntu 26.04 CI; trusted-main QEMU/HVF no-network guest.

**Spec:** [Approved Phase 7B1 design](../specs/2026-10-05-phase-7b1-ledger-systemd-design.md), [ADR 0009](../../decisions/0009-ledger-systemd-sandbox.md). Read these and the repository's normative development/security/API/policy documents before implementation.

**Status:** Plan approved 2026-10-06; Tasks 1–2 complete through exact merge-main gates (PRs 124/125). Task 3 inventory found no executable C compiler in the pinned guest; its native prerequisite design/plan are approved, not implemented or activated. G1 is complete through PR #127. See [approved native design](../specs/2026-10-06-offline-native-e2e-toolchain-design.md) and [approved prerequisite plan](2026-10-06-offline-native-e2e-toolchain.md). No Phase 7B1 acceptance or closure is claimed. Baseline main: a37747291894ac7b01ae5483af83d0dd89821015. Written design approved 2026-10-06 at 34805e7729e09b78b3b8fb5b8e40d2455d80081f.

## Global Constraints

- 小步快跑，持续迭代，关注质量、安全、一致性。 One bounded deliverable per PR; finish merge-main evidence and cleanup before the next PR.
- Self-hosted runners only. No sudo, root, Docker socket or new privilege on ordinary CI or the persistent Mac. Do not provision the production service on the Mac.
- Trusted root guest code must already be on main before certifying a target; it must not import or execute target builders, installers, applications or validation code as root.
- Fresh disposable Ubuntu 26.04 x86_64 QEMU guest, no NIC/host shares/host credentials/production secrets. Keep the pinned image/provider contract unless a separately reviewed authority prerequisite is necessary.
- Approval mutation remains real ssh-over-mcp-approvalctl outside MCP; no protocol operation, policy bypass, approval retry, framing timeout change or dynamic probe dispatch.
- Production command: /opt/ssh-over-mcp/venv/bin/python -I -B -m ssh_over_mcp.approvals.main. Mandatory installed-runtime proof permits no source adapter or ExecStart override.
- Unit: ssh-over-mcp-ledger.service. Profile values and layout are exactly design sections 3–5; unsupported mandatory enforcement blocks acceptance.
- Persistent/shared writable paths exactly /var/lib/ssh-over-mcp-ledger, /run/ssh-over-mcp-ledger-exec, /run/ssh-over-mcp-ledger-admin. Private /tmp and /var/tmp are separate permitted temporary roots, with isolation/non-persistence evidence.
- In the disposable guest, establish and verify the fixed non-pipe kernel.core_pattern plus RLIMIT_CORE hard/soft (0, 0) **before the first target exec**, including backend/builder/installer. All direct target children inherit and verify zero limits before exec; systemd-spawned processes separately require effective LimitCORE=0:0. Recheck before key access and crash/syscall canaries. No production-host core-policy mutator or late lifecycle-only setup.
- Type=exec, Restart=no, KillMode=control-group, SIGTERM, TimeoutStopSec=10s, final SIGKILL. Readiness means authenticated ping, not successful exec.
- Preserve fixed SSH → MCP → filesystem/profile → Task 6 → Task 7 probe; STOP_MANAGER\n / OK\n stays unchanged and Task 7 stays last.
- Never casually cancel E2E, auto-delete provider state, blindly unlink sockets or repair unknown key/database state. Cleanup failure fails the run.
- Every behavior PR requires exact-head ordinary CI and Level-3, fresh independent review without Critical/Important findings, then exact merge-main CI and Level-3. Initial authority bootstrap uses legacy-7a; after the native prerequisite, Tasks 3–8 additionally require native-required evidence containing all five legacy fixtures. Scoped native-authority repair follows the separately approved prerequisite protocol; it does not certify native/7B1 completion.
- A new production defect, architectural deviation or unprovable mandatory criterion stops that slice for a focused RED/fix or renewed design review; no relaxed assertions, sleeps or skipped checks.

## Review Focus

1. Partial key writes/fsync failure or an existing/replaced key: fail without success, replacement, secret output or unsafe retry (Tasks 1–2).
2. Builder descendants, mutable interpreter links, forged RECORD or sealing races: fail before any systemd start, preserve the outer VM boundary (Task 5).
3. Build-tool lock/metadata drift, drop-ins, command prefixes, aliases, core collectors or unexpected memberships: reject effective configuration before loading a key (Tasks 3, 5 and 8).
4. Foreign/replayed lifecycle record, active/replaced socket or incomplete process/namespace inventory: recovery preserves the endpoint and refuses removal (Task 6).
5. Missing target probe, false denial attribution or incomplete result matrix: never downgrade 7B1 to legacy evidence or mark it PASS (Tasks 7–10).

## File and responsibility map

| Files | Responsibility |
| --- | --- |
| src/ssh_over_mcp/approvals/keyfile.py; approvals/bootstrap.py | Small stdlib key-write primitive; unchanged legacy bootstrap semantics |
| ops/systemd/ledger_provision.py; ssh-over-mcp-ledger-provision | Explicit fresh-install provisioning, fixed reference paths, no recovery daemon |
| requirements/build.in; requirements/build.lock; pyproject.toml | Existing single build-tool authority, derivation consistency and verified Python/guest compatibility; no second E2E lock |
| ops/live-e2e/ledger_guest_preflight.py | Guest-only no-core setup/check, before every target execution boundary |
| ops/live-e2e/ledger_systemd_contract.py; ledger-systemd.service | Trusted fixed identities/paths/profile and bounded evidence vocabulary |
| ops/live-e2e/ledger_runtime.py | Non-root build/install, writer quiescence, runtime attestation/sealing |
| ops/live-e2e/ledger_lifecycle.py | Fixed-unit lifecycle and verified run-owned socket recovery |
| ops/live-e2e/ledger_sandbox.py; ledger_sandbox_probe.c | Fixed differential canary setup and native helper inputs |
| ops/live-e2e/ssh-over-mcp-live-e2e-gate; scripts/run-live-local-e2e-orchestrator.py; .github/workflows/live-local-e2e.yml | Trusted mode selection, phase sequencing, payload, commit/result binding and cleanup |
| ops/systemd/ssh-over-mcp-ledger.service; ledger.env.example; README.md | Actual production reference and precise operator procedures |
| tests/live/ledger_systemd_support.py; scripts/run-live-ledger-systemd-probe.py | Non-root target client assertions; no systemctl/root interface |
| tests/approvals/test_installed_ledger.py | Early installed-wheel startup/ping/stop regression on ordinary Linux CI |
| tests/ops/test_ledger_*.py; test_phase7b1_closure_evidence.py | Focused negative authority/unit contracts and evidence consistency |
| docs/security-model.md; audit-and-approvals.md; self-hosted-runner.md; development-plan.md; tests/live/README.md | Source-of-truth boundaries, supported deployment and exact revision evidence |

Test examples below use local fixtures/spies defined in their owning test files; they are not extra production APIs or target-facing controls. New trusted modules use only stdlib and explicitly packaged trusted-main files. Do not grow the existing root gate into a second large monolith or restructure unrelated code. Unit tests may load these modules with the existing SourceFileLoader pattern. REQUIRED_CRITERIA is exactly: identity, unit-loading, persistence, installed-composition, key-provisioning, endpoint-separation, network, io-uring, readonly-runtime-key, kernel-cgroup, graceful-stop, forced-stop-recovery, approvals-secrets, crash-retention, phase7a-regression, revision-cleanup. These IDs are fixed trusted evidence categories; target success alone cannot establish their completion. Their dependency-injection fakes must never become target-facing root interfaces.

## Delivery sequence and common per-PR gate

Tasks 1–8 are separate preparatory PRs, each merged and verified before the next starts. Tasks 3, 5, 6, 7 and 8 are trusted authority prerequisites; their new functions are dormant under legacy mode until Task 8 connects them. Task 9 is the target acceptance PR and uses only authority already verified on main. Task 10 ships one terminal evidence/protocol PR, adds no new capability, repeats mandatory gates and records its post-merge closure attestation outside Git.

For **each** task, the final “ship” step means all of the following, not merely committing:

1. Run focused tests and relevant existing security regressions; record the actual RED/GREEN reason.
2. Obtain fresh independent slice review; fix Critical/Important findings with their own RED/GREEN loop.
3. Run full supported Linux regression on both Python versions, Ruff and compile checks through ordinary self-hosted CI; use git diff --check. Include new tools in lint/compile coverage without executing them as privileged code.
4. Pin PR head SHA and trusted main authority SHA. Dispatch the task's fixed workflow **from main**, passing only exact commit_sha: initial bootstrap/scoped native repair uses live-local-e2e.yml; remaining Tasks 3–8 use live-native-toolchain-e2e.yml (native-required); Tasks 9–10 use live-ledger-systemd-e2e.yml (ledger-systemd-7b1). Candidate proof uses its separate fixed workflow as required by the native prerequisite. No caller mode selector or cross-class evidence substitution. Verify head SHA has not changed, all bindings agree, fixture coverage and cleanup PASS; then fresh final review and merge.
5. Record merge SHA, require ordinary push CI bound to that SHA, dispatch Level-3 for exactly that merge SHA using trusted main. Verify provider absence, guest cleanup, whole VM/media/bundle destruction. Only then remove clean merged/superseded branches/worktrees and proceed.

Tasks 1–2 and initial native-authority bootstrap use the complete legacy-7a matrix. After the prerequisite, remaining Tasks 3–8 use native-required with the same complete five-fixture regression; scoped native-authority repair alone may use legacy bootstrap pending fresh required proof. No unavailable 7B1 target evidence is claimed. Tasks 9–10 require ledger-systemd-7b1 and its installed composition matrix plus all five legacy fixtures. Gate failures keep the slice open. Local Mac tests are useful focused evidence, never Linux/systemd certification; use short AF_UNIX test paths without weakening endpoint checks.

### Task 1: Extract the reviewed key-write primitive without changing bootstrap behavior

**Files:** Create src/ssh_over_mcp/approvals/keyfile.py; modify src/ssh_over_mcp/approvals/bootstrap.py; test tests/approvals/test_keyfile.py and existing test_bootstrap.py.

**Interfaces:** Produce write_hmac_key(fd: int, *, uid: int, gid: int, mode: int) -> None and KeyFileError with fixed non-secret text. The caller owns fd creation/close, canonical-parent validation and parent fsync. This primitive generates 32 CSPRNG bytes, completes writes, applies/validates descriptor metadata and fsyncs the file. No imports of runtime/storage/package dependencies in this module.

- [ ] Write test_complete_short_writes_and_file_fsync: simulate writes of 7, 9, 16 bytes; assert exactly 32 bytes, creation payload from secrets.token_bytes(32), final requested metadata and file fsync before return. Parameterize zero write, write/chown/chmod/fsync failures: assert KeyFileError and no payload in its text/captured output. Add test_legacy_existing_key_is_validated_without_replacement: same inode/content remains for a valid existing 0600 key; invalid metadata still fails through current storage validation.
~~~python
# fd is a test-owned regular-file descriptor; io_spy injects short writes.
write_hmac_key(fd, uid=os.getuid(), gid=os.getgid(), mode=0o600)
assert io_spy.token_requests == [32]
assert io_spy.bytes_written == 32
assert io_spy.file_fsync_completed
~~~

- [ ] Run python -m pytest tests/approvals/test_keyfile.py tests/approvals/test_bootstrap.py -q; record intended missing-interface RED rather than unrelated fixture failures.
- [ ] Implement the stdlib primitive and delegate the current _create_hmac_key open/close wrapper to it with mode=0o600. Preserve exclusive-open flags, FileExists behavior, same-parent restriction, public bootstrap error and legacy validated-existing-key behavior. Do not add the new split layout here.
- [ ] Run the focused tests plus tests/approvals/test_storage.py and test_runtime.py; require GREEN with both fresh and pre-existing key paths.
- [ ] Commit “Refactor: reuse reviewed Ledger key write primitive”; ship this behavior-preserving prerequisite using the common legacy gate.

### Task 2: Implement strict fresh-install split-layout provisioning

**Files:** Create ops/systemd/ledger_provision.py and ops/systemd/ssh-over-mcp-ledger-provision; create tests/ops/test_ledger_provision.py; update docs/audit-and-approvals.md. Operator instructions are completed in Task 9.

**Interfaces:** Consume Task 1's write_hmac_key. Produce provision_reference() -> None and ProvisionError with fixed text “Ledger provisioning failed”. CLI accepts no arguments; fixed paths are those in the design. Resolve the Ledger account's numeric IDs from the trusted account database, not caller arguments or environment. Test-only private filesystem/OS fakes exercise failures without root.

- [ ] Write test_new_key_is_exclusive_private_and_durable: assert NOFOLLOW|EXCL|CLOEXEC, private creation, final 0400, exact owner, 32 bytes, file then parent fsync and descriptor/path identity match. Parameterize existing regular key/symlink/FIFO, writable or symlink ancestor, changed inode/parent and failed parent fsync: assert refusal, no overwrite, no success output. Write test_core_preflight_precedes_csprng: pipe pattern or nonzero hard/soft limit refuses before token_bytes. Assert CLI arguments and loader hooks cannot select another path/identity.
~~~python
# provision_fs injects an existing key and records all mutations.
with pytest.raises(ProvisionError, match="^Ledger provisioning failed$"):
    provision_reference()
assert provision_fs.key_bytes == original_key
assert provision_fs.unlink_calls == []
assert provision_fs.success_output == ""
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_provision.py -q; require intended RED.
- [ ] Implement provision_reference using pinned canonical directory descriptors and the reviewed primitive. Apply zero hard/soft core limits before generation and require non-pipe effective core pattern. Provision only fresh reference state with exact directory/group modes; reject unknown existing state, active Ledger use or inconsistent memberships. After a mutation/durability failure, leave uncertain run-owned state for explicit recovery rather than report success or auto-retry. Import the provisioned reviewed primitive only from an operator-trusted installation; no sys.path/environment hooks.
- [ ] Run provisioning and all bootstrap/key/storage regressions to GREEN; verify captured stdout/stderr/logs contain no key bytes and expected modes/owners are checked before service use.
- [ ] Commit “Add strict operator Ledger provisioning”; ship using the common legacy gate. No Mac/production provisioning occurs.

### Task 3: Pin the trusted profile, identities and offline payload contract

**Prerequisite discovered:** Fixed guest inventory run 37459216524 returned code 102 (no executable /usr/bin/cc). The approved ADR 0010/native plan must be completed first. Its G1 no-core guard is already complete independently as PR #127 at verified main8bcdca8; N3 candidate proof and N4 native-required/full-legacy merge-main gates must pass before the remaining profile/build work resumes. This is no acceptance downgrade.

**Files:** Consume the already-main ops/live-e2e/ledger_guest_preflight.py; create ledger_systemd_contract.py and ledger-systemd.service; extend tests/ops/test_ledger_guest_preflight.py; create tests/ops/test_ledger_systemd_contract.py and test_ledger_build_inputs.py; modify orchestrator trusted payload list/preparation and tests/ops/test_live_e2e_orchestrator_contract.py; extend tests/ops/test_container_reproducibility_contract.py; consume existing requirements/build.in and requirements/build.lock without a dependency update; update ops/live-e2e/README.md.

**Interfaces:** Re-export the already-main ledger_guest_preflight.ProfileError from ledger_systemd_contract.py. Consume G1 establish_guest_no_core() -> None and require_no_core() -> None, raising that same ProfileError on unsafe/unverifiable state; do not rename, convert or duplicate the verified guard. The establishment operation is fixed, guest-root-only and called after trusted fresh-guest verification, before any target execution; it is not a production provisioning API. Produce verify_candidate_unit(candidate: bytes) -> None; verify_effective_unit(properties: Mapping[str, str], *, core_pattern: str) -> None; require_reference_accounts() -> None. Produce constants FIXTURE_UNIT, RUNTIME_PREFIX, REQUIRED_CRITERIA: tuple[str, ...], PRODUCTION_COMMAND: tuple[str, ...]. Effective-property expectations are an explicit allowlisted snapshot, not a security score or permissive parser.

- [ ] Write test_candidate_bytes_and_effective_properties_are_both_required: reject changed bytes, duplicate directives, root command prefixes, extra Exec phases/drop-ins/aliases/environment sources, changed fragment, identity, capabilities, stop/core or sandbox properties. Assert these fail before any start. Write test_pairwise_gids_and_memberships: reject equal GIDs, client cross-membership and unexpected extra memberships. Write test_guest_no_core_precedes_first_target_exec: trace fixed guest policy establishment and hard/soft zero verification before backend/builder/installer, and reject pipe pattern, failed setting/readback or nonzero/unreadable limits without executing a target. Write test_target_children_verify_inherited_zero_core_limits: builder, installer, client probes, legacy manager/probe and descendants inherit hard/soft (0, 0); check every direct spawn before exec and assert a builder descendant cannot raise the hard limit without privilege. Write test_systemd_children_require_effective_zero_limits: since PID 1 does not inherit the controller limits, missing effective unit limits rejects start. Keep test_pipe_core_pattern_rejected_before_key_access. Write test_build_inputs_have_one_authority: normalized full build.in requirements (including specifiers, extras and markers) equal pyproject build-system.requires; hatchling.build is the trusted backend; every selected pinned version satisfies its applicable requirement; reject a second independently selected lock. Write test_build_lock_compatibility_precedes_authority_activation: exact/hash-complete lock, full dependency closure, Requires-Python/markers and binary wheels resolve and install unchanged for Linux x86_64 Python 3.13 and 3.14; offline pip check passes; any incompatibility blocks new authority activation. Test target backend/requires drift and missing/hash-mismatched build inputs fail before backend execution; persistent-host commands never run a target backend.
~~~python
with pytest.raises(ProfileError):
    verify_candidate_unit(canonical_bytes + b"ExecStartPre=/bin/sh\n")
with pytest.raises(ProfileError):
    verify_effective_unit(unexpected_dropin_properties, core_pattern="core")
assert systemctl_spy.start_calls == []
assert build_inputs.direct_requirements == build_inputs.pyproject_requirements
assert build_inputs.backend == "hatchling.build"
assert build_inputs.validated_python_versions == {"3.13", "3.14"}
assert build_inputs.lock_path == Path("requirements/build.lock")
assert spawn_trace.index("no_core_verified") < spawn_trace.index("first_target_exec")
assert child_core_limits == (0, 0)
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_guest_preflight.py tests/ops/test_ledger_systemd_contract.py tests/ops/test_ledger_build_inputs.py tests/ops/test_container_reproducibility_contract.py tests/ops/test_live_e2e_orchestrator_contract.py -q; record RED.
- [ ] Verify the already-main G1 establish_guest_no_core contract in the stdlib trusted guest module: require the gate's verified fresh-guest/root context, lower the controller's RLIMIT_CORE hard/soft to (0, 0), establish only the fixed non-pipe guest pattern "core", and read back both values before success. Failed/unverifiable setup forbids target exec. require_no_core checks effective limits and pattern without mutation. Package this module from trusted main only; neither function imports target code or accepts a caller-selected sysctl/path/policy. Each target spawn must verify the parent guard and the child's zero limits before exec; systemd processes independently use verified unit limits.
- [ ] Implement the canonical production unit snapshot with every section-5 setting, exact root-owned env source and only the three writable exceptions. Pin guest identities Ledger UID/GID 2210/3210, execution client 2211/3211, admin client 2212/3212, builder 2213/3213; endpoint GIDs 3297/3298. Use production names ssh-over-mcp-ledger, ssh-over-mcp-ledger-exec/admin and guest-only client/admin/builder account names; reject collisions/pre-existing state. Existing Phase 7A workload identity stays 2203/3203. Numeric IDs are guest fixture values only; production operator resolves its own distinct IDs.
- [ ] Establish compatibility evidence **before creating/activating new build authority**: reuse requirements/build.lock, whose existing provenance is requirements/build.in, pip-tools 7.6.1 and the recorded Python/base image. On supported self-hosted Linux, use fresh non-root build venvs for Python 3.13 and 3.14, prepare the same exact pinned build-tool wheel set (platform/marker-appropriate artifacts, with no version reselection), install with --require-hashes --only-binary=:all: --no-index --no-deps, run pip check and build a wheel with --no-build-isolation --no-deps. Record interpreter/platform tags, selected wheel hashes and marker/Requires-Python checks. Reuse the already-trusted requirements/e2e-bootstrap.lock for the pip frontend; do not independently choose another installer/build frontend. Existing lock provenance is not evidence of 3.14 compatibility. If incompatible, stop and land a separate reviewed update to the existing build.in/build.lock authority, preserving container reproducibility gates and lock-generation provenance; never create a fallback E2E lock or silently resolve new versions.
- [ ] Prepare the guest build wheelhouse from the **trusted-main copy** of that existing lock; the persistent orchestrator only fetches hash-verified binary inputs for the guest's Python 3.14/native platform. Record trusted authority SHA, source build.in/build.lock digests and selected wheel hashes in payload provenance. Target pyproject build backend/requires must exactly match the trusted approved build metadata before the backend runs; a changed requirement/backend requires a separate prerequisite. Recheck hashes and unchanged lock bytes inside the guest, install offline without build isolation/resolution, and run pip check. Package the reviewed stdlib provisioning helper/primitive from trusted main, never the target version. Inventory pinned guest systemd/kernel/native compiler support before adding canary prerequisites. If tools are missing, stop for a separate hash-pinned offline tool/image prerequisite with legacy gates; do not invent version/digest evidence or enable guest networking.
- [ ] Run contract/orchestrator regressions to GREEN, including existing no-network/provider-state tests. Keep the new mode inactive and describe this as authority preparation, not sandbox proof.
- [ ] Commit “Pin trusted Ledger profile and offline inputs”; ship using the common native-required gate. Record the merged authority SHA for later payload origin checks.

### Task 4: Add early installed-wheel Ledger regression on ordinary Linux CI

**Files:** Create tests/approvals/test_installed_ledger.py; modify .github/workflows/ci.yml and tests/ops/test_ci_workflow.py; consume existing requirements/build.lock through Task 3's verified build-input contract; update tests/live/README.md.

**Interfaces:** Produce test_installed_ledger_ping_and_sigterm. All build/install/start operations are current non-root CI identity. Uses existing SecurityLedgerClient.ping() -> None and exact isolated module entrypoint. Temporary runtime settings use the current validated identity and short run-owned paths; distinct-peer proof remains in the guest.

- [ ] Write test_installed_ledger_ping_and_sigterm: build exact checkout wheel with trusted locked build inputs prepared by the non-root test itself in an isolated build venv (so new workflow steps are not needed to run this test before merge), install non-editably into a fresh venv with locked dependencies, remove temporary build/source staging and clear loader hooks. From an unrelated cwd run -I -B -m ssh_over_mcp.approvals.main; assert authenticated ping, normal SIGTERM exit and endpoint cleanup. Check application/third-party origins inside this venv; stdlib/base interpreter origins are allowed. Write test_ci_runs_installed_regression_on_both_python_versions: inspect workflow dependency preparation for 3.13 and 3.14 without runner privilege or host-source import assists.
~~~python
# installed fixture is constructed by this non-root test, not the source venv.
assert installed.process_command == [str(installed.python), "-I", "-B", "-m", "ssh_over_mcp.approvals.main"]
await installed.client.ping()
installed.process.send_signal(signal.SIGTERM)
assert installed.process.wait(timeout=10) == 0
assert not installed.execution_socket.exists()
assert not installed.admin_socket.exists()
~~~

- [ ] Run the new workflow contract first and confirm RED; run the packaging test on supported Linux to identify missing packaging behavior separately from setup failure. If the product already passes, use the missing CI coverage as RED; do not deliberately break packaging.
- [ ] Implement only the test/harness and CI dependency preparation needed for this isolated regression. Do not claim that an ordinary CI checkout is physically inaccessible or that this substitutes for systemd evidence.
- [ ] Run the new test and Ledger regression suite on both Python versions through self-hosted CI; require real startup/ping/stop GREEN.
- [ ] Commit “Test installed Ledger entrypoint on supported Python versions”; ship using the common native-required gate.

### Task 5: Build, attest and seal the fixed installed runtime in the guest

**Files:** Create ops/live-e2e/ledger_runtime.py and tests/ops/test_ledger_runtime.py; modify trusted payload packaging tests/list and ops/live-e2e/README.md.

**Interfaces:** Consume Task 3 constants, require_no_core() and the trusted-main requirements/build.lock provenance. Produce frozen RuntimeEvidence(target_sha: str, authority_sha: str, build_lock_sha256: str, wheel_sha256: str, tree_sha256: str); build_and_seal_runtime(target_sha: str) -> RuntimeEvidence; unsafe runtime state raises Task 3 ProfileError. Public guest interface accepts only validated commit binding; paths/identities/tool commands remain fixed trusted constants. Root code reads/measures files; target origin checks run non-root.

- [ ] Write test_builder_requires_prior_no_core_guard: pipe pattern or nonzero/unreadable parent/child limits refuses before backend or installer; missing guard cannot be deferred to LedgerLifecycle.prepare(). Write test_backend_never_runs_before_verified_drop: assert exact builder identity/groups, zero Eff/Prm/Inh/Amb capability sets and NoNewPrivs=1 before wheel backend/installer. Write test_final_prefix_is_used_without_relocation: assert /opt/ssh-over-mcp/venv construction and final production path. Add test_runtime_uses_trusted_main_build_lock: replacing the target build.lock cannot change selected tools; altered payload lock digest, target backend/requires or installed tool version fails before build/sealing. Parameterize surviving/escaped writer, forged RECORD, modified locked dependency, writable interpreter/ancestor, .pth/editable hook, special file, hard link, unsafe symlink, set-ID/file capability and parent/inode replacement: assert refusal before unit start; measured candidate RECORD alone cannot attest dependencies.
~~~python
# runtime_fs leaves a builder descendant alive after backend exit.
with pytest.raises(ProfileError):
    build_and_seal_runtime(target_sha)
assert runtime_fs.builder_writer_still_present
assert systemctl_spy.start_calls == []
assert runtime_fs.target_root_execution_calls == []
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_runtime.py -q; require intended RED.
- [ ] Require Task 3's already-established no-core guard **before spawning the builder**; verify hard/soft (0, 0) in the dropped builder before any backend/installer exec and in a descendant integration canary. Then implement offline target build/install in a fixed run-owned builder cgroup with bounded output/error handling and no inherited sensitive FDs. Fail if builder descendants escape or cannot be fully inventoried/quiesced. Independently compare installed dependency content/origins with Task 3's trusted-main hash-locked wheel inputs; bind target artifact/tree measurement to exact source SHA and authority SHA/build-lock digest. The ordinary packaging regression consumes the same committed build lock and compatibility contract; it cannot independently select build-tool versions. Attest interpreter lineage and pyvenv.cfg, retain only explicit trusted interpreter links. Seal through descriptor-based safe filesystem operations after all writers stop; reject races instead of repairing unknown trees. Root must never execute target import/installer/RECORD validation code.
- [ ] Run runtime/contracts and legacy payload tests to GREEN, including exception/timeout cleanup. Record no claim of live composition until Task 9.
- [ ] Commit “Add trusted guest installed-runtime construction and sealing”; ship using the common native-required gate.

### Task 6: Implement fixed lifecycle and verified socket recovery authority

**Files:** Create ops/live-e2e/ledger_lifecycle.py and tests/ops/test_ledger_lifecycle.py; add it to trusted payload list; update ops/systemd/README.md with explicit recovery procedure draft and docs/audit-and-approvals.md.

**Interfaces:** Consume Task 3 profile checks/require_no_core() and Task 5 RuntimeEvidence. Produce frozen LifecycleIdentity(run_id: str, target_sha: str, guest_boot_id: str, lifecycle_id: str), EndpointRecord(path: Path, device: int, inode: int, uid: int, gid: int, parent_device: int, parent_inode: int), RecoveryRecord(identity: LifecycleIdentity, endpoints: tuple[EndpointRecord, ...]), and ReadWaitEvidence(identity: LifecycleIdentity, main_pid: int, process_start_ticks: int, accepted_socket_inode: int, observed_monotonic_ns: int); class LedgerLifecycle (unsafe operations raise Task 3 ProfileError) with prepare() -> None, start() -> None, await_partial_frame_read() -> ReadWaitEvidence, stop() -> None, record_endpoints() -> RecoveryRecord, recover(record: RecoveryRecord) -> None, cleanup() -> None, verify_clean() -> None. The trusted class owns an immutable identity: run_id is validated workflow run ID plus attempt from root-owned bootstrap configuration, target_sha is the trusted exact target binding, guest_boot_id is read from the guest kernel, and lifecycle_id is a fresh trusted UUID per fault/recovery lifecycle. The recovery/read-wait records are held in trusted controller memory, never accepted from a target checkpoint or file. await_partial_frame_read observes only the fixed unit's current MainPID/start identity and its accepted run-owned client connection using bounded trusted read-only kernel/socket evidence. A client connect/send/READY report alone is insufficient. It exposes no target-selected PID/path, secret-bearing memory dump or new application/privileged RPC. Only this trusted class invokes fixed systemctl commands; no target RPC/arguments select paths or commands.

- [ ] Write test_effective_unit_preflight_precedes_every_start: reject pre-existing/running fixture unit and unexpected loaded state before execution. Write test_recovery_requires_no_owner_and_original_inode: parameterize active PID/socket owner, inaccessible process/net namespace, incomplete inventory, replaced inode/type/owner/parent and concurrent start; assert original endpoint remains and no unlink is attempted. Write test_verified_recovery_only_unlinks_recorded_sockets: assert no database/key/directory deletion, pinned-parent recheck and fixed-unit restart. Write test_recovery_record_matches_active_run_boot_and_lifecycle: foreign run/attempt, wrong target SHA, previous guest boot, earlier clean-restart generation, forged record or second use after recovery must refuse before unlink even when inode metadata matches. Write test_stop_requires_observed_partial_read: missing accepted connection/read-wait evidence, timeout, PID reuse, closed/completed frame or a receive timeout before signal must fail the partial-frame criterion. Write test_forced_stop_is_systemd_timeout_not_helper_kill: an ordinary exit, direct helper SIGKILL, unrelated signal or missing unit timeout evidence cannot satisfy forced-stop. Test cleanup errors cannot become PASS.
~~~python
# lifecycle_ops reports that the recorded inode now has an active owner.
with pytest.raises(ProfileError):
    lifecycle.recover(record)
assert lifecycle_ops.unlink_calls == []
assert lifecycle_ops.endpoint_inode == record.endpoints[0].inode
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_lifecycle.py -q; require RED.
- [ ] Implement fixed provisioning using only merged trusted helper bytes and exact account/mode contracts. Recheck Task 3's previously established no-core guard; prepare() must never be the first policy-establishment point. Check hard/soft zero before key-handling helpers and effective LimitCORE=0:0 on every fixed systemd unit before start. Install only snapshot-equal unit, daemon-reload, verify all loaded properties before start. For shutdown cases, run the authorized partial-frame client concurrently with the trusted controller; await_partial_frame_read has a fixed 1s observation deadline below the existing 2s per-receive timeout and fails without evidence. Bind the observation to the current unit/process/socket and require event ordering accepted → incomplete-frame read wait → SIGTERM delivery, with no intervening EOF/frame completion/receive timeout; revalidate before stop and reject stale evidence. If the pinned guest cannot expose discriminating read-wait evidence, block acceptance for a reviewed alternative rather than adding a sleep or target diagnostic opcode. Before recording endpoints, bind the trusted run/attempt, target SHA, guest boot and lifecycle UUID and save the original record internally. Recovery requires the current trusted record and expected state sequence (recorded → forced-stop verified → stale-start refused → recovery); reject foreign/replayed records before filesystem mutation and invalidate the record after recovery. Recovery verifies stopped unit/empty cgroup/no Ledger UID processes and absence of socket owners across relevant namespaces, excludes competing starts, then unlinks only original run-owned sockets via pinned parents. Any uncertainty refuses. No automatic recovery, restart loop or generic root service API.
- [ ] Run lifecycle/provision/profile tests to GREEN. Require negative checks to leave state unchanged and bounded failures to preserve cleanup evidence.
- [ ] Commit “Add fixed Ledger lifecycle and verified recovery fixture”; ship using the common native-required gate. Production procedure remains an explicit trusted operator action with the same safety checks, never blind deletion.

### Task 7: Add attributable sandbox and crash canary authority

**Files:** Create ops/live-e2e/ledger_sandbox.py, ledger_sandbox_probe.c and tests/ops/test_ledger_sandbox.py; update trusted payload manifest and ops/live-e2e/README.md.

**Interfaces:** Consume Task 3 profile/constants and Task 6 lifecycle. Produce run_sandbox_matrix() -> tuple[str, ...] (unsafe or unproven state raises Task 3 ProfileError), returning only completed criterion IDs from REQUIRED_CRITERIA. Fixed helpers/controllers accept an internal closed enum of trusted cases, not arbitrary syscall numbers, paths, units or commands. Non-root compiler executes only trusted canary source; root never runs a target helper.

- [ ] Write test_io_uring_requires_per_syscall_differential: for each setup/enter/register require attested native x86_64 ABI, actual seccomp state, restricted SIGSYS versus documented kernel EPERM/EINVAL/EBADF in a control differing only in that syscall filter; reject missing ABI, unexplained result, other-filter SIGSYS or identical outcomes. Write test_dac_failure_is_not_readonly_mount_evidence: control service-owned sacrificial canary succeeds, restricted mount fails, actual key/runtime mounts remain read-only and permissions unchanged. Write test_crash_canary_requires_preflight_before_secret: reject pipe core collection before memory sentinel and require zero limits before SIGABRT/SIGSEGV/SIGSYS. Test canary cleanup and fixed-control profiles are mandatory, cannot widen the production unit.
~~~python
# helper_results injects SIGSYS into the supposedly unfiltered control.
with pytest.raises(ProfileError):
    run_sandbox_matrix()
assert helper_results.completed_criteria == ()
assert helper_results.production_profile_unchanged
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_sandbox.py -q; require RED.
- [ ] Implement isolated native C helpers using system headers/ABI constants, one helper per syscall/crash case. Set fixed trusted comparison profiles; capture only bounded safe status, never sentinel/key memory. Prove INET/INET6/raw-socket and namespace denial; attest private devices, protected kernel/cgroup mounts and zero capabilities with harmless probes, without modifying live kernel/cgroup authority. Prove PrivateTmp isolation/non-persistence/no credentials and independent DAC versus SO_PEERCRED tests. Scan run-owned paths/journal/crash locations after canaries; policy proof precedes scans and no collector loophole is inferred from empty artifacts. Missing discriminatory evidence blocks the criterion.
- [ ] Run canary/contracts and legacy gate regressions to GREEN. Native compilation/enforcement claims wait for the disposable guest in Task 9; no persistent-host capability probe.
- [ ] Commit “Add fixed sandbox differential and crash canaries”; ship using the common native-required gate.

### Task 8: Connect explicit trusted acceptance mode and complete result binding

**Files:** Create .github/workflows/live-ledger-systemd-e2e.yml and scripts/run-live-ledger-systemd-orchestrator.py; modify trusted orchestrator/bootstrap/result parsing and guest gate, preserving existing fixed legacy/candidate/native-required routes; extend tests/ops/test_live_e2e_gate_contract.py, test_live_e2e_orchestrator_contract.py and test_ci_workflow.py; update docs/self-hosted-runner.md and tests/live/README.md.

**Interfaces:** Produce one fixed main-only Ledger workflow/entrypoint selecting exactly ledger-systemd-7b1; its only input is exact commit_sha. Use the already-main closed profile/receipt registry from the native prerequisite, never a caller --acceptance-mode option. Preserve legacy-7a for scoped bootstrap/native repair, native-candidate for feasibility and native-required for authority preparation. The Ledger workflow shares the same live-local-e2e concurrency group, cancel-in-progress false, self-hosted dedicated account, pinned provider and cleanup contract. None of the other result classes can satisfy Ledger verification. Bootstrap carries trusted selected mode, exact commit and validated GitHub run ID/attempt in root-owned configuration, read from trusted workflow context rather than target data. Bind these to the new trusted lifecycle identity before any record is created. Fixed client phases are exactly pending, grant, consume, partial, after-clean-restart, trickle and after-recovery, with admin identity only for grant. Produce verify_acceptance_result(raw: str, *, target: str, mode: str) -> None: one bounded commit/mode-bound result with exact complete criterion set, duplicate/extra/missing fields rejected. Legacy result syntax may remain only for explicit legacy mode; it cannot satisfy new-mode verification.

- [ ] Write test_target_cannot_downgrade_requested_mode: missing/deleted/renamed/failing new probe must fail new mode even if legacy passes; target env/files cannot change trusted selection. Write test_result_binds_commit_mode_and_complete_matrix: wrong SHA/mode, duplicate PASS, truncated/missing criteria or cleanup failure rejected. Write test_new_matrix_precedes_fixed_five_fixture_probe: existing five-call order unchanged; STOP_MANAGER remains last; no systemctl command appears in its control protocol. Write test_no_core_guard_precedes_all_target_phases: the fixed order is verified fresh guest → establish_guest_no_core → require_no_core → builder drop/core verification → first target exec; deliberately moving the guard after construction must fail. Assert legacy direct target spawns and all fixed systemd/canary units retain zero limits. Test effective unit checks and build/drop verification precede any installed process.
~~~python
with pytest.raises(OrchestratorError):
    verify_acceptance_result(legacy_pass, target=sha, mode="ledger-systemd-7b1")
with pytest.raises(OrchestratorError):
    verify_acceptance_result(missing_recovery_result, target=sha, mode="ledger-systemd-7b1")
~~~

- [ ] Run focused gate/orchestrator/workflow tests and require RED.
- [ ] Connect only fixed phases: verified fresh-guest preconditions → establish_guest_no_core/require_no_core → mandatory native input/image reconciliation and feasibility → builder identity/capability/core-limit verification → non-root installed construction/sealing → production-unit/lifecycle/client phases → sandbox canaries → forced stop/refusal/verified recovery/client checks → clean Ledger stop/scan → unchanged full five-fixture probe → guest cleanup → bounded serial result. Use concurrent, bounded client/controller shutdown phases: the client holds the incomplete frame while trusted await_partial_frame_read establishes accepted/read-wait evidence, then the controller requests the fixed systemd stop. Do not wait for a trickling client to exit before stopping the unit; reap it afterwards. Root calls the target client probe only after dropping to the fixed execution/admin identities; target receives neither systemctl authority nor a parameterized privileged control channel. Reuse existing STOP_MANAGER control unchanged. Catch target failures with safe numeric categories, never raw exception strings. Native-required remains the Tasks 3–8 authority-preparation path and never invokes missing Ledger target probes. The reserved legacy path remains independent and scope checked for native-authority bootstrap/repair. A Ledger authority defect is repaired in a separate authority-only PR using native-required gates, then full Ledger proof must be repeated; a product fix cannot use preparation evidence.
- [ ] Run all authority/payload/result contracts to GREEN and full existing regressions. Dispatch exact-head and merge-main **native-required** from trusted main; after merge verify the selected mode and every new authority/helper/profile/lock originate at the merged trusted SHA. Record that new-mode target certification is still pending.
- [ ] Commit “Bind trusted Ledger acceptance mode and fixed lifecycle”; ship this final authority prerequisite using the common native-required gate; do not claim missing Ledger target acceptance. Freeze these authority bytes for Task 9; later changes require another independent prerequisite.

### Task 9: Ship the target unit and full installed Ledger acceptance probe

**Files:** Create ops/systemd/ssh-over-mcp-ledger.service and ledger.env.example; modify ops/systemd/README.md; create tests/live/ledger_systemd_support.py, scripts/run-live-ledger-systemd-probe.py, tests/ops/test_ledger_systemd_probe_contract.py and test_ledger_systemd_unit.py; update docs/security-model.md, docs/audit-and-approvals.md, tests/live/README.md. No trusted authority/gate/workflow change in this PR.

**Interfaces:** Consume all authority on main from Task 8, Task 6 await_partial_frame_read() -> ReadWaitEvidence, existing SecurityLedgerClient and real approvalctl. Keep no-core preflight and runtime-origin attestations ahead of secret-bearing service phases. Produce run_client_phase(phase: str) -> None in support and probe main(argv: Sequence[str] | None = None) -> int, with invalid phases returning 64 and assertion failures returning fixed safe nonzero categories. Phase is a closed allowlist fixed by the trusted lifecycle: pending, grant, consume, partial, after-clean-restart, trickle, after-recovery. Trusted orchestration runs pending/consume/partial/restart/trickle checks as the execution client and grant as the distinct admin client. Grant launches the real installed approvalctl process for the bounded run-owned approval ID; it cannot impersonate admin from the execution-client process. It selects non-root assertions only, never unit/identity/path/privileged action. The partial phase holds a paused incomplete frame; trickle holds an incomplete frame with paced bytes. Both are non-root concurrent client actions, never stop commands. The authority owns the start/stop/recovery ordering. Non-secret checkpoint data is bounded, run-owned and not accepted as authority for root cleanup.

- [ ] Write test_reference_unit_matches_already_trusted_snapshot and test_probe_phase_allowlist_has_no_root_controls: copied profile bytes exactly match trusted main, production command has no override, bad phases rejected with safe status. Define live assertions: authenticated ping; WAL/FULL audit persistence; real CLI pending→grant→consume; replay and argv/env binding denial; clean restart preservation; exact runtime origins/groups/caps; cross-direction DAC denial independently of peer denial. Write test_partial_frame_signal_follows_trusted_read_wait: SIGTERM before the server accepts/reads, stale PID/socket evidence or client-only READY must not pass. Write test_trickle_stays_active_until_verified_systemd_kill: the client remains connected and continues incomplete payload delivery across SIGTERM; assertions require the fixed unit's actual stop-timeout outcome, MainPID termination by SIGKILL and empty service cgroup, not elapsed time or a nonzero exit alone. Existing approval/deny protocol tests remain unchanged.
~~~python
assert main(["arbitrary-systemctl-command"]) == 64
assert target_unit.read_bytes() == trusted_unit.read_bytes()
assert privilege_spy.systemctl_calls == []
assert privilege_spy.admin_impersonation_calls == []
assert shutdown_trace.index("accepted_partial_read") < shutdown_trace.index("sigterm_delivery")
assert forced_stop.unit_timed_out and forced_stop.main_signal == signal.SIGKILL
assert forced_stop.service_cgroup_empty
~~~

- [ ] Run the new static/probe contracts to intended RED. Then dispatch one exact diagnostic target through trusted-main ledger-systemd-7b1 to establish the missing acceptance RED; keep bounded stage codes, no secrets, and do not alter root authority in this target to make it pass.
- [ ] Implement the minimal fixed-profile reference/unit/env and non-root client phases. Pending phase seeds audit and pending approval requests; grant and consume establish granted/consumed states and a non-secret preservation checkpoint before the lifecycle fault. For each shutdown case, send a valid protocol header declaring an unfinished payload within existing MAX_LEDGER_MESSAGE_BYTES, keep the connection open and run the client concurrently. Require Task 6's trusted accepted/read-wait observation and event ordering before SIGTERM. In the graceful case, pause further bytes, allow the existing 2s receive timeout and require normal cleanup before the 10s stop deadline, with no timeout/SIGKILL unit outcome. In the forced case, use contract-driven byte pacing (at most 1s between bytes, below the existing 2s receive timeout) without completing the frame or closing it; continue through SIGTERM until systemd enforces its configured 10s stop deadline. Require actual unit timeout evidence and MainPID SIGKILL, empty cgroup and preserved stale sockets, then reap the client. Missing synchronization, exhausted payload/client exit before the deadline, or unsupported observation fails the criterion; no fixed readiness sleep, arbitrary retry or production timeout change. After-recovery asserts ping, database clean open, unchanged key through trusted identity/digest checks kept out of public output, audit preserved, pending/granted/consumed states preserved except natural expiry; choose existing supported approval TTLs/checkpoints so expiry is recorded and does not erase the intended pending/granted/consumed comparisons; never extend TTL/resurrect consumption. Seal Ledger before offline final audit reads; do not reintroduce live-WAL visibility dependence. Scan secrets at all required phases using current retention guarantees.
- [ ] Complete operator docs: exact identities/memberships/layout, strict provisioning/core preflight, trusted installed release, systemd effective validation, readiness, clean restart, forced-stop verified recovery, rollback stop/preserve data; no shell key recipe, blind unlink or automatic fallback. Document initial Ubuntu/x86 support and out-of-scope collectors/architectures/services.
- [ ] Run all focused target/approval/static/security tests and full ordinary self-hosted regression. Require the early installed-wheel test on Python 3.13 and 3.14. Obtain fresh adversarial review, then exact-head **ledger-systemd-7b1** PASS with actual installed production command, full criterion matrix, all five Phase 7A fixtures and cleanup. Any stage failure gets one root-cause RED/minimal fix, not delays/retries. Repeat only after changed head/failure evidence warrants it.
- [ ] Commit “Validate installed Ledger systemd sandbox end to end”; ship with the mandatory new-mode common gate. Require exact merge SHA ordinary CI and full new-mode E2E PASS before calling implementation complete. Do not mark Phase 7B1 closed yet.

### Task 10: Whole-slice review, terminal closure PR and post-merge attestation

**Files:** Create docs/phase7b1-closure-evidence.md and tests/ops/test_phase7b1_closure_evidence.py; update docs/development-plan.md, docs/self-hosted-runner.md, tests/live/README.md, approved spec evidence/status. No new capability. Retain the final non-secret attestation outside Git at /Users/yuz/src/ssh-over-mcp-preserved/phase-7b1-closure/<terminal-merge-sha>.json; this is intentional audit evidence, not a temporary guest resource.

**Interfaces:** Consume Task 3 REQUIRED_CRITERIA and Task 8 exact commit/mode-bound results. Produce a tracked **implementation evidence** table using already-completed Task 9 head/merge runs, and a tracked **terminal closure protocol** whose post-merge result is explicitly pending. Produce test-owned validate_terminal_record(record: Mapping[str, object], *, expected_head: str, expected_merge: str, expected_authority_head: str, expected_authority_merge: str) -> None for offline consistency checks after live/API evidence is collected. It rejects incomplete or inconsistent records; fabricated unit-test records are never live evidence.

**Finite closure boundary:** Call the final documentation/evidence PR **C**, its reviewed exact head **H**, and its actual merge-main SHA **M**. C contains known Task 9 implementation evidence and the terminal protocol; it cannot contain future PASS results for H or M. Before merge, pin and verify H's ordinary CI, mandatory new-mode E2E and final review. After merging C, require CI and mandatory E2E for exactly M, then verified cleanup. Produce external attestation **E** bound to C/H/M and those actual runs. **M is the terminal Git revision for this closure; recording E does not create another commit/PR.** The roadmap/spec in C state “implementation complete; closure requires successful terminal merge attestation” and point to this protocol. Final closed status is derived only when E verifies the terminal gates and cleanup; the tracked pending protocol is not itself a claim of closure. If a later behavioral or documentation correction is required before closure, invalidate the proposed terminal record, choose a new C/H/M and repeat the terminal gates; do not silently keep old evidence or generate an endless sequence of evidence-only commits.

- [ ] Write test_closure_requires_current_complete_implementation_evidence: reject missing criterion, legacy-mode substitute, mismatched SHA/run, source-only composition claim, absent recovery/key/audit preservation or cleanup evidence; require existing five-fixture coverage and early installed-wheel results. Write test_terminal_protocol_does_not_claim_future_pass: tracked docs have known implementation proof plus pending terminal gates, not guessed H/M or future run IDs. Write test_terminal_attestation_requires_actual_revision_bound_gates: reject missing/failed post-merge run, wrong PR/head/merge/authority binding, wrong run attempt/mode, missing criterion/Python version/cleanup, or closed status asserted by a pending record.
~~~python
# terminal_record is a test fixture, not asserted live evidence.
validate_terminal_record(terminal_record, expected_head=head_sha,
                         expected_merge=merge_sha, expected_authority_head=head_authority_sha,
                         expected_authority_merge=merge_authority_sha)
with pytest.raises(AssertionError):
    validate_terminal_record(missing_merge_e2e, expected_head=head_sha,
                             expected_merge=merge_sha, expected_authority_head=head_authority_sha,
                             expected_authority_merge=merge_authority_sha)
assert tracked_status == "implementation complete; terminal closure pending"
~~~
- [ ] Run python -m pytest tests/ops/test_phase7b1_closure_evidence.py -q and record missing-evidence/consistency RED.
- [ ] Populate the tracked table only from successful Task 9 runs: each criterion's source invariant, focused RED/GREEN/static/integration test, actual implementation-head and implementation-merge live runs, review and cleanup evidence. Record authority/head/merge bindings, guest/kernel/systemd/QEMU versions, pinned image digest, unit/runtime artifact digests without secrets, resolved fixture accounts/groups and test counts. Mark implementation complete and terminal closure pending, not closed; future C/H/M results belong in E, not placeholder PASS cells.
- [ ] Obtain fresh whole-Phase-7B1 adversarial review against every acceptance row, Phase 5 approval/audit invariants, Phase 6 credential boundaries and ADRs 0005–0009. Search root-before-drop, generic privileged interfaces, stale state/TOCTOU/recovery-record replay, client/group confusion, build-lock drift, incomplete attribution, crash retention and acceptance downgrade. Findings use RED/minimal GREEN/full regression/fresh review; behavioral fixes remain separate small PRs. Refresh implementation evidence before choosing C if any fix changes it.
- [ ] Run closure contracts to GREEN, full ordinary CI and exact-H mandatory ledger-systemd-7b1 from trusted main with all five legacy fixtures and cleanup. Freeze H; fresh final review must have zero Critical/Important findings before merging C. Head changes invalidate the evidence and review.
- [ ] Merge C and read M from the actual PR merge record; verify its association with reviewed H. Record each E2E dispatch's actual trusted-main checkout SHA separately: the head and merge runs may have different checkout revisions, while their frozen Task 8 authority files must retain the already-approved digests. Do not conflate a prerequisite authority anchor with a run's checkout SHA. Require ordinary push CI for exactly M including installed-wheel tests on Python 3.13/3.14, then trusted-main mandatory new-mode Level-3 for exactly M. Verify commit/authority/mode/complete matrix bindings and provider/guest/whole-VM cleanup. A failed/pending M gate means **not closed**, regardless of Task 9 evidence or C merging.
- [ ] Audit then remove only clean merged/superseded branches/worktrees; preserve dirty work. Prune refs and verify root main equals origin/main at M and is clean, no temporary QEMU/orchestrator/guest/provider state, no temp bare repo/bundle/media/runtime remnants. Record bounded operator cleanup checks without privilege escalation or stale-state deletion. Dedicated runner/account intentionally remain.
- [ ] Collect E after all M gates and cleanup are verified: schema version, closure PR identity, reviewed H, terminal M, trusted-main checkout SHA for each head/merge E2E dispatch, the frozen Task 8 authority anchor and matching authority-file/lock digests, exact ordinary CI and E2E run IDs/attempts/permalinks and their observed SHA/event/mode/conclusions, both Python installed-wheel results, all REQUIRED_CRITERIA, fresh review and cleanup results. Reconcile these with actual GitHub run/PR metadata and trusted run outputs before writing the record; a self-reported JSON PASS is insufficient. Validate its internal bindings with validate_terminal_record, retain E at the fixed external location and link it plus authoritative run permalinks in the user-facing closure report. Declare Phase 7B1 closed for terminal M only now. **Do not commit E or amend M to record its own result.** Other Phase 7B capabilities remain unimplemented and separately designed.

## Plan self-review and execution record

Prepared 2026-10-06; checked against all ten design sections and sixteen acceptance rows. Tasks 1–2 cover key semantics; 3/8 unit/identity/trust; 4/5 installed artifacts; 6 recovery/lifecycle; 7 sandbox/crash attribution; 9 real behavior/composition and Phase 7A preservation; 10 finite terminal closure/evidence/cleanup. Review revisions 2026-10-06 remove the proposed second build lock, require existing-lock derivation and 3.13/3.14 compatibility before activation, bind recovery records to trusted run/boot/lifecycle identity, and distinguish the terminal merge M from its later external attestation E. The subsequent author-review corrections assign guest no-core establishment to Task 3 before any builder/target exec, verify inherited and systemd-specific zero limits, and require trusted accepted/read-wait ordering plus actual systemd timeout/SIGKILL evidence for shutdown cases. Interfaces above are the implementation contract, not claims that these modules exist today.

Before executing a task, write its actual baseline, intended RED, minimal GREEN, review and exact-head/merge evidence into the PR or a linked evidence record. Do not tick a task complete on mocked authority tests alone. The plan does not grant deployment to a production host, expand the STOP_MANAGER channel or make later Phase 7B slices part of this work.
