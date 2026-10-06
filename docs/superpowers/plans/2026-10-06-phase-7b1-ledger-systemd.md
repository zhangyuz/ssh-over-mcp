# Phase 7B1 Ledger systemd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver and certify one installed Security Ledger service under the approved systemd sandbox, preserving approval, audit, identity and recovery invariants.

**Architecture:** Land narrow trusted guest authority prerequisites before the target unit and acceptance probe. Build/install the target offline as a separate non-root identity, seal the measured runtime, then exercise the actual production command under the canonical profile. Keep the existing five-fixture Phase 7A proof intact and run it after the new Ledger matrix, so STOP_MANAGER remains last.

**Tech Stack:** Python 3.13/3.14; existing Ledger clients/SQLite; Linux systemd and native x86_64 syscall canaries; self-hosted Ubuntu 26.04 CI; trusted-main QEMU/HVF no-network guest.

**Spec:** [Approved Phase 7B1 design](../specs/2026-10-05-phase-7b1-ledger-systemd-design.md), [ADR 0009](../../decisions/0009-ledger-systemd-sandbox.md). Read these and the repository's normative development/security/API/policy documents before implementation.

**Status:** Plan prepared for review; implementation has not started. Baseline main: a37747291894ac7b01ae5483af83d0dd89821015. Written design approved 2026-10-06 at 34805e7729e09b78b3b8fb5b8e40d2455d80081f.

## Global Constraints

- 小步快跑，持续迭代，关注质量、安全、一致性。 One bounded deliverable per PR; finish merge-main evidence and cleanup before the next PR.
- Self-hosted runners only. No sudo, root, Docker socket or new privilege on ordinary CI or the persistent Mac. Do not provision the production service on the Mac.
- Trusted root guest code must already be on main before certifying a target; it must not import or execute target builders, installers, applications or validation code as root.
- Fresh disposable Ubuntu 26.04 x86_64 QEMU guest, no NIC/host shares/host credentials/production secrets. Keep the pinned image/provider contract unless a separately reviewed authority prerequisite is necessary.
- Approval mutation remains real ssh-over-mcp-approvalctl outside MCP; no protocol operation, policy bypass, approval retry, framing timeout change or dynamic probe dispatch.
- Production command: /opt/ssh-over-mcp/venv/bin/python -I -B -m ssh_over_mcp.approvals.main. Mandatory installed-runtime proof permits no source adapter or ExecStart override.
- Unit: ssh-over-mcp-ledger.service. Profile values and layout are exactly design sections 3–5; unsupported mandatory enforcement blocks acceptance.
- Persistent/shared writable paths exactly /var/lib/ssh-over-mcp-ledger, /run/ssh-over-mcp-ledger-exec, /run/ssh-over-mcp-ledger-admin. Private /tmp and /var/tmp are separate permitted temporary roots, with isolation/non-persistence evidence.
- LimitCORE=0:0 and effective non-pipe kernel.core_pattern before secret generation, key access or crash/syscall canaries; no automatic production core-policy mutator.
- Type=exec, Restart=no, KillMode=control-group, SIGTERM, TimeoutStopSec=10s, final SIGKILL. Readiness means authenticated ping, not successful exec.
- Preserve fixed SSH → MCP → filesystem/profile → Task 6 → Task 7 probe; STOP_MANAGER\n / OK\n stays unchanged and Task 7 stays last.
- Never casually cancel E2E, auto-delete provider state, blindly unlink sockets or repair unknown key/database state. Cleanup failure fails the run.
- Every behavior PR requires exact-head ordinary CI and Level-3, fresh independent review without Critical/Important findings, then exact merge-main CI and Level-3. Authority bootstrap uses legacy-7a only; it does not certify 7B1.
- A new production defect, architectural deviation or unprovable mandatory criterion stops that slice for a focused RED/fix or renewed design review; no relaxed assertions, sleeps or skipped checks.

## Review Focus

1. Partial key writes/fsync failure or an existing/replaced key: fail without success, replacement, secret output or unsafe retry (Tasks 1–2).
2. Builder descendants, mutable interpreter links, forged RECORD or sealing races: fail before any systemd start, preserve the outer VM boundary (Task 5).
3. Drop-ins, command prefixes, aliases, core collectors or unexpected memberships: reject effective configuration before loading a key (Tasks 3 and 8).
4. Active/replaced socket or incomplete process/namespace inventory: recovery preserves the endpoint and refuses removal (Task 6).
5. Missing target probe, false denial attribution or incomplete result matrix: never downgrade 7B1 to legacy evidence or mark it PASS (Tasks 7–10).

## File and responsibility map

| Files | Responsibility |
| --- | --- |
| src/ssh_over_mcp/approvals/keyfile.py; approvals/bootstrap.py | Small stdlib key-write primitive; unchanged legacy bootstrap semantics |
| ops/systemd/ledger_provision.py; ssh-over-mcp-ledger-provision | Explicit fresh-install provisioning, fixed reference paths, no recovery daemon |
| requirements/e2e-build.lock | Exact/hash-locked offline build-tool dependencies, selected and verified during execution |
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

Tasks 1–8 are separate preparatory PRs, each merged and verified before the next starts. Tasks 3, 5, 6, 7 and 8 are trusted authority prerequisites; their new functions are dormant under legacy mode until Task 8 connects them. Task 9 is the target acceptance PR and uses only authority already verified on main. Task 10 records closure, adds no new capability, and repeats mandatory gates.

For **each** task, the final “ship” step means all of the following, not merely committing:

1. Run focused tests and relevant existing security regressions; record the actual RED/GREEN reason.
2. Obtain fresh independent slice review; fix Critical/Important findings with their own RED/GREEN loop.
3. Run full supported Linux regression on both Python versions, Ruff and compile checks through ordinary self-hosted CI; use git diff --check. Include new tools in lint/compile coverage without executing them as privileged code.
4. Pin PR head SHA and trusted main authority SHA. Dispatch live-local-e2e.yml **from main**, passing exact commit_sha and the task's required mode. Verify head SHA has not changed, all bindings agree, fixture coverage and cleanup PASS; then fresh final review and merge.
5. Record merge SHA, require ordinary push CI bound to that SHA, dispatch Level-3 for exactly that merge SHA using trusted main. Verify provider absence, guest cleanup, whole VM/media/bundle destruction. Only then remove clean merged/superseded branches/worktrees and proceed.

Tasks 1–8 use the complete legacy-7a matrix; no unavailable 7B1 target evidence is claimed. Tasks 9–10 require ledger-systemd-7b1 and its installed composition matrix plus all five legacy fixtures. Gate failures keep the slice open. Local Mac tests are useful focused evidence, never Linux/systemd certification; use short AF_UNIX test paths without weakening endpoint checks.

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

**Files:** Create ops/live-e2e/ledger_systemd_contract.py and ledger-systemd.service, requirements/e2e-build.lock, tests/ops/test_ledger_systemd_contract.py; modify orchestrator trusted payload list/preparation and tests/ops/test_live_e2e_orchestrator_contract.py; update ops/live-e2e/README.md.

**Interfaces:** Produce ProfileError; verify_candidate_unit(candidate: bytes) -> None; verify_effective_unit(properties: Mapping[str, str], *, core_pattern: str) -> None; require_reference_accounts() -> None. Produce constants FIXTURE_UNIT, RUNTIME_PREFIX, REQUIRED_CRITERIA: tuple[str, ...], PRODUCTION_COMMAND: tuple[str, ...]. Effective-property expectations are an explicit allowlisted snapshot, not a security score or permissive parser.

- [ ] Write test_candidate_bytes_and_effective_properties_are_both_required: reject changed bytes, duplicate directives, root command prefixes, extra Exec phases/drop-ins/aliases/environment sources, changed fragment, identity, capabilities, stop/core or sandbox properties. Assert these fail before any start. Write test_pairwise_gids_and_memberships: reject equal GIDs, client cross-membership and unexpected extra memberships. Write test_pipe_core_pattern_rejected_before_key_access. Test missing/hash-mismatched build inputs fail payload construction; persistent-host commands never run a target backend.
~~~python
with pytest.raises(ProfileError):
    verify_candidate_unit(canonical_bytes + b"ExecStartPre=/bin/sh\n")
with pytest.raises(ProfileError):
    verify_effective_unit(unexpected_dropin_properties, core_pattern="core")
assert systemctl_spy.start_calls == []
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_systemd_contract.py tests/ops/test_live_e2e_orchestrator_contract.py -q; record RED.
- [ ] Implement the canonical production unit snapshot with every section-5 setting, exact root-owned env source and only the three writable exceptions. Pin guest identities Ledger UID/GID 2210/3210, execution client 2211/3211, admin client 2212/3212, builder 2213/3213; endpoint GIDs 3297/3298. Use production names ssh-over-mcp-ledger, ssh-over-mcp-ledger-exec/admin and guest-only client/admin/builder account names; reject collisions/pre-existing state. Existing Phase 7A workload identity stays 2203/3203. Numeric IDs are guest fixture values only; production operator resolves its own distinct IDs.
- [ ] Prepare a trusted hash-locked wheelhouse for hatchling and all build dependencies compatible with the existing target backend and Python 3.14; require binary/offline installation with no resolver downloads. Package the reviewed stdlib provisioning helper/primitive from trusted main, never the target version. Inventory the pinned guest systemd/kernel/native compiler support before adding canary prerequisites. If the image lacks needed tools, stop and land a separately reviewed hash-pinned offline tool/image prerequisite with legacy gates; do not invent version/digest evidence or enable guest networking.
- [ ] Run contract/orchestrator regressions to GREEN, including existing no-network/provider-state tests. Keep the new mode inactive and describe this as authority preparation, not sandbox proof.
- [ ] Commit “Pin trusted Ledger profile and offline inputs”; ship using the common legacy gate. Record the merged authority SHA for later payload origin checks.

### Task 4: Add early installed-wheel Ledger regression on ordinary Linux CI

**Files:** Create tests/approvals/test_installed_ledger.py; modify .github/workflows/ci.yml and tests/ops/test_ci_workflow.py; consume requirements/e2e-build.lock; update tests/live/README.md.

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
- [ ] Commit “Test installed Ledger entrypoint on supported Python versions”; ship using the common legacy gate.

### Task 5: Build, attest and seal the fixed installed runtime in the guest

**Files:** Create ops/live-e2e/ledger_runtime.py and tests/ops/test_ledger_runtime.py; modify trusted payload packaging tests/list and ops/live-e2e/README.md.

**Interfaces:** Consume Task 3 constants/locked inputs. Produce frozen RuntimeEvidence(target_sha: str, wheel_sha256: str, tree_sha256: str); build_and_seal_runtime(target_sha: str) -> RuntimeEvidence; unsafe runtime state raises Task 3 ProfileError. Public guest interface accepts only validated commit binding; paths/identities/tool commands remain fixed trusted constants. Root code reads/measures files; target origin checks run non-root.

- [ ] Write test_backend_never_runs_before_verified_drop: assert exact builder identity/groups, zero Eff/Prm/Inh/Amb capability sets and NoNewPrivs=1 before wheel backend/installer. Write test_final_prefix_is_used_without_relocation: assert /opt/ssh-over-mcp/venv construction and final production path. Parameterize surviving/escaped writer, forged RECORD, modified locked dependency, writable interpreter/ancestor, .pth/editable hook, special file, hard link, unsafe symlink, set-ID/file capability and parent/inode replacement: assert refusal before unit start; measured candidate RECORD alone cannot attest dependencies.
~~~python
# runtime_fs leaves a builder descendant alive after backend exit.
with pytest.raises(ProfileError):
    build_and_seal_runtime(target_sha)
assert runtime_fs.builder_writer_still_present
assert systemctl_spy.start_calls == []
assert runtime_fs.target_root_execution_calls == []
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_runtime.py -q; require intended RED.
- [ ] Implement offline target build/install in a fixed run-owned builder cgroup with bounded output/error handling and no inherited sensitive FDs. Fail if builder descendants escape or cannot be fully inventoried/quiesced. Independently compare installed dependency content/origins with trusted hash-locked wheel inputs; bind target artifact/tree measurement to exact source SHA. Attest interpreter lineage and pyvenv.cfg, retain only explicit trusted interpreter links. Seal through descriptor-based safe filesystem operations after all writers stop; reject races instead of repairing unknown trees. Root must never execute target import/installer/RECORD validation code.
- [ ] Run runtime/contracts and legacy payload tests to GREEN, including exception/timeout cleanup. Record no claim of live composition until Task 9.
- [ ] Commit “Add trusted guest installed-runtime construction and sealing”; ship using the common legacy gate.

### Task 6: Implement fixed lifecycle and verified socket recovery authority

**Files:** Create ops/live-e2e/ledger_lifecycle.py and tests/ops/test_ledger_lifecycle.py; add it to trusted payload list; update ops/systemd/README.md with explicit recovery procedure draft and docs/audit-and-approvals.md.

**Interfaces:** Consume Task 3 profile checks and Task 5 RuntimeEvidence. Produce frozen EndpointRecord(path: Path, device: int, inode: int, uid: int, gid: int, parent_device: int, parent_inode: int); class LedgerLifecycle (unsafe operations raise Task 3 ProfileError) with prepare() -> None, start() -> None, stop() -> None, record_endpoints() -> tuple[EndpointRecord, ...], recover(record: tuple[EndpointRecord, ...]) -> None, cleanup() -> None, verify_clean() -> None. Only this trusted class invokes fixed systemctl commands; no target RPC/arguments select paths or commands.

- [ ] Write test_effective_unit_preflight_precedes_every_start: reject pre-existing/running fixture unit and unexpected loaded state before execution. Write test_recovery_requires_no_owner_and_original_inode: parameterize active PID/socket owner, inaccessible process/net namespace, incomplete inventory, replaced inode/type/owner/parent and concurrent start; assert original endpoint remains and no unlink is attempted. Write test_verified_recovery_only_unlinks_recorded_sockets: assert no database/key/directory deletion, pinned-parent recheck and fixed-unit restart. Test cleanup errors cannot become PASS.
~~~python
# lifecycle_ops reports that the recorded inode now has an active owner.
with pytest.raises(ProfileError):
    lifecycle.recover(record)
assert lifecycle_ops.unlink_calls == []
assert lifecycle_ops.endpoint_inode == record[0].inode
~~~

- [ ] Run python -m pytest tests/ops/test_ledger_lifecycle.py -q; require RED.
- [ ] Implement fixed provisioning using only merged trusted helper bytes and exact account/mode contracts. Establish guest non-pipe core policy before any target child; check hard/soft zero for key-handling helpers. Install only snapshot-equal unit, daemon-reload, verify all loaded properties before start. Recovery verifies stopped unit/empty cgroup/no Ledger UID processes and absence of socket owners across relevant namespaces, excludes competing starts, then unlinks only original run-owned sockets via pinned parents. Any uncertainty refuses. No automatic recovery, restart loop or generic root service API.
- [ ] Run lifecycle/provision/profile tests to GREEN. Require negative checks to leave state unchanged and bounded failures to preserve cleanup evidence.
- [ ] Commit “Add fixed Ledger lifecycle and verified recovery fixture”; ship using the common legacy gate. Production procedure remains an explicit trusted operator action with the same safety checks, never blind deletion.

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
- [ ] Commit “Add fixed sandbox differential and crash canaries”; ship using the common legacy gate.

### Task 8: Connect explicit trusted acceptance mode and complete result binding

**Files:** Modify .github/workflows/live-local-e2e.yml, orchestrator/bootstrap/result parsing, trusted guest gate; extend tests/ops/test_live_e2e_gate_contract.py, test_live_e2e_orchestrator_contract.py and test_ci_workflow.py; update docs/self-hosted-runner.md and tests/live/README.md.

**Interfaces:** Produce acceptance_mode workflow choice and --acceptance-mode orchestrator option, each exactly legacy-7a or ledger-systemd-7b1. Bootstrap carries trusted selected mode and exact commit in root-owned configuration. Fixed client phases are exactly pending, grant, consume, after-clean-restart, trickle and after-recovery, with admin identity only for grant. Produce verify_acceptance_result(raw: str, *, target: str, mode: str) -> None: one bounded commit/mode-bound result with exact complete criterion set, duplicate/extra/missing fields rejected. Legacy result syntax may remain only for explicit legacy mode; it cannot satisfy new-mode verification.

- [ ] Write test_target_cannot_downgrade_requested_mode: missing/deleted/renamed/failing new probe must fail new mode even if legacy passes; target env/files cannot change trusted selection. Write test_result_binds_commit_mode_and_complete_matrix: wrong SHA/mode, duplicate PASS, truncated/missing criteria or cleanup failure rejected. Write test_new_matrix_precedes_fixed_five_fixture_probe: existing five-call order unchanged; STOP_MANAGER remains last; no systemctl command appears in its control protocol. Test effective unit checks and build/drop verification precede any installed process.
~~~python
with pytest.raises(OrchestratorError):
    verify_acceptance_result(legacy_pass, target=sha, mode="ledger-systemd-7b1")
with pytest.raises(OrchestratorError):
    verify_acceptance_result(missing_recovery_result, target=sha, mode="ledger-systemd-7b1")
~~~

- [ ] Run focused gate/orchestrator/workflow tests and require RED.
- [ ] Connect only fixed phases: trusted preflight → non-root installed construction/sealing → production-unit/lifecycle/client phases → sandbox canaries → forced stop/refusal/verified recovery/client checks → clean Ledger stop/scan → unchanged full five-fixture probe → guest cleanup → bounded serial result. Root calls the target client probe only after dropping to the fixed execution/admin identities; target receives neither systemctl authority nor a parameterized privileged control channel. Reuse existing STOP_MANAGER control unchanged. Catch target failures with safe numeric categories, never raw exception strings. Explicit legacy mode remains the authority-bootstrap path and never invokes missing new target probes.
- [ ] Run all authority/payload/result contracts to GREEN and full existing regressions. Dispatch exact-head and merge-main **legacy-7a** from trusted main; after merge verify the selected mode and every new authority/helper/profile/lock originate at the merged trusted SHA. Record that new-mode target certification is still pending.
- [ ] Commit “Bind trusted Ledger acceptance mode and fixed lifecycle”; ship this final authority prerequisite using the common legacy gate. Freeze these authority bytes for Task 9; later changes require another independent prerequisite.

### Task 9: Ship the target unit and full installed Ledger acceptance probe

**Files:** Create ops/systemd/ssh-over-mcp-ledger.service and ledger.env.example; modify ops/systemd/README.md; create tests/live/ledger_systemd_support.py, scripts/run-live-ledger-systemd-probe.py, tests/ops/test_ledger_systemd_probe_contract.py and test_ledger_systemd_unit.py; update docs/security-model.md, docs/audit-and-approvals.md, tests/live/README.md. No trusted authority/gate/workflow change in this PR.

**Interfaces:** Consume all authority on main from Task 8, existing SecurityLedgerClient and real approvalctl. Keep no-core preflight and runtime-origin attestations ahead of secret-bearing service phases. Produce run_client_phase(phase: str) -> None in support and probe main(argv: Sequence[str] | None = None) -> int, with invalid phases returning 64 and assertion failures returning fixed safe nonzero categories. Phase is a closed allowlist fixed by the trusted lifecycle: pending, grant, consume, after-clean-restart, trickle, after-recovery. Trusted orchestration runs pending/consume/restart/trickle checks as the execution client and grant as the distinct admin client. Grant launches the real installed approvalctl process for the bounded run-owned approval ID; it cannot impersonate admin from the execution-client process. It selects non-root assertions only, never unit/identity/path/privileged action. The authority owns the start/stop/recovery ordering. Non-secret checkpoint data is bounded, run-owned and not accepted as authority for root cleanup.

- [ ] Write test_reference_unit_matches_already_trusted_snapshot and test_probe_phase_allowlist_has_no_root_controls: copied profile bytes exactly match trusted main, production command has no override, bad phases rejected with safe status. Define live assertions: authenticated ping; WAL/FULL audit persistence; real CLI pending→grant→consume; replay and argv/env binding denial; clean restart preservation; exact runtime origins/groups/caps; cross-direction DAC denial independently of peer denial. Existing approval/deny protocol tests remain unchanged.
~~~python
assert main(["arbitrary-systemctl-command"]) == 64
assert target_unit.read_bytes() == trusted_unit.read_bytes()
assert privilege_spy.systemctl_calls == []
assert privilege_spy.admin_impersonation_calls == []
~~~

- [ ] Run the new static/probe contracts to intended RED. Then dispatch one exact diagnostic target through trusted-main ledger-systemd-7b1 to establish the missing acceptance RED; keep bounded stage codes, no secrets, and do not alter root authority in this target to make it pass.
- [ ] Implement the minimal fixed-profile reference/unit/env and non-root client phases. Pending phase seeds audit and pending approval requests; grant and consume establish granted/consumed states and a non-secret preservation checkpoint before the lifecycle fault. A paused partial frame proves graceful stop; a separately authorized trickling connection forces the 10s deadline/SIGKILL path. After-recovery asserts ping, database clean open, unchanged key through trusted identity/digest checks kept out of public output, audit preserved, pending/granted/consumed states preserved except natural expiry; choose existing supported approval TTLs/checkpoints so expiry is recorded and does not erase the intended pending/granted/consumed comparisons; never extend TTL/resurrect consumption. Seal Ledger before offline final audit reads; do not reintroduce live-WAL visibility dependence. Scan secrets at all required phases using current retention guarantees.
- [ ] Complete operator docs: exact identities/memberships/layout, strict provisioning/core preflight, trusted installed release, systemd effective validation, readiness, clean restart, forced-stop verified recovery, rollback stop/preserve data; no shell key recipe, blind unlink or automatic fallback. Document initial Ubuntu/x86 support and out-of-scope collectors/architectures/services.
- [ ] Run all focused target/approval/static/security tests and full ordinary self-hosted regression. Require the early installed-wheel test on Python 3.13 and 3.14. Obtain fresh adversarial review, then exact-head **ledger-systemd-7b1** PASS with actual installed production command, full criterion matrix, all five Phase 7A fixtures and cleanup. Any stage failure gets one root-cause RED/minimal fix, not delays/retries. Repeat only after changed head/failure evidence warrants it.
- [ ] Commit “Validate installed Ledger systemd sandbox end to end”; ship with the mandatory new-mode common gate. Require exact merge SHA ordinary CI and full new-mode E2E PASS before calling implementation complete. Do not mark Phase 7B1 closed yet.

### Task 10: Whole-slice review, evidence and exact-revision closure

**Files:** Create docs/phase7b1-closure-evidence.md and tests/ops/test_phase7b1_closure_evidence.py; update docs/development-plan.md, docs/self-hosted-runner.md, tests/live/README.md, approved spec evidence/status. No new capability.

**Interfaces:** Consume Task 3 REQUIRED_CRITERIA and Task 8 exact commit/mode-bound results. Produce one evidence table with one row per criterion: source invariant, focused RED/GREEN/static/integration test, exact-head live run, exact merge-main live run, review and cleanup evidence. Every design section-7 row must be represented; do not copy Phase 7A's count or assert planned tests are live evidence.

- [ ] Write test_closure_requires_current_complete_evidence: reject missing criterion, legacy-mode substitute, mismatched SHA/run, source-only composition claim, absent recovery/key/audit preservation or cleanup evidence; require existing five-fixture coverage and early installed-wheel results. Run python -m pytest tests/ops/test_phase7b1_closure_evidence.py -q and record missing-evidence RED.
- [ ] Populate evidence from actual successful runs; record authority/head/merge bindings, guest/kernel/systemd/QEMU versions, pinned image digest, unit/runtime artifact digests without secrets, resolved fixture accounts/groups, exact tests/counts, review results and guest/provider/VM cleanup. No placeholder PASS. Update status only to implementation complete while closure gates remain pending.
- [ ] Obtain fresh whole-Phase-7B1 adversarial review against every acceptance row, Phase 5 approval/audit invariants, Phase 6 credential boundaries and ADRs 0005–0009. Search root-before-drop, generic privileged interfaces, stale state/TOCTOU, client/group confusion, unauthenticated/network bypass, incomplete attribution, crash retention and acceptance downgrade. Findings loop through RED/minimal GREEN/full regression/fresh review; behavioral fixes are separate small PRs, not hidden in closure docs.
~~~python
# Parsed evidence is test-owned; verify row bindings, not substring PASS claims.
assert set(evidence.rows) == set(REQUIRED_CRITERIA)
assert evidence.head.mode == evidence.merge.mode == "ledger-systemd-7b1"
assert evidence.head.commit == evidence.reviewed_head
assert evidence.merge.commit == evidence.merge_sha
assert evidence.merge.provider_absent and evidence.merge.vm_destroyed
~~~

- [ ] Run closure contracts to GREEN, full ordinary CI and exact-head mandatory ledger-systemd-7b1 from trusted main with all five legacy fixtures and cleanup. Fresh final review must have zero Critical/Important findings before merge.
- [ ] Merge and pin the exact merge SHA; require ordinary push CI including both installed-wheel tests and exact-merge mandatory 7B1 Level-3 PASS. Record immutable run links/bindings; do not invent a self-referential merge SHA inside the pre-merge commit. If an additional closure-record commit is needed, it repeats closure-level exact-head/merge gates.
- [ ] Audit then remove only clean merged/superseded branches/worktrees; preserve dirty work. Prune refs and verify root main equals origin/main and is clean, no temporary QEMU/orchestrator/guest/provider state, no temp bare repo/bundle/media/runtime remnants. Dedicated runner/account intentionally remain. Mark Phase 7B1 closed only with current evidence and cleanup; other Phase 7B capabilities remain unimplemented and separately designed.

## Plan self-review and execution record

Prepared 2026-10-06; checked against all ten design sections and sixteen acceptance rows. Tasks 1–2 cover key semantics; 3/8 unit/identity/trust; 4/5 installed artifacts; 6 recovery/lifecycle; 7 sandbox/crash attribution; 9 real behavior/composition and Phase 7A preservation; 10 exact evidence/cleanup. Interfaces above are the implementation contract, not claims that these modules exist today.

Before executing a task, write its actual baseline, intended RED, minimal GREEN, review and exact-head/merge evidence into the PR or a linked evidence record. Do not tick a task complete on mocked authority tests alone. The plan does not grant deployment to a production host, expand the STOP_MANAGER channel or make later Phase 7B slices part of this work.
