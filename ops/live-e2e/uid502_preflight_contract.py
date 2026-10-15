"""Pure, UNAUTHENTICATED UID502 preflight schema checks.

Never use caller-supplied eligibility as live admission, a host permission,
UID502 acceptance, or evidence that a real filesystem/process was inspected.
No I/O, subprocess, CLI entrypoint or live host collector exists here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RunIdentity:
    repository: str
    event: str
    ref: str
    github_sha: str
    inputs: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class CheckoutEvidence:
    head_sha: str
    clean: bool
    checkout_uses: str
    checkout_ref: str
    persist_credentials: bool
    checkout_clean: bool
    fetch_depth: int
    credential_env_present: bool
    credential_helper_present: bool
    complete: bool


@dataclass(frozen=True, slots=True)
class WorkflowJobEvidence:
    permissions: tuple[tuple[str, str], ...]
    runs_on: tuple[str, ...]
    concurrency_group: str
    cancel_in_progress: bool
    complete: bool


@dataclass(frozen=True, slots=True)
class RunnerIdentity:
    user: str
    home: str
    uid: int
    euid: int
    account_uid: int
    gid: int
    egid: int
    account_primary_gid: int
    supplementary_gids: tuple[int, ...]
    admin_gid: int
    group_names: tuple[str, ...]
    platform: str
    arch: str
    complete: bool


_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
_LABELS = ("self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator")


def _int_id(value: object) -> bool:
    return type(value) is int and value >= 0


def validate_run(
    run: RunIdentity,
    checkout: CheckoutEvidence,
    job: WorkflowJobEvidence,
    runner: RunnerIdentity,
) -> tuple[str, ...]:
    """Evaluate untrusted field values, never prove real GitHub/host identity."""
    if not all(
        (
            isinstance(run, RunIdentity),
            isinstance(checkout, CheckoutEvidence),
            isinstance(job, WorkflowJobEvidence),
            isinstance(runner, RunnerIdentity),
        )
    ):
        return ("EVIDENCE_INVALID",)

    failed: list[str] = []
    if (
        run.repository != "zhangyuz/ssh-over-mcp"
        or run.event != "workflow_dispatch"
        or run.ref != "refs/heads/main"
        or not isinstance(run.github_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", run.github_sha) is None
        or type(run.inputs) is not tuple
        or run.inputs != ()
    ):
        failed.append("RUN_CONTEXT_INVALID")
    if (
        checkout.head_sha != run.github_sha
        or checkout.clean is not True
        or checkout.checkout_uses != _CHECKOUT
        or checkout.checkout_ref != "${{ github.sha }}"
        or checkout.persist_credentials is not False
        or checkout.checkout_clean is not True
        or type(checkout.fetch_depth) is not int
        or checkout.fetch_depth != 1
        or checkout.credential_env_present is not False
        or checkout.credential_helper_present is not False
        or checkout.complete is not True
    ):
        failed.append("CHECKOUT_INVALID")
    if (
        job.permissions != (("contents", "read"),)
        or type(job.permissions) is not tuple
        or type(job.runs_on) is not tuple
        or job.runs_on != _LABELS
        or job.concurrency_group != "live-local-e2e"
        or job.cancel_in_progress is not False
        or job.complete is not True
    ):
        failed.append("JOB_INVALID")
    ids = (runner.uid, runner.euid, runner.account_uid, runner.gid,
           runner.egid, runner.account_primary_gid, runner.admin_gid)
    groups = runner.supplementary_gids
    if (
        runner.user != "gha-e2e-orchestrator"
        or runner.home != "/Users/gha-e2e-orchestrator"
        or not all(_int_id(v) for v in ids)
        or any(v != 502 for v in (runner.uid, runner.euid, runner.account_uid))
        or runner.admin_gid != 80
        or type(groups) is not tuple
        or not groups
        or not all(_int_id(g) for g in groups)
        or groups != tuple(sorted(set(groups)))
        or 80 in (runner.gid, runner.egid, runner.account_primary_gid, *groups)
        or type(runner.group_names) is not tuple
        or runner.platform != "Darwin"
        or runner.arch != "x86_64"
        or runner.complete is not True
    ):
        failed.append("RUNNER_INVALID")
    return tuple(failed)


@dataclass(frozen=True, slots=True)
class PathWitness:
    name: str
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    acl_state: str
    kind: str
    target: str | None
    writable_by_uid502: bool


@dataclass(frozen=True, slots=True)
class InterpreterInventory:
    resolved_path: str
    sys_executable: str
    version: tuple[int, int, int]
    arch: str
    complete: bool
    chain: tuple[PathWitness, ...]


@dataclass(frozen=True, slots=True)
class InterpreterTrustPolicy:
    policy_label: str
    expected_path: str
    version: tuple[int, int, int]
    allowed_owner_uid: int
    allowed_owner_gid: int
    approved_chain: tuple[str, ...]


def validate_interpreter(
    inventory: InterpreterInventory, policy: InterpreterTrustPolicy | None
) -> tuple[str, ...]:
    """Validate a fictional schema fixture; current real Homebrew Python is BLOCKED."""
    from pathlib import PurePosixPath

    if policy is None:
        return ("INTERPRETER_TRUST_UNAPPROVED",)
    if not isinstance(inventory, InterpreterInventory) or not isinstance(
        policy, InterpreterTrustPolicy
    ):
        return ("EVIDENCE_INVALID",)

    # There is intentionally *no* policy path for running the real UID501/admin
    # interpreter; a future trusted collector + immutable installation needs
    # separate operator/security approval.
    if (
        policy.policy_label != "TEST_ONLY_NOT_AUTHORITY"
        or policy.expected_path != "/test-only/uid502-pinned/python3.13"
        or inventory.resolved_path != policy.expected_path
        or inventory.sys_executable != policy.expected_path
        or inventory.version != (3, 13, 16)
        or any(type(i) is not int for i in inventory.version)
        or policy.version != inventory.version
        or inventory.arch != "x86_64"
        or inventory.complete is not True
        or policy.allowed_owner_uid != 0
        or policy.allowed_owner_gid != 0
        or type(inventory.chain) is not tuple
        or type(policy.approved_chain) is not tuple
        or policy.approved_chain != PurePosixPath(policy.expected_path).parts
        or len(inventory.chain) != len(policy.approved_chain)
    ):
        return ("INTERPRETER_INVALID",)

    for i, (witness, name) in enumerate(zip(inventory.chain, policy.approved_chain)):
        if not isinstance(witness, PathWitness):
            return ("INTERPRETER_INVALID",)
        leaf = i == len(inventory.chain) - 1
        expected_type = 0o100000 if leaf else 0o040000
        if (
            witness.name != name
            or not all(_int_id(x) for x in (witness.dev, witness.ino, witness.uid, witness.gid))
            or witness.dev == 0
            or witness.ino == 0
            or witness.uid != policy.allowed_owner_uid
            or witness.gid != policy.allowed_owner_gid
            or type(witness.mode) is not int
            or witness.mode & 0o170000 != expected_type
            or witness.mode & 0o022 != 0
            or witness.acl_state != "verified_safe"
            or witness.kind != ("regular" if leaf else "directory")
            or witness.target is not None
            or witness.writable_by_uid502 is not False
        ):
            return ("INTERPRETER_INVALID",)
    return ()
