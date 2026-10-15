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


def _text_tuple(values: object) -> bool:
    return type(values) is tuple and all(type(v) is str for v in values)


def _string_pairs(values: object) -> bool:
    return (
        type(values) is tuple
        and all(
            type(pair) is tuple
            and len(pair) == 2
            and type(pair[0]) is str
            and type(pair[1]) is str
            for pair in values
        )
    )


def _int_triple(values: object) -> bool:
    return type(values) is tuple and len(values) == 3 and all(
        type(v) is int for v in values
    )


def validate_run(
    run: RunIdentity,
    checkout: CheckoutEvidence,
    job: WorkflowJobEvidence,
    runner: RunnerIdentity,
) -> tuple[str, ...]:
    """Evaluate untrusted field values, never prove real GitHub/host identity."""
    if not all(
        (
            type(run) is RunIdentity,
            type(checkout) is CheckoutEvidence,
            type(job) is WorkflowJobEvidence,
            type(runner) is RunnerIdentity,
        )
    ):
        return ("EVIDENCE_INVALID",)

    # Fail each typed domain BEFORE comparisons: dataclasses do not enforce
    # constructor types, and arbitrary rich comparisons can be malicious.
    if not (
        all(type(v) is str for v in (
            run.repository, run.event, run.ref, run.github_sha
        ))
        and _string_pairs(run.inputs)
    ):
        return ("RUN_CONTEXT_INVALID",)
    if not (
        all(type(v) is str for v in (
            checkout.head_sha, checkout.checkout_uses, checkout.checkout_ref
        ))
        and all(type(v) is bool for v in (
            checkout.clean, checkout.persist_credentials, checkout.checkout_clean,
            checkout.credential_env_present, checkout.credential_helper_present,
            checkout.complete,
        ))
        and type(checkout.fetch_depth) is int
    ):
        return ("CHECKOUT_INVALID",)
    if not (
        _string_pairs(job.permissions)
        and _text_tuple(job.runs_on)
        and type(job.concurrency_group) is str
        and type(job.cancel_in_progress) is bool
        and type(job.complete) is bool
    ):
        return ("JOB_INVALID",)
    if not (
        all(type(v) is str for v in (
            runner.user, runner.home, runner.platform, runner.arch
        ))
        and all(_int_id(v) for v in (
            runner.uid, runner.euid, runner.account_uid, runner.gid,
            runner.egid, runner.account_primary_gid, runner.admin_gid,
        ))
        and type(runner.supplementary_gids) is tuple
        and all(_int_id(v) for v in runner.supplementary_gids)
        and _text_tuple(runner.group_names)
        and type(runner.complete) is bool
    ):
        return ("RUNNER_INVALID",)

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
    if type(inventory) is not InterpreterInventory or type(policy) is not InterpreterTrustPolicy:
        return ("EVIDENCE_INVALID",)
    if not (
        all(type(v) is str for v in (
            inventory.resolved_path, inventory.sys_executable, inventory.arch
        ))
        and _int_triple(inventory.version)
        and type(inventory.complete) is bool
        and type(inventory.chain) is tuple
        and all(type(v) is str for v in (policy.policy_label, policy.expected_path))
        and _int_triple(policy.version)
        and type(policy.allowed_owner_uid) is int
        and type(policy.allowed_owner_gid) is int
        and _text_tuple(policy.approved_chain)
    ):
        return ("INTERPRETER_INVALID",)
    for witness in inventory.chain:
        if type(witness) is not PathWitness or not (
            all(type(v) is str for v in (
                witness.name, witness.acl_state, witness.kind
            ))
            and (witness.target is None or type(witness.target) is str)
            and all(_int_id(v) for v in (
                witness.dev, witness.ino, witness.uid, witness.gid
            ))
            and type(witness.mode) is int
            and type(witness.writable_by_uid502) is bool
        ):
            return ("INTERPRETER_INVALID",)

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


@dataclass(frozen=True, slots=True)
class NamespaceEdge:
    name: str
    original: tuple[int, int, int, int, int]
    current: tuple[int, int, int, int, int]
    acl_state: str
    nofollow: bool


@dataclass(frozen=True, slots=True)
class NamespaceEvidence:
    verification_root: str
    protected_root: str
    native_temp_parent: str
    edges: tuple[NamespaceEdge, ...]
    complete: bool
    foreign_entry: bool
    quarantine_present: bool
    alias_disjoint: bool


@dataclass(frozen=True, slots=True)
class ProviderInventory:
    marker_state: str
    marker_chain_pinned: bool
    qemu_state: str
    qemu_count: int | None
    protected_clean: bool
    legacy_private_clean: bool
    legacy_native_clean: bool
    complete: bool


_VERIFICATION_ROOT = (
    "/Users/gha-e2e-orchestrator/Library/Application Support/"
    "ssh-over-mcp-uid502-verification-v1"
)
_PROTECTED_ROOT = (
    "/Users/gha-e2e-orchestrator/Library/Application Support/"
    "ssh-over-mcp-e2e/staging-v1"
)
_NAMESPACE_CHAIN = (
    "gha-e2e-orchestrator", "Library", "Application Support",
    "ssh-over-mcp-uid502-verification-v1",
)


_NATIVE_TEMP_CANONICAL = re.compile(
    r"/private/var/folders/[a-z0-9]{2}/[a-z0-9_]{1,255}/T/"
)


def _namespace_identity(values: object, *, private: bool) -> bool:
    # 0700/0755 are allowed on shared ancestors; private root remains 0700.
    return (
        type(values) is tuple
        and len(values) == 5
        and all(_int_id(v) for v in values)
        and values[0] > 0
        and values[1] > 0
        and values[2] == 502
        and values[4] in ((0o40700,) if private else (0o40700, 0o40755))
    )


def validate_namespace(namespace: NamespaceEvidence) -> tuple[str, ...]:
    """Only compare synthetic claims; lexical checks do not prove real APFS aliases."""
    if type(namespace) is not NamespaceEvidence:
        return ("EVIDENCE_INVALID",)
    if not (
        all(type(v) is str for v in (
            namespace.verification_root, namespace.protected_root,
            namespace.native_temp_parent,
        ))
        and all(type(v) is bool for v in (
            namespace.complete, namespace.foreign_entry,
            namespace.quarantine_present, namespace.alias_disjoint,
        ))
        and type(namespace.edges) is tuple
    ):
        return ("NAMESPACE_INVALID",)
    if (
        namespace.verification_root != _VERIFICATION_ROOT
        or namespace.protected_root != _PROTECTED_ROOT
        or _NATIVE_TEMP_CANONICAL.fullmatch(namespace.native_temp_parent) is None
        or namespace.complete is not True
        or namespace.foreign_entry is not False
        or namespace.quarantine_present is not False
        or namespace.alias_disjoint is not True
        or type(namespace.edges) is not tuple
        or len(namespace.edges) != len(_NAMESPACE_CHAIN)
    ):
        return ("NAMESPACE_INVALID",)

    witnessed = []
    for index, (edge, component) in enumerate(zip(namespace.edges, _NAMESPACE_CHAIN)):
        if type(edge) is not NamespaceEdge or not (
            type(edge.name) is str
            and type(edge.acl_state) is str
            and type(edge.nofollow) is bool
            and _namespace_identity(edge.original, private=index == len(_NAMESPACE_CHAIN) - 1)
            and _namespace_identity(edge.current, private=index == len(_NAMESPACE_CHAIN) - 1)
        ):
            return ("NAMESPACE_INVALID",)
        if (
            edge.name != component
            or edge.original != edge.current
            or edge.acl_state != "verified_safe"
            or edge.nofollow is not True
        ):
            return ("NAMESPACE_INVALID",)
        witnessed.append((edge.original[0], edge.original[1]))
    if len(set(witnessed)) != len(witnessed):
        return ("NAMESPACE_INVALID",)
    return ()


def validate_provider(provider: ProviderInventory) -> tuple[str, ...]:
    """Synthetic complete-empty claims are not authenticated process evidence."""
    if type(provider) is not ProviderInventory:
        return ("EVIDENCE_INVALID",)
    if not (
        type(provider.marker_state) is str
        and type(provider.qemu_state) is str
        and (provider.qemu_count is None or type(provider.qemu_count) is int)
        and all(type(v) is bool for v in (
            provider.marker_chain_pinned, provider.protected_clean,
            provider.legacy_private_clean, provider.legacy_native_clean,
            provider.complete,
        ))
    ):
        return ("PROVIDER_INVALID",)
    if (
        provider.marker_state != "absent_no_follow"
        or provider.marker_chain_pinned is not True
        or provider.qemu_state != "complete_empty"
        or type(provider.qemu_count) is not int
        or provider.qemu_count != 0
        or provider.protected_clean is not True
        or provider.legacy_private_clean is not True
        or provider.legacy_native_clean is not True
        or provider.complete is not True
    ):
        return ("PROVIDER_INVALID",)
    return ()


@dataclass(frozen=True, slots=True)
class ContractEvidence:
    run: RunIdentity
    checkout: CheckoutEvidence
    job: WorkflowJobEvidence
    runner: RunnerIdentity
    interpreter: InterpreterInventory
    namespace: NamespaceEvidence
    provider: ProviderInventory


@dataclass(frozen=True, slots=True)
class ContractResult:
    status: str
    violations: tuple[str, ...]


_FIXED_CODES = frozenset({
    "RUN_CONTEXT_INVALID", "CHECKOUT_INVALID", "JOB_INVALID",
    "RUNNER_INVALID", "INTERPRETER_INVALID", "INTERPRETER_TRUST_UNAPPROVED",
    "NAMESPACE_INVALID", "PROVIDER_INVALID", "EVIDENCE_INVALID",
})


def assess(
    evidence: ContractEvidence,
    *,
    interpreter_policy: InterpreterTrustPolicy | None = None,
) -> ContractResult:
    """Classify *synthetic* evidence only; never authorize native execution."""
    refuse = ContractResult("CONTRACT_REFUSED", ("EVIDENCE_INVALID",))
    if type(evidence) is not ContractEvidence:
        return refuse
    if not all((
        type(evidence.run) is RunIdentity,
        type(evidence.checkout) is CheckoutEvidence,
        type(evidence.job) is WorkflowJobEvidence,
        type(evidence.runner) is RunnerIdentity,
        type(evidence.interpreter) is InterpreterInventory,
        type(evidence.namespace) is NamespaceEvidence,
        type(evidence.provider) is ProviderInventory,
    )):
        return refuse

    try:
        codes = (
            *validate_run(evidence.run, evidence.checkout, evidence.job, evidence.runner),
            *validate_interpreter(evidence.interpreter, interpreter_policy),
            *validate_namespace(evidence.namespace),
            *validate_provider(evidence.provider),
        )
        if (
            len(codes) > 32
            or not all(type(code) is str and code in _FIXED_CODES for code in codes)
        ):
            return refuse
        violations = tuple(sorted(set(codes)))
    except (AttributeError, IndexError, KeyError, OverflowError, TypeError, ValueError):
        return refuse
    return ContractResult(
        "CONTRACT_REFUSED" if violations else "CONTRACT_ELIGIBLE_FOR_HOST_PROBE",
        violations,
    )
