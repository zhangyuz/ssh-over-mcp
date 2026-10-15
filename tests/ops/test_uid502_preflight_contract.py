"""Inert UID502 preflight: synthetic evidence never confers host authority."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/uid502_preflight_contract.py"


@pytest.fixture(scope="module")
def contract():
    spec = importlib.util.spec_from_file_location("_uid502_inert_contract_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


@pytest.fixture()
def inputs(contract):
    return (
        contract.RunIdentity(
            "zhangyuz/ssh-over-mcp", "workflow_dispatch", "refs/heads/main", "a" * 40, ()
        ),
        contract.CheckoutEvidence(
            "a" * 40,
            True,
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "${{ github.sha }}",
            False,
            True,
            1,
            False,
            False,
            True,
        ),
        contract.WorkflowJobEvidence(
            (("contents", "read"),),
            ("self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"),
            "live-local-e2e",
            False,
            True,
        ),
        contract.RunnerIdentity(
            "gha-e2e-orchestrator",
            "/Users/gha-e2e-orchestrator",
            502, 502, 502,
            20, 20, 20, (20,), 80, ("staff",),
            "Darwin", "x86_64", True,
        ),
    )


def test_trusted_run_contract(contract, inputs):
    assert contract.validate_run(*inputs) == ()
    for obj in inputs:
        assert obj.__dataclass_params__.frozen
        with pytest.raises(AttributeError):
            setattr(obj, next(iter(obj.__dataclass_fields__)), None)


@pytest.mark.parametrize(
    ("part", "attr", "invalid", "expected"),
    [
        (0, "repository", "someone/other", "RUN_CONTEXT_INVALID"),
        (0, "event", "pull_request", "RUN_CONTEXT_INVALID"),
        (0, "event", "workflow_run", "RUN_CONTEXT_INVALID"),
        (0, "ref", "refs/pull/9/head", "RUN_CONTEXT_INVALID"),
        (0, "github_sha", "A" * 40, "RUN_CONTEXT_INVALID"),
        (0, "github_sha", "a" * 39, "RUN_CONTEXT_INVALID"),
        (0, "github_sha", "z" * 40, "RUN_CONTEXT_INVALID"),
        (0, "inputs", (("commit_sha", "a" * 40),), "RUN_CONTEXT_INVALID"),
        (1, "head_sha", "b" * 40, "CHECKOUT_INVALID"),
        (1, "clean", False, "CHECKOUT_INVALID"),
        (1, "checkout_uses", "actions/checkout@v4", "CHECKOUT_INVALID"),
        (1, "checkout_ref", "${{ github.event.pull_request.head.sha }}", "CHECKOUT_INVALID"),
        (1, "persist_credentials", True, "CHECKOUT_INVALID"),
        (1, "checkout_clean", False, "CHECKOUT_INVALID"),
        (1, "fetch_depth", 2, "CHECKOUT_INVALID"),
        (1, "fetch_depth", True, "CHECKOUT_INVALID"),
        (1, "credential_env_present", True, "CHECKOUT_INVALID"),
        (1, "credential_helper_present", True, "CHECKOUT_INVALID"),
        (1, "complete", False, "CHECKOUT_INVALID"),
        (3, "user", "someone", "RUNNER_INVALID"),
        (3, "home", "/tmp", "RUNNER_INVALID"),
        (3, "uid", 0, "RUNNER_INVALID"),
        (3, "euid", 0, "RUNNER_INVALID"),
        (3, "account_uid", 501, "RUNNER_INVALID"),
        (3, "uid", True, "RUNNER_INVALID"),
        (3, "platform", "Linux", "RUNNER_INVALID"),
        (3, "arch", "arm64", "RUNNER_INVALID"),
        (3, "complete", False, "RUNNER_INVALID"),
    ],
)
def test_untrusted_inputs_refuse(contract, inputs, part, attr, invalid, expected):
    changed = list(inputs)
    changed[part] = replace(inputs[part], **{attr: invalid})
    result = contract.validate_run(*changed)
    assert expected in result
    assert all(code.isupper() and code.replace("_", "").isalpha() for code in result)


@pytest.mark.parametrize(
    ("attr", "invalid"),
    [
        ("permissions", (("contents", "write"),)),
        ("permissions", (("contents", "read"), ("actions", "write"))),
        ("runs_on", ("self-hosted", "macOS", "X64")),
        ("runs_on", ("macOS", "self-hosted", "X64", "ssh-over-mcp-e2e-orchestrator")),
        ("runs_on", ("self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator", "extra")),
        ("concurrency_group", "different"),
        ("cancel_in_progress", True),
        ("cancel_in_progress", 0),
        ("complete", False),
    ],
)
def test_workflow_job_authority_refuses(contract, inputs, attr, invalid):
    run, checkout, job, runner = inputs
    result = contract.validate_run(run, checkout, replace(job, **{attr: invalid}), runner)
    assert "JOB_INVALID" in result


@pytest.mark.parametrize(
    ("attr", "invalid"),
    [
        ("gid", 80),
        ("egid", 80),
        ("account_primary_gid", 80),
        ("supplementary_gids", (20, 80)),
        ("supplementary_gids", ()),
        ("supplementary_gids", (20, 20)),
        ("supplementary_gids", (50, 20)),
        ("supplementary_gids", (True,)),
        ("supplementary_gids", (-1,)),
        ("gid", -1),
        ("egid", True),
        ("admin_gid", 81),
        ("admin_gid", True),
    ],
)
def test_numeric_admin_gid_refuses(contract, inputs, attr, invalid):
    run, checkout, job, runner = inputs
    changed = replace(runner, **{attr: invalid}, group_names=("staff",))
    assert "RUNNER_INVALID" in contract.validate_run(run, checkout, job, changed)


# Task 2: positive example is fictional and never a real interpreter approval.
def _safe_interpreter(contract):
    from pathlib import PurePosixPath

    path = "/test-only/uid502-pinned/python3.13"
    names = PurePosixPath(path).parts
    chain = tuple(
        contract.PathWitness(
            name, i + 10, i + 100, 0, 0,
            0o100755 if i == len(names) - 1 else 0o40755,
            "verified_safe",
            "regular" if i == len(names) - 1 else "directory",
            None, False,
        )
        for i, name in enumerate(names)
    )
    return (
        contract.InterpreterInventory(path, path, (3, 13, 16), "x86_64", True, chain),
        contract.InterpreterTrustPolicy(
            "TEST_ONLY_NOT_AUTHORITY", path, (3, 13, 16), 0, 0, names
        ),
    )


def test_interpreter_unapproved_by_default(contract):
    inv, _ = _safe_interpreter(contract)
    assert contract.validate_interpreter(inv, None) == ("INTERPRETER_TRUST_UNAPPROVED",)


def test_interpreter_synthetic_safe_contract(contract):
    inv, policy = _safe_interpreter(contract)
    assert contract.validate_interpreter(inv, policy) == ()
    assert "/test-only/" in inv.resolved_path
    assert policy.policy_label == "TEST_ONLY_NOT_AUTHORITY"


def test_interpreter_actual_observed_candidate_refused(contract):
    from pathlib import PurePosixPath

    # Actual observed ancestry includes UID501:GID80 0775 on Cellar.
    path = ("/usr/local/Cellar/python@3.13/3.13.16/Frameworks/"
            "Python.framework/Versions/3.13/bin/python3.13")
    names = PurePosixPath(path).parts
    chain = []
    for i, name in enumerate(names):
        operator_owned = i >= names.index("Cellar")
        mode = 0o100755 if i == len(names) - 1 else 0o40755
        if name == "Cellar":
            mode = 0o40775
        chain.append(contract.PathWitness(
            name, i + 10, i + 100, 501 if operator_owned else 0,
            80 if operator_owned else 0, mode, "verified_safe",
            "regular" if i == len(names) - 1 else "directory", None, False,
        ))
    observed = contract.InterpreterInventory(
        path, path, (3, 13, 16), "x86_64", True, tuple(chain)
    )
    optimistic = contract.InterpreterTrustPolicy(
        "TEST_ONLY_NOT_AUTHORITY", path, (3, 13, 16), 501, 80, names
    )
    assert "INTERPRETER_INVALID" in contract.validate_interpreter(observed, optimistic)


@pytest.mark.parametrize(
    ("part", "attribute", "value"),
    [
        ("inv", "resolved_path", "/usr/local/bin/python3"),
        ("inv", "sys_executable", "/bin/python3"),
        ("inv", "version", (3, 12, 5)),
        ("inv", "version", (3, True, 16)),
        ("inv", "arch", "arm64"),
        ("inv", "complete", False),
        ("inv", "chain", ()),
        ("policy", "policy_label", ""),
        ("policy", "policy_label", "approved"),
        ("policy", "allowed_owner_uid", 501),
        ("policy", "allowed_owner_gid", 80),
        ("policy", "expected_path", "/tmp/python3"),
    ],
)
def test_interpreter_chain_tamper_refuses(contract, part, attribute, value):
    inv, policy = _safe_interpreter(contract)
    if part == "inv":
        inv = replace(inv, **{attribute: value})
    else:
        policy = replace(policy, **{attribute: value})
    assert "INTERPRETER_INVALID" in contract.validate_interpreter(inv, policy)


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("name", "renamed"),
        ("dev", 0),
        ("ino", 0),
        ("uid", 502),
        ("gid", 80),
        ("mode", 0o40775),
        ("mode", 0o120777),
        ("acl_state", "unknown"),
        ("kind", "symlink"),
        ("target", "/foreign"),
        ("writable_by_uid502", True),
    ],
)
def test_interpreter_chain_witness_tamper_refuses(contract, attribute, value):
    inv, policy = _safe_interpreter(contract)
    bad = replace(inv.chain[1], **{attribute: value})
    inv = replace(inv, chain=(*inv.chain[:1], bad, *inv.chain[2:]))
    assert "INTERPRETER_INVALID" in contract.validate_interpreter(inv, policy)


def test_interpreter_wrong_chain_order_refuses(contract):
    inv, policy = _safe_interpreter(contract)
    inv = replace(inv, chain=tuple(reversed(inv.chain)))
    assert "INTERPRETER_INVALID" in contract.validate_interpreter(inv, policy)


# Task 3: all "FD witnesses" below are untrusted SYNTHETIC records.
def _safe_namespace(contract):
    names = ("gha-e2e-orchestrator", "Library", "Application Support",
             "ssh-over-mcp-uid502-verification-v1")
    edges = tuple(
        contract.NamespaceEdge(
            name, (1, i + 50, 502, 20, 0o40700),
            (1, i + 50, 502, 20, 0o40700), "verified_safe", True
        )
        for i, name in enumerate(names)
    )
    return contract.NamespaceEvidence(
        "/Users/gha-e2e-orchestrator/Library/Application Support/"
        "ssh-over-mcp-uid502-verification-v1",
        "/Users/gha-e2e-orchestrator/Library/Application Support/"
        "ssh-over-mcp-e2e/staging-v1",
        "/private/var/folders/test/T/",
        edges, True, False, False, True,
    )


def _safe_provider(contract):
    return contract.ProviderInventory(
        "absent_no_follow", True, "complete_empty", 0, True, True, True, True
    )


def test_namespace_synthetic_fixed_edges_are_consistent(contract):
    assert contract.validate_namespace(_safe_namespace(contract)) == ()


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("verification_root", "/private/tmp/ssh-over-mcp-e2e-unsafe"),
        ("verification_root", (
            "/Users/gha-e2e-orchestrator/Library/Application Support/"
            "ssh-over-mcp-e2e/staging-v1"
        )),
        ("protected_root", "/private/tmp/protected"),
        ("native_temp_parent", "/private/tmp"),
        ("native_temp_parent", "relative/path"),
        ("complete", False),
        ("foreign_entry", True),
        ("quarantine_present", True),
        ("alias_disjoint", False),
    ],
)
def test_namespace_identity_and_quarantine_refuse(contract, attribute, value):
    n = replace(_safe_namespace(contract), **{attribute: value})
    assert "NAMESPACE_INVALID" in contract.validate_namespace(n)


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("name", "renamed"),
        ("original", (1, 2, 502, 20, 0o40700)),
        ("current", (2, 52, 502, 20, 0o40700)),
        ("current", (1, 52, 0, 20, 0o40700)),
        ("current", (1, 52, 502, 20, 0o40775)),
        ("acl_state", "unknown"),
        ("nofollow", False),
    ],
)
def test_namespace_edge_tamper_refuses(contract, attribute, value):
    n = _safe_namespace(contract)
    changed = replace(n.edges[2], **{attribute: value})
    n = replace(n, edges=(*n.edges[:2], changed, *n.edges[3:]))
    assert "NAMESPACE_INVALID" in contract.validate_namespace(n)


@pytest.mark.parametrize("replacement", [(), ("duplicate",), "reverse"])
def test_namespace_missing_duplicate_or_out_of_order_edges_refuse(contract, replacement):
    n = _safe_namespace(contract)
    if replacement == "reverse":
        bad = tuple(reversed(n.edges))
    elif replacement == ():
        bad = n.edges[:-1]
    else:
        bad = (*n.edges, n.edges[-1])
    assert "NAMESPACE_INVALID" in contract.validate_namespace(replace(n, edges=bad))


def test_provider_complete_absence_synthetic_schema(contract):
    assert contract.validate_provider(_safe_provider(contract)) == ()


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("marker_state", "present_file"),
        ("marker_state", "dangling_symlink"),
        ("marker_state", "dangling_parent_symlink"),
        ("marker_state", "unknown"),
        ("marker_chain_pinned", False),
        ("qemu_state", "enumeration_failed"),
        ("qemu_state", "truncated"),
        ("qemu_state", "unknown"),
        ("qemu_count", 1),
        ("qemu_count", None),
        ("qemu_count", True),
        ("protected_clean", False),
        ("legacy_private_clean", False),
        ("legacy_native_clean", False),
        ("complete", False),
    ],
)
def test_provider_incomplete_refuses(contract, attribute, value):
    p = replace(_safe_provider(contract), **{attribute: value})
    assert "PROVIDER_INVALID" in contract.validate_provider(p)


# Task 4: aggregate status is never authority to execute, dispatch or release.
def _safe_evidence(contract, inputs):
    run, checkout, job, runner = inputs
    inv, policy = _safe_interpreter(contract)
    return (
        contract.ContractEvidence(
            run, checkout, job, runner, inv, _safe_namespace(contract), _safe_provider(contract)
        ),
        policy,
    )


def test_synthetic_eligible_result_never_authorizes_host(contract, inputs):
    evidence, policy = _safe_evidence(contract, inputs)
    result = contract.assess(evidence, interpreter_policy=policy)
    assert result.status == "CONTRACT_ELIGIBLE_FOR_HOST_PROBE"
    assert result.violations == ()
    assert result.__dataclass_params__.frozen
    for name in ("dispatch", "run", "token", "pass_clean", "ready_to_dispatch"):
        assert not hasattr(result, name)
    rejected = contract.assess(evidence)
    assert rejected.status == "CONTRACT_REFUSED"
    assert "INTERPRETER_TRUST_UNAPPROVED" in rejected.violations


@pytest.mark.parametrize(
    ("part", "attribute", "invalid"),
    [
        ("run", "event", "pull_request_target"),
        ("run", "github_sha", "b"*40),
        ("checkout", "credential_env_present", True),
        ("checkout", "persist_credentials", True),
        ("job", "permissions", (("contents", "write"),)),
        ("job", "concurrency_group", "other"),
        ("runner", "gid", 80),
        ("runner", "egid", 80),
        ("runner", "account_primary_gid", 80),
        ("runner", "supplementary_gids", (20,80)),
        ("interpreter", "resolved_path", "/tmp/python3"),
        ("namespace", "alias_disjoint", False),
        ("namespace", "quarantine_present", True),
        ("provider", "marker_state", "dangling_symlink"),
        ("provider", "qemu_state", "enumeration_failed"),
        ("provider", "legacy_native_clean", False),
    ],
)
def test_single_field_mutation_refuses(contract, inputs, part, attribute, invalid):
    evidence, policy = _safe_evidence(contract, inputs)
    evidence = replace(
        evidence,
        **{part: replace(getattr(evidence, part), **{attribute: invalid})},
    )
    result = contract.assess(evidence, interpreter_policy=policy)
    assert result.status == "CONTRACT_REFUSED"
    assert result.violations


@pytest.mark.parametrize(
    ("part", "payload"),
    [
        ("run", {"fake": "SECRET_SENTINEL"}),
        ("checkout", None),
        ("job", "SECRET_SENTINEL"),
        ("runner", 0),
        ("interpreter", {"path": "/sensitive/SECRET_SENTINEL"}),
        ("namespace", ()),
        ("provider", object()),
    ],
)
def test_malformed_and_secrets_do_not_leak(contract, inputs, part, payload):
    evidence, policy = _safe_evidence(contract, inputs)
    evidence = replace(evidence, **{part: payload})
    result = contract.assess(evidence, interpreter_policy=policy)
    assert result.status == "CONTRACT_REFUSED"
    assert "EVIDENCE_INVALID" in result.violations
    assert "SECRET_SENTINEL" not in repr(result)
    assert "/sensitive" not in repr(result)
    assert len(result.violations) <= 32


def test_malformed_evidence_outer_shape_refuses(contract):
    result = contract.assess({"token": "SECRET_SENTINEL"})
    assert result.status == "CONTRACT_REFUSED"
    assert result.violations == ("EVIDENCE_INVALID",)
    assert "SECRET_SENTINEL" not in repr(result)


def test_no_host_io_or_execution_surface(contract, inputs):
    import ast
    source = MODULE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_modules = {"os", "subprocess", "socket", "urllib", "requests", "httpx"}
    forbidden_names = {"main", "dispatch", "ready_to_dispatch", "pass_clean"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(n.name.split(".")[0] in forbidden_modules for n in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module and node.module.split(".")[0] not in forbidden_modules
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert node.name not in forbidden_names
        if isinstance(node, ast.Compare):
            assert "__main__" not in ast.unparse(node)
    for name in forbidden_names:
        assert not hasattr(contract, name)
    evidence, policy = _safe_evidence(contract, inputs)
    assert contract.assess(evidence, interpreter_policy=policy).status == (
        "CONTRACT_ELIGIBLE_FOR_HOST_PROBE"
    )
