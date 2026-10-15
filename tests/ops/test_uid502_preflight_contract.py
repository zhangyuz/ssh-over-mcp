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
