from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/pr_ci_admission.py"
SHA = "a" * 40
PARTITIONS = (
    "projection-hot",
    "projection-rest-classified",
    "projection-rest-other",
    "rest",
)


def _module():
    spec = importlib.util.spec_from_file_location("pr_ci_admission", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _case():
    repository = {
        "id": 42,
        "full_name": "zhangyuz/ssh-over-mcp",
        "default_branch": "main",
    }
    workflow = {
        "id": 9,
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "state": "active",
    }
    event = {
        "action": "completed",
        "repository": dict(repository),
        "workflow_run": {
            "id": 123,
            "workflow_id": 9,
            "run_attempt": 1,
            "head_sha": SHA,
        },
    }
    run = {
        "id": 123,
        "run_attempt": 1,
        "workflow_id": 9,
        "path": ".github/workflows/ci.yml",
        "name": "CI",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA,
        "head_branch": "feat/canary",
        "head_repository": {"id": 42},
        "repository": {"id": 42},
    }
    pr = {
        "number": 40,
        "state": "open",
        "draft": False,
        "head": {
            "sha": SHA,
            "ref": "feat/canary",
            "repo": {"id": 42},
        },
        "base": {
            "ref": "main",
            "repo": {"id": 42},
        },
    }
    jobs = [
        {
            "id": i + 100,
            "name": f"Full validation / Python {version} / {partition}",
            "status": "completed",
            "conclusion": "success",
            "run_id": 123,
        }
        for i, (version, partition) in enumerate(
            (v, p) for v in ("3.13", "3.14") for p in PARTITIONS
        )
    ]
    jobs.extend(
        {
            "id": i + 108,
            "name": f"Ubuntu 26.04 x86 / Python {v}",
            "status": "completed",
            "conclusion": "success",
            "run_id": 123,
        }
        for i, v in enumerate(("3.13", "3.14"))
    )
    jobs.append(
        {
            "id": 110,
            "name": "Merge-main no-network Level-3",
            "status": "completed",
            "conclusion": "skipped",
            "run_id": 123,
        }
    )
    return (event, repository, workflow, run, [pr], jobs)


def test_matches_one_live_same_repo_pr_metadata_only() -> None:
    m = _module()
    observed = m.decide(*_case())
    assert observed == m.ShadowObservation(
        repo_id=42,
        pr_number=40,
        head_sha=SHA,
        ci_run_id=123,
        ci_attempt=1,
    )
    assert observed.base_freshness_proven is False
    assert observed.trusted_suite_proven is False
    assert observed.dispatch_authorized is False
    with pytest.raises(TypeError):
        m.ShadowObservation(42, 40, SHA, 123, 1, trusted_suite_proven=True)


def test_duplicate_job_ids_refuse_even_when_names_are_unique() -> None:
    m = _module()
    args = list(_case())
    jobs = args[5]
    jobs[1]["id"] = jobs[0]["id"]
    with pytest.raises(m.Refused) as exc:
        m.decide(*args)
    assert exc.value.reason_code == "DUPLICATE_JOB_ID"


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("no_association", None),
        ("fork", 43),
        ("draft", True),
        ("closed", "closed"),
        ("wrong_branch", "other-branch"),
        ("changed_head", "b" * 40),
        ("wrong_base", "not-main"),
        ("wrong_repo", 41),
        ("wrong_workflow", 10),
        ("wrong_attempt", 2),
        ("wrong_run_id", 124),
        ("mixed_attempt", 2),
        ("missing_job", None),
        ("duplicate_job", None),
        ("failed_job", "failure"),
        ("skipped_required_job", "skipped"),
        ("unexpected_job", "Injected"),
        ("duplicate_pr", None),
    ],
)
def test_adversarial_ci_metadata_refuses(mutation: str, value: object) -> None:
    m = _module()
    args = list(_case())
    _, repo, _, run, pulls, jobs = args
    if mutation == "no_association":
        pulls.clear()
    elif mutation == "fork":
        pulls[0]["head"]["repo"]["id"] = value
    elif mutation == "draft":
        pulls[0]["draft"] = value
    elif mutation == "closed":
        pulls[0]["state"] = value
    elif mutation == "wrong_branch":
        pulls[0]["head"]["ref"] = value
    elif mutation == "changed_head":
        pulls[0]["head"]["sha"] = value
    elif mutation == "wrong_base":
        pulls[0]["base"]["ref"] = value
    elif mutation == "wrong_repo":
        repo["id"] = value
    elif mutation == "wrong_workflow":
        run["workflow_id"] = value
    elif mutation == "wrong_attempt":
        run["run_attempt"] = value
    elif mutation == "wrong_run_id":
        run["id"] = value
    elif mutation == "mixed_attempt":
        jobs[0]["run_attempt"] = value
    elif mutation == "missing_job":
        jobs.pop(0)
    elif mutation == "duplicate_job":
        jobs[1]["name"] = jobs[0]["name"]
    elif mutation in ("failed_job", "skipped_required_job"):
        jobs[0]["conclusion"] = value
    elif mutation == "unexpected_job":
        jobs[0]["name"] = value
    elif mutation == "duplicate_pr":
        pulls.append(pulls[0].copy())
    with pytest.raises(m.Refused):
        m.decide(*args)


def test_modified_ci_same_green_names_is_not_trusted_suite_proof() -> None:
    """GitHub metadata cannot reveal if a PR-edited CI skipped the real suite."""
    m = _module()
    observed = m.decide(*_case())
    assert observed.trusted_suite_proven is False
    assert observed.dispatch_authorized is False
    assert observed.base_freshness_proven is False
    for name in ("trusted_suite_proven", "dispatch_authorized", "base_freshness_proven"):
        with pytest.raises(TypeError):
            m.ShadowObservation(42, 40, SHA, 123, 1, **{name: True})


def test_base_freshness_not_claimed() -> None:
    m = _module()
    assert m.decide(*_case()).base_freshness_proven is False


def test_skip_is_not_native_evidence() -> None:
    m = _module()
    args = list(_case())
    args[5][-1]["conclusion"] = "success"
    with pytest.raises(m.Refused):
        m.decide(*args)


@pytest.mark.parametrize("bad_sha", ["0" * 39, "A" * 40, "Z" * 40, "0" * 41, 7, None])
def test_invalid_sha_refuses(bad_sha: object) -> None:
    m = _module()
    args = list(_case())
    args[3]["head_sha"] = bad_sha
    with pytest.raises(m.Refused):
        m.decide(*args)
