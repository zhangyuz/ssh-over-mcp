"""Adversarial fixture tests for read-only exact-main acceptance."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / "ops/live-e2e/merge_main_evidence.py"
spec = importlib.util.spec_from_file_location("merge_main_evidence", PATH)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
SHA = "a" * 40
RUN_ID = 1234


def _run(**changes):
    value = {"id": RUN_ID, "head_sha": SHA, "event": "push", "head_branch": "main",
                 "path": ".github/workflows/ci.yml", "name": "CI",
                 "status": "completed", "conclusion": "success"}
    value.update(changes)
    return value


def _jobs():
    return {"total_count": len(mod._EXPECTED),
            "jobs": [{"name": name, "run_id": RUN_ID, "status": "completed", "conclusion": "success"}
                     for name in sorted(mod._EXPECTED)]}


def _check(runs=None, jobs=None, sha=SHA):
    runs = {"total_count": 1, "workflow_runs": [_run()]} if runs is None else runs
    jobs = _jobs() if jobs is None else jobs
    return mod.verify_snapshot(sha, runs, lambda rid: jobs)


def test_complete_exact_main_pass():
    assert _check() == RUN_ID


@pytest.mark.parametrize("run", [
    _run(head_sha="b" * 40), _run(event="pull_request"),
    _run(head_branch="feature"), _run(path=".github/workflows/other.yml"),
    _run(name="other"), _run(status="queued"), _run(conclusion="failure"),
    _run(conclusion="skipped"), _run(conclusion=None),
])
def test_wrong_run_refused(run):
    with pytest.raises(mod.Refused):
        _check({"total_count": 1, "workflow_runs": [run]})


def test_absent_main_run_refused():
    with pytest.raises(mod.Refused, match="MISSING"):
        _check({"total_count": 0, "workflow_runs": []})


def test_pr_success_cannot_replace_main_success():
    with pytest.raises(mod.Refused, match="MISSING"):
        _check({"total_count": 1, "workflow_runs": [_run(event="pull_request")]})


def test_duplicate_matching_runs_refused():
    with pytest.raises(mod.Refused, match="AMBIGUOUS"):
        _check({"total_count": 2, "workflow_runs": [_run(), _run(id=999)]})


@pytest.mark.parametrize("mutate", [
    lambda j: j["jobs"].pop(),
    lambda j: j["jobs"][0].update(conclusion="failure"),
    lambda j: j["jobs"][0].update(conclusion="skipped"),
    lambda j: j["jobs"][0].update(status="in_progress"),
    lambda j: j["jobs"][0].update(run_id=999),
    lambda j: j["jobs"][0].update(name="unrelated"),
    lambda j: j["jobs"][0].update(name=j["jobs"][1]["name"]),
])
def test_job_adversaries_refused(mutate):
    jobs = _jobs()
    mutate(jobs)
    with pytest.raises(mod.Refused):
        _check(jobs=jobs)


@pytest.mark.parametrize("runs", [
    {"total_count": 2, "workflow_runs": [_run()]},
    {"total_count": 101, "workflow_runs": [_run()]},
    {"total_count": True, "workflow_runs": [_run()]},
    {"workflow_runs": [_run()]},
])
def test_incomplete_or_malformed_pagination_refused(runs):
    with pytest.raises(mod.Refused):
        _check(runs=runs)


@pytest.mark.parametrize("sha", ["abc", "A" * 40, "a" * 39 + "x", "a" * 41])
def test_invalid_sha_refused(sha):
    with pytest.raises(mod.Refused):
        _check(sha=sha)


def test_no_live_dispatch_and_fail_closed_on_missing_real_merge(monkeypatch, capsys):
    calls = []

    def fake(path):
        calls.append(path)
        return {"total_count": 0, "workflow_runs": []}

    monkeypatch.setattr(mod, "_gh_api", fake)
    assert mod.main(["--sha", SHA]) == 2
    assert len(calls) == 1 and "head_sha=" + SHA in calls[0]
    assert "MERGE_MAIN_UNVERIFIED" in capsys.readouterr().err


def test_api_pins_canonical_github_host_despite_hostile_ambient_host(monkeypatch):
    """Hostile GH_HOST must never redirect acceptance to a different server."""
    from types import SimpleNamespace

    monkeypatch.setenv("GH_HOST", "evil.enterprise.invalid")
    observed = []

    def fake_run(argv, **kwargs):
        observed.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'{"total_count":0,"workflow_runs":[]}')

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    assert mod._gh_api("repos/zhangyuz/ssh-over-mcp/actions/runs") == {
        "total_count": 0, "workflow_runs": []
    }
    assert len(observed) == 1
    argv, kwargs = observed[0]
    assert argv[:4] == ["gh", "api", "--hostname", "github.com"]
    assert kwargs["env"]["GH_HOST"] == "github.com"
    assert argv[4] == "repos/zhangyuz/ssh-over-mcp/actions/runs"


def test_api_host_unavailable_refuses(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("GH_HOST", "evil.enterprise.invalid")
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b""),
    )
    with pytest.raises(mod.Refused, match="GITHUB_API_UNAVAILABLE"):
        mod._gh_api("repos/zhangyuz/ssh-over-mcp/actions/runs")
