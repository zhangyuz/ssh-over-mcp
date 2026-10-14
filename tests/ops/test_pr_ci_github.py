"""Contract tests for the bounded, read-only GitHub evidence fetcher."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/pr_ci_github.py"
SHA = "a" * 40
BASE = "/repos/zhangyuz/ssh-over-mcp"


def _module():
    sys.path.insert(0, str(MODULE.parent))
    spec = importlib.util.spec_from_file_location("pr_ci_github", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _event(*, attempt: int = 2):
    return {
        "action": "completed",
        "repository": {"id": 42, "full_name": "zhangyuz/ssh-over-mcp"},
        "workflow_run": {
            "id": 123,
            "workflow_id": 9,
            "run_attempt": attempt,
            "head_sha": SHA,
        },
    }


def _responses():
    jobs = [
        {
            "id": n,
            "name": f"job-{n}",
            "status": "completed",
            "conclusion": "success",
            "run_id": 123,
        }
        for n in range(100, 111)
    ]
    repo = {"id": 42, "full_name": "zhangyuz/ssh-over-mcp", "default_branch": "main"}
    workflow = {"id": 9, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}
    run = {
        "id": 123,
        "run_attempt": 2,
        "workflow_id": 9,
        "head_sha": SHA,
        "head_branch": "feat/canary",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": 42},
        "head_repository": {"id": 42},
    }
    pr = {
        "number": 40,
        "state": "open",
        "draft": False,
        "head": {"sha": SHA, "ref": "feat/canary", "repo": {"id": 42}},
        "base": {"ref": "main", "repo": {"id": 42}},
    }
    return {
        BASE: repo,
        BASE + "/actions/workflows/ci.yml": workflow,
        BASE + "/actions/runs/123": run,
        BASE + f"/commits/{SHA}/pulls?per_page=100&page=1": [{"number": 40}],
        BASE + "/pulls/40": pr,
        BASE + "/actions/runs/123/attempts/2/jobs?per_page=100&page=1": {
            "total_count": 11,
            "jobs": jobs,
        },
    }


def test_only_attempt_jobs_endpoint() -> None:
    m = _module()
    replies = _responses()
    called: list[str] = []

    def fake(path: str):
        called.append(path)
        return replies[path]

    repository, workflow, run, pulls, jobs = m.GitHubReadAPI(
        "fake-read-token", transport=fake
    ).load(_event())

    assert repository["id"] == 42
    assert workflow["id"] == 9
    assert run["run_attempt"] == 2
    assert pulls == [replies[BASE + "/pulls/40"]]
    assert jobs == replies[BASE + "/actions/runs/123/attempts/2/jobs?per_page=100&page=1"]["jobs"]
    assert called == list(replies)
    assert BASE + "/actions/runs/123/jobs" not in called


def test_pr_detail_mismatch_with_commit_association_refuses() -> None:
    m = _module()
    replies = _responses()
    replies[BASE + "/pulls/40"]["number"] = 41
    with pytest.raises(m.Refused) as exc:
        m.GitHubReadAPI("fake", transport=replies.__getitem__).load(_event())
    assert exc.value.reason_code == "API_PR_DETAIL_MISMATCH"


def test_commit_pagination_over_cap_refuses() -> None:
    m = _module()
    replies = _responses()
    calls = []

    def fake(path: str):
        calls.append(path)
        if "/commits/" in path:
            page = int(path.rsplit("page=", 1)[1])
            return [{"number": (page - 1) * 100 + i + 1} for i in range(100)]
        return replies[path]

    with pytest.raises(m.Refused) as exc:
        m.GitHubReadAPI("fake", transport=fake).load(_event())
    assert exc.value.reason_code == "API_PR_LIMIT"
    assert len([p for p in calls if "/commits/" in p]) == 5


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"total_count": 12, "jobs": [{"id": 1}]}, "API_JOBS_INCOMPLETE"),
        ({"total_count": 201, "jobs": []}, "API_JOBS_LIMIT_OR_SHAPE"),
        ({"total_count": True, "jobs": []}, "API_JOBS_LIMIT_OR_SHAPE"),
        ({"total_count": 11, "jobs": "bad"}, "API_INVALID_SHAPE"),
    ],
)
def test_incomplete_jobs_total_count_refuses(override: dict, reason: str) -> None:
    m = _module()
    replies = _responses()
    endpoint = BASE + "/actions/runs/123/attempts/2/jobs?per_page=100&page=1"
    replies[endpoint] = override
    with pytest.raises(m.Refused) as exc:
        m.GitHubReadAPI("fake", transport=replies.__getitem__).load(_event())
    assert exc.value.reason_code == reason


@pytest.mark.parametrize("value", [True, 0, -1, "2", None])
def test_invalid_attempt_refuses_before_any_api_request(value: object) -> None:
    m = _module()
    event = _event()
    event["workflow_run"]["run_attempt"] = value
    called = []

    def fake(path: str):
        called.append(path)
        return _responses()[path]

    with pytest.raises(m.Refused):
        m.GitHubReadAPI("fake", transport=fake).load(event)
    assert called == []


def test_no_commit_association_refuses() -> None:
    m = _module()
    replies = _responses()
    replies[BASE + f"/commits/{SHA}/pulls?per_page=100&page=1"] = []
    with pytest.raises(m.Refused) as exc:
        m.GitHubReadAPI("fake", transport=replies.__getitem__).load(_event())
    assert exc.value.reason_code == "API_PR_ASSOCIATION_MISSING"


def test_transport_exception_uses_constant_safe_error() -> None:
    m = _module()

    def offline(_path: str):
        raise RuntimeError("untrusted response content")

    with pytest.raises(m.Refused) as exc:
        m.GitHubReadAPI("test-token", transport=offline).load(_event())
    assert exc.value.reason_code == "API_TRANSPORT_ERROR"
    assert "untrusted" not in str(exc.value)


@pytest.mark.parametrize(
    ("result_url", "raw", "status", "expected"),
    [
        ("https://not-github.example/elsewhere", b"{}", 200, "API_RESPONSE_INVALID"),
        ("https://api.github.com" + BASE, b"x" * (1024 * 1024 + 1), 200, "API_BODY_TOO_LARGE"),
        ("https://api.github.com" + BASE, b"{invalid", 200, "API_JSON_INVALID"),
        ("https://api.github.com" + BASE, b"{}", 302, "API_RESPONSE_INVALID"),
    ],
)
def test_transport_rejects_redirect_oversize_and_malformed(
    monkeypatch, result_url: str, raw: bytes, status: int, expected: str
) -> None:
    m = _module()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def geturl(self):
            return result_url

        def read(self, _limit):
            return raw

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.github.com" + BASE
            assert request.get_method() == "GET"
            assert timeout <= 10
            return Response()

    Response.status = status
    monkeypatch.setattr(m.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(m.Refused) as exc:
        m.GitHubReadAPI("test")._http_get(BASE)
    assert exc.value.reason_code == expected


def test_two_complete_attempt_job_pages_return_exact_total() -> None:
    m = _module()
    replies = _responses()
    base = BASE + "/actions/runs/123/attempts/2/jobs?per_page=100&page="
    replies[base + "1"] = {"total_count": 101, "jobs": [{"id": i} for i in range(100)]}
    replies[base + "2"] = {"total_count": 101, "jobs": [{"id": 100}]}
    _, _, _, _, jobs = m.GitHubReadAPI("test", transport=replies.__getitem__).load(_event())
    assert len(jobs) == 101
    assert jobs[-1]["id"] == 100
