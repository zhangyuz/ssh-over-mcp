"""Bounded read-only GitHub API snapshots for PR CI shadow classification.

Every returned field is untrusted DATA. No result authorizes native execution.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from pr_ci_admission import Refused

_BASE = "/repos/zhangyuz/ssh-over-mcp"
_ORIGIN = "https://api.github.com"
_MAX_BODY = 1024 * 1024
_MAX_PRS = 500
_MAX_JOBS = 200
_SAFE_PATH = re.compile(r"[/a-zA-Z0-9_.?&=%-]+\Z", re.ASCII)
_SHA = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)


def _positive(value: object) -> int:
    if type(value) is not int or value < 1:
        raise Refused("API_INVALID_ID")
    return value


def _mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise Refused("API_INVALID_SHAPE")
    return value


def _list(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise Refused("API_INVALID_SHAPE")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("API_REDIRECT")


class GitHubReadAPI:
    """GET fixed same-repository endpoints with finite response and page caps."""

    def __init__(
        self, token: str, *, transport: Callable[[str], object] | None = None
    ) -> None:
        if not isinstance(token, str) or not token or any(c in token for c in "\r\n"):
            raise Refused("API_TOKEN_UNAVAILABLE")
        self._token = token
        self._transport = transport if transport is not None else self._http_get

    def _http_get(self, path: str) -> object:
        request = urllib.request.Request(
            _ORIGIN + path,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            opener = urllib.request.build_opener(_NoRedirect())
            with opener.open(request, timeout=10) as response:
                if response.geturl() != _ORIGIN + path or response.status != 200:
                    raise Refused("API_RESPONSE_INVALID")
                body = response.read(_MAX_BODY + 1)
        except Refused:
            raise
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise Refused("API_NETWORK_OR_HTTP_ERROR") from None
        if len(body) > _MAX_BODY:
            raise Refused("API_BODY_TOO_LARGE")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise Refused("API_JSON_INVALID") from None

    def _get(self, path: str) -> object:
        if (
            not path.startswith(_BASE)
            or len(path) > 250
            or _SAFE_PATH.fullmatch(path) is None
        ):
            raise Refused("API_PATH_REFUSED")
        try:
            return self._transport(path)
        except Refused:
            raise
        except Exception:  # noqa: BLE001 - erase untrusted transport error details
            raise Refused("API_TRANSPORT_ERROR") from None

    def _associated_pulls(self, sha: str) -> list[dict[str, Any]]:
        numbers: list[int] = []
        used: set[int] = set()
        for page in range(1, 6):
            endpoint = f"{_BASE}/commits/{sha}/pulls?per_page=100&page={page}"
            associations = _list(self._get(endpoint))
            if len(associations) > 100:
                raise Refused("API_PR_PAGE_OVERFLOW")
            for candidate in associations:
                number = _positive(_mapping(candidate).get("number"))
                if number in used:
                    raise Refused("API_PR_DUPLICATE")
                used.add(number)
                numbers.append(number)
            if len(associations) < 100:
                break
            if page == 5:
                raise Refused("API_PR_LIMIT")
        if not numbers or len(numbers) > _MAX_PRS:
            raise Refused("API_PR_ASSOCIATION_MISSING")
        pulls = []
        for number in numbers:
            detail = _mapping(self._get(f"{_BASE}/pulls/{number}"))
            if _positive(detail.get("number")) != number:
                raise Refused("API_PR_DETAIL_MISMATCH")
            pulls.append(detail)
        return pulls

    def _attempt_jobs(self, run_id: int, attempt: int) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        expected: int | None = None
        for page in range(1, 3):
            endpoint = (
                f"{_BASE}/actions/runs/{run_id}/attempts/{attempt}"
                f"/jobs?per_page=100&page={page}"
            )
            response = _mapping(self._get(endpoint))
            count = response.get("total_count")
            if type(count) is not int or count < 1 or count > _MAX_JOBS:
                raise Refused("API_JOBS_LIMIT_OR_SHAPE")
            if expected is None:
                expected = count
            elif count != expected:
                raise Refused("API_JOBS_COUNT_DRIFT")
            page_jobs = _list(response.get("jobs"))
            if len(page_jobs) > 100:
                raise Refused("API_JOBS_PAGE_OVERFLOW")
            jobs.extend(_mapping(item) for item in page_jobs)
            if len(jobs) == count:
                return jobs
            if len(page_jobs) != 100 or len(jobs) > count:
                raise Refused("API_JOBS_INCOMPLETE")
        raise Refused("API_JOBS_INCOMPLETE")

    def load(
        self, event: Mapping[str, object]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        evt = _mapping(event)
        if evt.get("action") != "completed":
            raise Refused("API_EVENT_NOT_COMPLETED")
        repo = _mapping(evt.get("repository"))
        if repo.get("full_name") != "zhangyuz/ssh-over-mcp":
            raise Refused("API_WRONG_REPOSITORY")
        source = _mapping(evt.get("workflow_run"))
        run_id = _positive(source.get("id"))
        attempt = _positive(source.get("run_attempt"))
        sha = source.get("head_sha")
        if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
            raise Refused("API_INVALID_SHA")
        repository = _mapping(self._get(_BASE))
        workflow = _mapping(self._get(f"{_BASE}/actions/workflows/ci.yml"))
        run = _mapping(self._get(f"{_BASE}/actions/runs/{run_id}"))
        pulls = self._associated_pulls(sha)
        jobs = self._attempt_jobs(run_id, attempt)
        return (repository, workflow, run, pulls, jobs)
