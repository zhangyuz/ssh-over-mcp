"""Pure read-only observation of GitHub-reported PR CI metadata.

This module never attests trusted test execution, PR authorization, or native E2E.
The caller must not use a ShadowObservation to allocate a persistent runner.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

_REPO = "zhangyuz/ssh-over-mcp"
_WORKFLOW = ".github/workflows/ci.yml"
_SHA_RE = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)
_PARTITIONS = (
    "projection-hot",
    "projection-rest-classified",
    "projection-rest-other",
    "rest",
)
_REQUIRED = frozenset(
    f"Full validation / Python {version} / {partition}"
    for version in ("3.13", "3.14")
    for partition in _PARTITIONS
) | frozenset(f"Ubuntu 26.04 x86 / Python {version}" for version in ("3.13", "3.14"))
_MAIN_ONLY = "Merge-main no-network Level-3"


class Refused(ValueError):
    """A fixed, non-sensitive refusal reason."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ShadowObservation:
    repo_id: int
    pr_number: int
    head_sha: str
    ci_run_id: int
    ci_attempt: int
    base_freshness_proven: bool = field(init=False, default=False)
    trusted_suite_proven: bool = field(init=False, default=False)
    dispatch_authorized: bool = field(init=False, default=False)


def _obj(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(k, str) for k in value):
        raise Refused("INVALID_SHAPE")
    return value


def _id(value: object) -> int:
    if type(value) is not int or value < 1:
        raise Refused("INVALID_ID")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise Refused("INVALID_SHA")
    return value


def _same_repo_identity(value: object, repo_id: int) -> bool:
    if not isinstance(value, Mapping):
        return False
    candidate = value.get("id")
    return type(candidate) is int and candidate == repo_id


def decide(
    event: Mapping[str, object],
    repository: Mapping[str, object],
    workflow: Mapping[str, object],
    run: Mapping[str, object],
    pull_requests: Sequence[Mapping[str, object]],
    jobs: Sequence[Mapping[str, object]],
) -> ShadowObservation:
    """Cross-check one reported CI run/attempt and its current PR association.

    A matched result only proves that the supplied GitHub API records are
    mutually consistent. PR-editable test/workflow steps are lower-trust data.
    """
    evt, repo, wf, ci = map(_obj, (event, repository, workflow, run))
    if repo.get("full_name") != _REPO or repo.get("default_branch") != "main":
        raise Refused("WRONG_REPOSITORY")
    repo_id = _id(repo.get("id"))
    event_repo = _obj(evt.get("repository"))
    if event_repo.get("full_name") != _REPO or _id(event_repo.get("id")) != repo_id:
        raise Refused("WRONG_REPOSITORY")
    if evt.get("action") != "completed":
        raise Refused("INCOMPLETE_RUN")
    erun = _obj(evt.get("workflow_run"))
    workflow_id = _id(wf.get("id"))
    if (
        wf.get("name") != "CI"
        or wf.get("path") != _WORKFLOW
        or wf.get("state") != "active"
        or _id(erun.get("workflow_id")) != workflow_id
        or _id(ci.get("workflow_id")) != workflow_id
        or ci.get("name") != "CI"
        or ci.get("path") != _WORKFLOW
        or ci.get("event") != "pull_request"
    ):
        raise Refused("WRONG_WORKFLOW")
    # The workflow_run payload and the fetched REST run are separate
    # observations. No conflicting or absent required event identity may
    # yield a positive shadow result, even though this is not authorization.
    if (
        erun.get("event") != ci.get("event")
        or erun.get("head_branch") != ci.get("head_branch")
        or erun.get("conclusion") != ci.get("conclusion")
        or erun.get("status") != ci.get("status")
        or not _same_repo_identity(erun.get("repository"), repo_id)
        or not _same_repo_identity(erun.get("head_repository"), repo_id)
        or ("name" in erun and erun["name"] != ci.get("name"))
        or ("path" in erun and erun["path"] != ci.get("path"))
    ):
        raise Refused("EVENT_REST_IDENTITY_MISMATCH")
    run_id = _id(erun.get("id"))
    attempt = _id(erun.get("run_attempt"))
    target = _sha(erun.get("head_sha"))
    if (
        _id(ci.get("id")) != run_id
        or _id(ci.get("run_attempt")) != attempt
        or _sha(ci.get("head_sha")) != target
        or ci.get("status") != "completed"
        or ci.get("conclusion") != "success"
    ):
        raise Refused("INCOMPLETE_RUN")
    if (
        _id(_obj(ci.get("repository")).get("id")) != repo_id
        or _id(_obj(ci.get("head_repository")).get("id")) != repo_id
    ):
        raise Refused("FORK_OR_WRONG_REPO")
    ref = ci.get("head_branch")
    if not isinstance(ref, str) or not ref or ref == "main":
        raise Refused("INVALID_HEAD_REF")

    if not isinstance(pull_requests, (list, tuple)) or len(pull_requests) > 500:
        raise Refused("INVALID_PR_ASSOCIATION")
    matching = []
    for raw in pull_requests:
        pr = _obj(raw)
        if pr.get("state") != "open" or pr.get("draft") is not False:
            continue
        head = _obj(pr.get("head"))
        base = _obj(pr.get("base"))
        if (
            head.get("sha") == target
            and head.get("ref") == ref
            and _id(_obj(head.get("repo")).get("id")) == repo_id
            and base.get("ref") == "main"
            and _id(_obj(base.get("repo")).get("id")) == repo_id
        ):
            matching.append(_id(pr.get("number")))
    if len(matching) != 1:
        raise Refused("PR_NOT_UNIQUE_OR_CURRENT")

    if not isinstance(jobs, (list, tuple)) or len(jobs) != 11:
        raise Refused("INCOMPLETE_JOBS")
    seen: set[str] = set()
    seen_ids: set[int] = set()
    for raw in jobs:
        job = _obj(raw)
        name = job.get("name")
        if not isinstance(name, str) or name in seen:
            raise Refused("DUPLICATE_OR_INVALID_JOB")
        seen.add(name)
        job_id = _id(job.get("id"))
        if job_id in seen_ids:
            raise Refused("DUPLICATE_JOB_ID")
        seen_ids.add(job_id)
        if "run_id" in job and _id(job.get("run_id")) != run_id:
            raise Refused("MIXED_ATTEMPT_JOBS")
        if "run_attempt" in job and _id(job.get("run_attempt")) != attempt:
            raise Refused("MIXED_ATTEMPT_JOBS")
        if job.get("status") != "completed":
            raise Refused("INCOMPLETE_JOBS")
        expected = "skipped" if name == _MAIN_ONLY else "success"
        if job.get("conclusion") != expected:
            raise Refused("INCOMPLETE_JOBS")
    if seen != _REQUIRED | {_MAIN_ONLY}:
        raise Refused("UNEXPECTED_JOBS")

    return ShadowObservation(
        repo_id=repo_id,
        pr_number=matching[0],
        head_sha=target,
        ci_run_id=run_id,
        ci_attempt=attempt,
    )
