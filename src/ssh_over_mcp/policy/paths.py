from __future__ import annotations

import posixpath
from pathlib import Path


class PathPolicyError(ValueError):
    pass


def normalize_remote_path(path: str) -> str:
    if not path.startswith("/"):
        raise PathPolicyError("remote policy paths must be absolute")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        raise PathPolicyError("normalized path is not absolute")
    return normalized


def resolve_within(root: Path, candidate: str | Path) -> Path:
    root_resolved = root.resolve(strict=True)
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = root_resolved / candidate_path
    resolved = candidate_path.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise PathPolicyError(f"path escapes allowed root: {candidate}") from exc
    return resolved
