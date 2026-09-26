from pathlib import Path

import pytest

from ssh_over_mcp.policy.models import Decision, EvaluationRequest
from ssh_over_mcp.policy.paths import PathPolicyError, normalize_remote_path, resolve_within


def test_remote_path_traversal_normalizes_outside_allowed_rule(engine):
    decision = engine.evaluate(
        EvaluationRequest(
            profile="observer",
            host="dev01",
            tool="fs_read",
            path="/srv/projects/app/../../../etc/shadow",
        )
    )
    assert decision.decision == Decision.DENY
    assert decision.normalized_path == "/etc/shadow"
    assert "deny.shadow" in decision.matched_deny_rules


def test_relative_remote_path_is_rejected():
    with pytest.raises(PathPolicyError):
        normalize_remote_path("../etc/passwd")


def test_resolve_within_accepts_normal_child(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    child = resolve_within(root, "project/file.txt")
    assert child == root / "project" / "file.txt"


def test_resolve_within_rejects_symlink_escape(tmp_path: Path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathPolicyError):
        resolve_within(root, "escape/secret.txt")
