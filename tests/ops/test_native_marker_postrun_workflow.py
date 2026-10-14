"""Real execution contract for the native self-hosted postrun marker guard."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/live-local-e2e.yml"
MARKER = Path("Library/Caches/ssh-over-mcp-e2e/active-run.json")


def _postrun_script() -> str:
    wf = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    return next(
        step["run"]
        for step in wf["jobs"]["e2e"]["steps"]
        if step["name"] == "Verify provider state is absent"
    )


@pytest.mark.parametrize(
    ("kind", "should_pass"),
    [
        ("missing", True),
        ("file", False),
        ("dangling_symlink", False),
        ("valid_symlink", False),
        ("directory", False),
        ("dangling_parent_symlink", False),
        ("valid_parent_symlink", False),
        ("missing_parent", False),
        ("file_parent", False),
    ],
)
def test_postrun_check_fails_closed_for_any_marker_entry(
    tmp_path: Path, kind: str, should_pass: bool
) -> None:
    marker = tmp_path / MARKER
    marker.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("outside must remain unchanged")
    if kind == "file":
        marker.write_text("state")
    elif kind == "dangling_symlink":
        marker.symlink_to(tmp_path / "missing-marker-target")
    elif kind == "valid_symlink":
        marker.symlink_to(outside)
    elif kind == "directory":
        marker.mkdir()
    elif kind == "dangling_parent_symlink":
        marker.parent.rmdir()
        marker.parent.symlink_to(tmp_path / "absent-provider-parent", target_is_directory=True)
    elif kind == "valid_parent_symlink":
        target = tmp_path / "outside-provider-parent"
        target.mkdir()
        marker.parent.rmdir()
        marker.parent.symlink_to(target, target_is_directory=True)
    elif kind == "missing_parent":
        marker.parent.rmdir()
    elif kind == "file_parent":
        marker.parent.rmdir()
        marker.parent.write_text("not a directory")

    result = subprocess.run(
        ["bash", "-c", _postrun_script()],
        env={**os.environ, "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is should_pass, (kind, result.stdout, result.stderr)
    assert outside.read_text() == "outside must remain unchanged"
    if kind in {"dangling_symlink", "valid_symlink"}:
        assert marker.is_symlink()
    if kind == "file":
        assert marker.read_text() == "state"
    if not should_pass:
        assert "::error::" in result.stdout or "::error::" in result.stderr


def test_postrun_guard_is_read_only_and_runs_on_failure() -> None:
    wf = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    step = next(s for s in wf["jobs"]["e2e"]["steps"] if s["name"] == "Verify provider state is absent")
    assert step["if"] == "always()"
    guard = step["run"]
    assert "O_NOFOLLOW" in guard
    assert "follow_symlinks=False" in guard
    assert "rm -rf" not in guard and "unlink(" not in guard
