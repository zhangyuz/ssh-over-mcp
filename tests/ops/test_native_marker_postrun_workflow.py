"""Execute the actual read-only provider guard against disposable fixtures."""

from __future__ import annotations

import ast
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/live-local-e2e.yml"
HELPER = ROOT / "ops/live-e2e/verify_native_provider_absence.py"
ORCHESTRATOR = ROOT / "scripts/run-live-local-e2e-orchestrator.py"
MARKER = Path("Library/Caches/ssh-over-mcp-e2e/active-run.json")


def _module():
    spec = importlib.util.spec_from_file_location("_test_native_provider_absence", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _postrun_step() -> dict:
    wf = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    return next(
        step for step in wf["jobs"]["e2e"]["steps"]
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
        ("dangling_library_symlink", False),
        ("valid_library_symlink", False),
        ("dangling_caches_symlink", False),
        ("valid_caches_symlink", False),
        ("missing_library", False),
        ("file_library", False),
        ("missing_caches", False),
        ("file_caches", False),
        ("file_home", False),
        ("missing_home", False),
    ],
)
def test_fixed_chain_probe_fails_closed_without_mutating_files(
    tmp_path: Path, kind: str, should_pass: bool
) -> None:
    module = _module()
    home = tmp_path / "original-home"
    marker = home / MARKER
    marker.parent.mkdir(parents=True)
    outside = tmp_path / "foreign-file"
    outside.write_text("outside must remain unchanged")
    foreign_dir = tmp_path / "foreign-dir"
    foreign_dir.mkdir()
    if kind == "file":
        marker.write_text("state")
    elif kind == "dangling_symlink":
        marker.symlink_to(tmp_path / "missing-marker-target")
    elif kind == "valid_symlink":
        marker.symlink_to(outside)
    elif kind == "directory":
        marker.mkdir()
    elif kind in ("dangling_parent_symlink", "valid_parent_symlink"):
        marker.parent.rmdir()
        marker.parent.symlink_to(
            tmp_path / "missing-dir" if kind.startswith("dangling") else foreign_dir,
            target_is_directory=True,
        )
    elif kind in ("missing_parent", "file_parent"):
        marker.parent.rmdir()
        if kind == "file_parent":
            marker.parent.write_text("not a directory")
    elif kind in ("dangling_caches_symlink", "valid_caches_symlink", "missing_caches", "file_caches"):
        marker.parent.rmdir()
        caches = marker.parent.parent
        caches.rmdir()
        if kind.endswith("symlink"):
            caches.symlink_to(
                tmp_path / "missing-dir" if kind.startswith("dangling") else foreign_dir,
                target_is_directory=True,
            )
        elif kind == "file_caches":
            caches.write_text("not a directory")
    elif kind in ("dangling_library_symlink", "valid_library_symlink", "missing_library", "file_library"):
        marker.parent.rmdir()
        marker.parent.parent.rmdir()
        library = marker.parent.parent.parent
        library.rmdir()
        if kind.endswith("symlink"):
            library.symlink_to(
                tmp_path / "missing-dir" if kind.startswith("dangling") else foreign_dir,
                target_is_directory=True,
            )
        elif kind == "file_library":
            library.write_text("not a directory")
    elif kind in ("missing_home", "file_home"):
        marker.parent.rmdir()
        marker.parent.parent.rmdir()
        marker.parent.parent.parent.rmdir()
        home.rmdir()
        if kind == "file_home":
            home.write_text("not a directory")

    try:
        module.assert_marker_absent_at(home)
        passed = True
    except (OSError, ValueError):
        passed = False
    assert passed is should_pass, kind
    assert outside.read_text() == "outside must remain unchanged"
    assert list(foreign_dir.iterdir()) == []
    if kind == "file":
        assert marker.read_text() == "state"
    if kind in {"dangling_symlink", "valid_symlink"}:
        assert marker.is_symlink()


def test_production_workflow_rejects_divergent_home_and_has_no_path_injection(
    tmp_path: Path,
) -> None:
    step = _postrun_step()
    assert step["if"] == "always()"
    run = step["run"]
    assert "verify_native_provider_absence.py" in run
    assert run.strip() == (
        "set -euo pipefail\npython3 ops/live-e2e/verify_native_provider_absence.py"
    )
    assert "$HOME" not in run
    assert "${{ inputs." not in run
    assert "rm " not in run and "unlink(" not in run

    alternate = tmp_path / "fake-home"
    (alternate / MARKER.parent).mkdir(parents=True)
    result = subprocess.run(
        ["bash", "-c", run],
        cwd=ROOT,
        env={**os.environ, "HOME": str(alternate)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, result.stdout
    assert "::error::" in result.stderr
    assert list((alternate / MARKER.parent).iterdir()) == []


def test_fixed_production_root_agrees_with_orchestrator_and_cannot_override() -> None:
    module = _module()
    tree = ast.parse(ORCHESTRATOR.read_text())
    val = next(
        x.value.args[0].value
        for x in tree.body if isinstance(x, ast.Assign)
        for tgt in x.targets
        if isinstance(tgt, ast.Name) and tgt.id == "ORCHESTRATOR_HOME"
    )
    assert val == module.FIXED_PROVIDER_HOME == "/Users/gha-e2e-orchestrator"
    assert "sys.argv" in HELPER.read_text()
    assert "pwd.getpwnam" in HELPER.read_text()
    assert "os.getuid()" in HELPER.read_text() and "os.geteuid()" in HELPER.read_text()
    assert "follow_symlinks=False" in HELPER.read_text()
    assert "O_NOFOLLOW" in HELPER.read_text()
    assert "unlink(" not in HELPER.read_text()
    assert "rmtree" not in HELPER.read_text()


def test_native_workflow_authority_fields_remain_constant() -> None:
    wf = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(wf["on"]) == {"workflow_call", "workflow_dispatch"}
    assert wf["permissions"] == {"contents": "read"}
    assert wf["concurrency"] == {"group": "live-local-e2e", "cancel-in-progress": "false"}
    job = wf["jobs"]["e2e"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["runs-on"] == ["self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"]
    assert job["timeout-minutes"] == "45"
    steps = {step["name"]: step for step in job["steps"]}
    checkout = steps["Checkout trusted-main orchestrator revision"]
    assert checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": "false",
        "clean": "true",
        "fetch-depth": "1",
    }
    run = steps["Run exact target in no-network QEMU guest"]["run"]
    assert 'python3 scripts/run-live-local-e2e-orchestrator.py "${{ inputs.commit_sha }}"' in run
    assert steps["Verify provider state is absent"]["if"] == "always()"


@pytest.mark.parametrize("error", [PermissionError, NotADirectoryError, OSError])
def test_permission_and_lookup_errors_fail_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[OSError]
) -> None:
    module = _module()
    home = tmp_path / "original-home"
    marker = home / MARKER
    marker.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("unmodified")
    raw_open = os.open

    def block_caches(path, flags, *args, **kwargs):
        if path == "Caches":
            raise error("injected directory-access failure")
        return raw_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", block_caches)
    with pytest.raises(error):
        module.assert_marker_absent_at(home)
    assert not marker.exists()
    assert outside.read_text() == "unmodified"


def test_production_main_refuses_uid_mismatch_without_probing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from types import SimpleNamespace

    module = _module()
    monkeypatch.setattr(module.sys, "argv", ["verify_native_provider_absence.py"])
    monkeypatch.setenv("HOME", module.FIXED_PROVIDER_HOME)
    monkeypatch.setattr(
        module.pwd,
        "getpwnam",
        lambda _: SimpleNamespace(pw_uid=502, pw_dir=module.FIXED_PROVIDER_HOME),
    )
    monkeypatch.setattr(module.os, "getuid", lambda: 501)
    monkeypatch.setattr(module.os, "geteuid", lambda: 501)
    called: list[str] = []
    monkeypatch.setattr(module, "assert_marker_absent_at", lambda _: called.append("unsafe"))
    assert module.main() == 1
    assert called == []
    assert "::error::" in capsys.readouterr().err


def test_production_main_rejects_cli_root_injection_without_probing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _module()
    monkeypatch.setattr(
        module.sys, "argv", ["verify_native_provider_absence.py", "/tmp/false-home"]
    )
    called: list[str] = []
    monkeypatch.setattr(module, "assert_marker_absent_at", lambda _: called.append("unsafe"))
    assert module.main() == 1
    assert called == []
    assert "::error::" in capsys.readouterr().err


@pytest.mark.parametrize("moment", ["after_provider_open", "after_leaf_enoent"])
def test_replaced_provider_directory_cannot_prove_marker_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moment: str
) -> None:
    """Swapping the held directory must not validate the canonical replacement."""
    module = _module()
    home = tmp_path / "home"
    marker = home / MARKER
    marker.parent.mkdir(parents=True)
    detached = marker.parent.with_name("ssh-over-mcp-e2e-detached")
    original_open = os.open
    original_stat = os.stat
    did_swap = False

    def swap() -> None:
        nonlocal did_swap
        if did_swap:
            return
        marker.parent.rename(detached)
        marker.parent.mkdir()
        marker.write_text("new canonical provider marker")
        did_swap = True

    def intercept_open(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if path == "ssh-over-mcp-e2e" and moment == "after_provider_open":
            swap()
        return fd

    def intercept_stat(path, *args, **kwargs):
        if path == "active-run.json" and moment == "after_leaf_enoent":
            try:
                return original_stat(path, *args, **kwargs)
            except FileNotFoundError:
                swap()
                raise
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", intercept_open)
    monkeypatch.setattr(module.os, "stat", intercept_stat)
    with pytest.raises((OSError, ValueError)):
        module.assert_marker_absent_at(home)
    monkeypatch.undo()
    assert did_swap
    assert marker.read_text() == "new canonical provider marker"
    assert detached.is_dir()
    assert not (detached / "active-run.json").exists()


def test_frozen_helper_hash_detects_modified_trusted_authority() -> None:
    from . import test_protected_staging_dormant as frozen

    key = "ops/live-e2e/verify_native_provider_absence.py"
    assert key in frozen.FROZEN
    original = (ROOT / key).read_bytes()
    frozen.assert_frozen_bytes_match(key, original)
    with pytest.raises(AssertionError):
        frozen.assert_frozen_bytes_match(key, original + b"\n# unreviewed modification")
