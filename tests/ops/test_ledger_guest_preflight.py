from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "ops/live-e2e/ledger_guest_preflight.py"


def _load_preflight() -> ModuleType:
    assert PREFLIGHT.is_file(), "trusted guest no-core guard is missing"
    spec = importlib.util.spec_from_file_location("ledger_guest_preflight", PREFLIGHT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def kernel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = _load_preflight()
    pattern = tmp_path / "core_pattern"
    pattern.write_text("|/untrusted/collector\n")
    state = {"limits": (4096, 8192)}
    monkeypatch.setattr(module, "_CORE_PATTERN", pattern)
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.resource, "getrlimit", lambda _: state["limits"])

    def set_limits(which, limits):
        assert which == module.resource.RLIMIT_CORE
        state["limits"] = limits

    monkeypatch.setattr(module.resource, "setrlimit", set_limits)
    return module, pattern, state


def test_establishes_fixed_guest_policy_and_both_zero_limits(kernel) -> None:
    module, pattern, state = kernel
    module.establish_guest_no_core()
    assert pattern.read_bytes() == b"core\n"
    assert state["limits"] == (0, 0)
    module.require_no_core()


@pytest.mark.parametrize("platform,uid", [("darwin", 0), ("linux", 1001)])
def test_establishment_refuses_wrong_context_without_mutation(
    kernel, monkeypatch: pytest.MonkeyPatch, platform: str, uid: int,
) -> None:
    module, pattern, state = kernel
    monkeypatch.setattr(module.sys, "platform", platform)
    monkeypatch.setattr(module.os, "geteuid", lambda: uid)
    with pytest.raises(module.ProfileError):
        module.establish_guest_no_core()
    assert state["limits"] == (4096, 8192)
    assert pattern.read_text() == "|/untrusted/collector\n"


@pytest.mark.parametrize("limits", [(0, 1), (1, 1), (-1, -1)])
def test_nonzero_effective_limits_are_rejected(kernel, limits) -> None:
    module, pattern, state = kernel
    pattern.write_text("core\n")
    state["limits"] = limits
    with pytest.raises(module.ProfileError):
        module.require_no_core()
    assert state["limits"] == limits


@pytest.mark.parametrize("pattern_bytes", [b"|/bin/collector\n", b"", b"elsewhere\n", b"core\nextra\n"])
def test_unexpected_pattern_is_rejected_without_repair(kernel, pattern_bytes) -> None:
    module, pattern, state = kernel
    state["limits"] = (0, 0)
    pattern.write_bytes(pattern_bytes)
    with pytest.raises(module.ProfileError):
        module.require_no_core()
    assert pattern.read_bytes() == pattern_bytes


def test_failed_limit_setting_does_not_change_core_pattern(
    kernel, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, pattern, _ = kernel

    def fail(*_):
        raise PermissionError("sensitive kernel detail")

    monkeypatch.setattr(module.resource, "setrlimit", fail)
    with pytest.raises(module.ProfileError) as error:
        module.establish_guest_no_core()
    assert "sensitive" not in str(error.value)
    assert pattern.read_text() == "|/untrusted/collector\n"


def test_successful_set_with_wrong_readback_is_rejected(
    kernel, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _, _ = kernel
    monkeypatch.setattr(module.resource, "setrlimit", lambda *_: None)
    with pytest.raises(module.ProfileError):
        module.establish_guest_no_core()


def test_unavailable_pattern_or_limits_fail_closed(kernel, monkeypatch: pytest.MonkeyPatch) -> None:
    module, pattern, state = kernel
    state["limits"] = (0, 0)
    pattern.unlink()
    with pytest.raises(module.ProfileError):
        module.require_no_core()

    def fail(*_):
        raise OSError("sensitive kernel detail")

    monkeypatch.setattr(module.resource, "getrlimit", fail)
    with pytest.raises(module.ProfileError) as error:
        module.require_no_core()
    assert "sensitive" not in str(error.value)


def test_failed_pattern_write_keeps_zero_limits(kernel, monkeypatch: pytest.MonkeyPatch) -> None:
    module, _, state = kernel

    def fail(*_, **__):
        raise PermissionError("sensitive kernel detail")

    monkeypatch.setattr(Path, "write_text", fail)
    with pytest.raises(module.ProfileError):
        module.establish_guest_no_core()
    assert state["limits"] == (0, 0)


def test_changed_pattern_readback_cannot_report_success(kernel, monkeypatch: pytest.MonkeyPatch) -> None:
    module, pattern, _ = kernel
    original_write = Path.write_text

    def changed_write(path, _data, **kwargs):
        return original_write(path, "|/unexpected/collector\n", **kwargs)

    monkeypatch.setattr(Path, "write_text", changed_write)
    with pytest.raises(module.ProfileError):
        module.establish_guest_no_core()
    assert pattern.read_bytes() == b"|/unexpected/collector\n"


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0, reason="non-root Linux inheritance proof")
def test_real_nonroot_descendant_cannot_raise_inherited_hard_zero(tmp_path: Path) -> None:
    pattern = tmp_path / "core_pattern"
    pattern.write_text("core\n")
    code = f"""
import importlib.util, resource, subprocess, sys
spec = importlib.util.spec_from_file_location('preflight', {str(PREFLIGHT)!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module._CORE_PATTERN = module.Path({str(pattern)!r})
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
module.require_no_core()
child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', '''
import resource
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
try:
    resource.setrlimit(resource.RLIMIT_CORE, (1, 1))
except (ValueError, OSError):
    pass
else:
    raise SystemExit('hard-zero limit was raised')
'''], check=False)
raise SystemExit(child.returncode)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code], capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode()
