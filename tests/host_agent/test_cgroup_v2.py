from __future__ import annotations

import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.cgroup_v2 import (
    CgroupV2Backend,
)
from ssh_over_mcp.host_agent.containment import (
    ContainmentError,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentUnavailableError,
)


def limits() -> ContainmentLimits:
    return ContainmentLimits(
        memory_max_bytes=512 * 1024 * 1024,
        pids_max=64,
        cpu_quota_us=50_000,
        cpu_period_us=100_000,
    )


def request() -> ContainmentRequest:
    return ContainmentRequest(
        request_id="req_12345678",
        limits=limits(),
    )


def make_root(tmp_path: Path) -> Path:
    root = tmp_path / "delegated"
    root.mkdir()
    (root / "cgroup.controllers").write_text(
        "cpu memory pids io\n",
        encoding="ascii",
    )
    (root / "cgroup.subtree_control").write_text(
        "cpu memory pids\n",
        encoding="ascii",
    )
    return root


class FakeCgroupV2Backend(CgroupV2Backend):
    def _create_scope_directory(self, scope: Path) -> None:
        super()._create_scope_directory(scope)
        files = {
            "cgroup.procs": "",
            "cgroup.kill": "",
            "cgroup.events": "populated 0\nfrozen 0\n",
            "memory.max": "max\n",
            "memory.current": "12345\n",
            "pids.max": "max\n",
            "pids.current": "3\n",
            "cpu.max": "max 100000\n",
            "cpu.stat": (
                "usage_usec 4567\n"
                "user_usec 3000\n"
                "system_usec 1567\n"
            ),
        }
        for name, content in files.items():
            (scope / name).write_text(content, encoding="ascii")


def test_create_configures_finite_limits(tmp_path: Path):
    backend = FakeCgroupV2Backend(make_root(tmp_path))

    handle = backend.create(request())

    assert backend.name == "cgroup-v2"
    assert handle.scope_id == "ssh-over-mcp-req_12345678"
    assert handle.path.parent == backend.root
    assert (handle.path / "memory.max").read_text(
        encoding="ascii"
    ).strip() == str(limits().memory_max_bytes)
    assert (handle.path / "pids.max").read_text(
        encoding="ascii"
    ).strip() == str(limits().pids_max)
    assert (handle.path / "cpu.max").read_text(
        encoding="ascii"
    ).strip() == "50000 100000"


def test_attach_writes_pid_to_cgroup_procs(tmp_path: Path):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    handle = backend.create(request())

    handle.attach(4321)

    assert (handle.path / "cgroup.procs").read_text(
        encoding="ascii"
    ).strip() == "4321"


@pytest.mark.parametrize("pid", [0, -1, True, 1.5])
def test_attach_rejects_invalid_pid(tmp_path: Path, pid):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    handle = backend.create(request())

    with pytest.raises(ValueError):
        handle.attach(pid)


def test_kill_all_writes_recursive_kill_control(tmp_path: Path):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    handle = backend.create(request())

    handle.kill_all()

    assert (handle.path / "cgroup.kill").read_text(
        encoding="ascii"
    ).strip() == "1"


def test_stats_parses_kernel_accounting_files(tmp_path: Path):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    handle = backend.create(request())

    stats = handle.stats()

    assert stats.memory_current_bytes == 12345
    assert stats.pids_current == 3
    assert stats.cpu_usage_usec == 4567
    assert stats.populated is False


def test_close_rejects_populated_scope(tmp_path: Path):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    handle = backend.create(request())
    (handle.path / "cgroup.events").write_text(
        "populated 1\nfrozen 0\n",
        encoding="ascii",
    )

    with pytest.raises(ContainmentError, match="still populated"):
        handle.close()


def test_close_removes_empty_scope(
    tmp_path: Path,
    monkeypatch,
):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    handle = backend.create(request())
    scope = handle.path
    real_rmdir = os.rmdir

    def fake_cgroup_rmdir(path):
        path = Path(path)
        for child in path.iterdir():
            child.unlink()
        real_rmdir(path)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cgroup_v2.os.rmdir",
        fake_cgroup_rmdir,
    )

    handle.close()
    handle.close()

    assert not scope.exists()
    with pytest.raises(ContainmentError, match="closed"):
        handle.stats()


def test_duplicate_request_scope_is_rejected(tmp_path: Path):
    backend = FakeCgroupV2Backend(make_root(tmp_path))
    backend.create(request())

    with pytest.raises(ContainmentError, match="already exists"):
        backend.create(request())


def test_missing_required_controller_fails_closed(tmp_path: Path):
    root = make_root(tmp_path)
    (root / "cgroup.controllers").write_text(
        "cpu memory\n",
        encoding="ascii",
    )
    backend = FakeCgroupV2Backend(root)

    with pytest.raises(
        ContainmentUnavailableError,
        match="controllers",
    ):
        backend.create(request())


def test_noncanonical_root_is_rejected(tmp_path: Path):
    root = make_root(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)

    with pytest.raises(
        ContainmentUnavailableError,
        match="canonical",
    ):
        CgroupV2Backend(alias)


class MissingKillBackend(FakeCgroupV2Backend):
    def _create_scope_directory(self, scope: Path) -> None:
        super()._create_scope_directory(scope)
        (scope / "cgroup.kill").unlink()


def test_missing_required_scope_interface_fails_closed(tmp_path: Path):
    backend = MissingKillBackend(make_root(tmp_path))

    with pytest.raises(
        ContainmentUnavailableError,
        match="cgroup.kill",
    ):
        backend.create(request())
