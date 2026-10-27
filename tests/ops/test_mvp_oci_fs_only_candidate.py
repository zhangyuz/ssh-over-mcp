"""Source-only review tests for NNP-safe v3 FS ForceCommand candidate.

Never starts sshd/containers or changes host privileges. Runtime remains HOLD.
"""

from __future__ import annotations

import builtins
import importlib.util
import io
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from ssh_over_mcp.host_agent.policy import load_host_policy

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "ops/mvp/ssh-over-mcp-fs-only-launcher.py"
FS_CONFIG = ROOT / "deploy/ssh-target/sshd_config.fs-only-review-candidate"
ORIGINAL_CONFIG = ROOT / "deploy/ssh-target/sshd_config.review-candidate"
POLICY = ROOT / "deploy/ssh-target/host-policy.review-candidate.yaml"


def _entry():
    spec = importlib.util.spec_from_file_location("som_fs_only_review", ENTRY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _kernel_status(*, uid=2201, gid=3201, nnp="1", bound="0000000000000000"):
    zero = "0000000000000000"
    return (
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
        f"NoNewPrivs:\t{nnp}\n"
        f"CapInh:\t{zero}\nCapPrm:\t{zero}\nCapEff:\t{zero}\n"
        f"CapBnd:\t{bound}\nCapAmb:\t{zero}\n"
    )


@pytest.mark.parametrize(
    "uid,gid,nnp,bound,accepted",
    [
        (2201, 3201, "1", "0000000000000000", True),
        (2201, 3201, "0", "0000000000000000", False),
        (2201, 3201, "1", "0000000000000400", False),
        (0, 3201, "1", "0000000000000000", False),
        (2201, 0, "1", "0000000000000000", False),
    ],
)
def test_guest_nnp_zero_caps_and_ssh_identity_fail_closed(
    monkeypatch, uid, gid, nnp, bound, accepted
):
    entry = _entry()
    monkeypatch.setattr(
        entry,
        "sys",
        SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1, no_site=1)),
    )
    monkeypatch.setattr(entry.os, "getresuid", lambda: (uid,) * 3, raising=False)
    monkeypatch.setattr(entry.os, "getresgid", lambda: (gid,) * 3, raising=False)
    monkeypatch.setattr(entry.os, "getgroups", lambda: [3201])
    real_open = builtins.open

    def mocked_open(name, *args, **kwargs):
        if name == "/proc/self/status":
            return io.StringIO(_kernel_status(uid=uid, gid=gid, nnp=nnp, bound=bound))
        return real_open(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", mocked_open)
    if accepted:
        entry._kernel_identity()
    else:
        with pytest.raises(entry.FsOnlyStartRefused):
            entry._kernel_identity()


def test_manager_group_inherited_is_rejected(monkeypatch):
    entry = _entry()
    monkeypatch.setattr(
        entry,
        "sys",
        SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1, no_site=1)),
    )
    monkeypatch.setattr(entry.os, "getresuid", lambda: (2201,) * 3, raising=False)
    monkeypatch.setattr(entry.os, "getresgid", lambda: (3201,) * 3, raising=False)
    monkeypatch.setattr(entry.os, "getgroups", lambda: [3299])
    with pytest.raises(entry.FsOnlyStartRefused, match="group"):
        entry._kernel_identity()


def test_data_volume_wrong_owner_and_permissions_refused(monkeypatch):
    entry = _entry()
    for owner, group, mode, allowed in [
        (2201, 3201, 0o700, True),
        (2202, 3202, 0o700, False),
        (2201, 3201, 0o770, False),
        (2201, 3201, 0o777, False),
    ]:
        monkeypatch.setattr(
            entry.os,
            "lstat",
            lambda _path, owner=owner, group=group, mode=mode: SimpleNamespace(
                st_uid=owner, st_gid=group, st_mode=stat.S_IFDIR | mode
            ),
        )
        if allowed:
            entry._data_root()
        else:
            with pytest.raises(entry.FsOnlyStartRefused):
                entry._data_root()


def test_only_existing_v3_fs_policy_admitted():
    entry = _entry()
    policy = load_host_policy(POLICY, require_root_owner=False)
    entry._fixed_policy(policy)
    for bad in [
        policy.model_copy(update={"version": 4}),
        policy.model_copy(update={"allowed_profiles": {"rw-operator", "developer"}}),
        policy.model_copy(update={"filesystem": {}}),
    ]:
        with pytest.raises(entry.FsOnlyStartRefused):
            entry._fixed_policy(bad)


@pytest.mark.parametrize(
    "field,value",
    [
        ("commands", {}),
        ("env_allow", frozenset({"SAFE_NAME"})),
        ("max_timeout_seconds", 11),
        ("max_output_bytes", 16384),
        ("max_stdin_bytes", 1),
    ],
)
def test_fs_only_policy_rejects_nonfilesystem_expansion(field, value):
    entry = _entry()
    policy = load_host_policy(POLICY, require_root_owner=False)
    with pytest.raises(entry.FsOnlyStartRefused):
        entry._fixed_policy(policy.model_copy(update={field: value}))


def test_fs_only_policy_rejects_raised_process_limits():
    entry = _entry()
    policy = load_host_policy(POLICY, require_root_owner=False)
    raised = policy.child_limits.model_copy(update={"max_processes": 64})
    with pytest.raises(entry.FsOnlyStartRefused):
        entry._fixed_policy(policy.model_copy(update={"child_limits": raised}))


def test_fs_only_policy_rejects_widened_command_rules():
    entry = _entry()
    policy = load_host_policy(POLICY, require_root_owner=False)
    original = policy.commands["/usr/bin/true"]
    for changed in [
        original.model_copy(update={"allow_file_capabilities": True}),
        original.model_copy(update={"allow_setuid_or_setgid": True}),
        original.model_copy(
            update={"argv": (original.argv[0].model_copy(update={"args": ("run",)}),)}
        ),
    ]:
        with pytest.raises(entry.FsOnlyStartRefused):
            entry._fixed_policy(policy.model_copy(update={"commands": {"/usr/bin/true": changed}}))


def test_alternate_sshd_exact_original_except_forcecommand():
    original = ORIGINAL_CONFIG.read_text()
    reviewed = FS_CONFIG.read_text()
    root_command = (
        "ForceCommand /usr/bin/sudo -n /usr/bin/python3 -I -S "
        "/usr/local/libexec/ssh-over-mcp-oci-launcher.py"
    )
    fs_command = (
        "ForceCommand /usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-fs-only-launcher.py"
    )
    assert original.count(root_command) == reviewed.count(fs_command) == 1
    assert fs_command in reviewed
    assert [line for line in reviewed.splitlines() if not line.startswith("#")] == [
        line.replace("Port 22", "Port 2222").replace(root_command, fs_command)
        for line in original.splitlines()
        if not line.startswith("#")
    ]
    assert "PasswordAuthentication no" in reviewed
    assert "AuthenticationMethods publickey" in reviewed
    assert "DisableForwarding yes" in reviewed
    assert "PermitTTY no" in reviewed
    assert "UsePAM no" in reviewed
    assert "sudo" not in fs_command
    assert "cap_add:" not in reviewed


def test_unprivileged_openssh_candidate_requires_high_port_and_no_sudo():
    reviewed = FS_CONFIG.read_text()
    assert "Port 2222" in reviewed.splitlines()
    assert "Port 22" not in reviewed.splitlines()
    assert "UsePAM no" in reviewed
    assert "AllowUsers ssh-over-mcp-e2e-host" in reviewed
    assert "AuthenticationMethods publickey" in reviewed
    assert "PermitRootLogin no" in reviewed
    assert "PermitTTY no" in reviewed
    assert "DisableForwarding yes" in reviewed
    assert "UsePrivilegeSeparation no" not in reviewed
    assert (
        "ForceCommand /usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-fs-only-launcher.py"
        in reviewed
    )
    assert "/usr/bin/sudo" not in reviewed


def test_non_admitted_rootless_candidate_does_not_change_image_or_compose():
    current = (ROOT / "deploy/ssh-target/Dockerfile.review-candidate").read_text()
    manager = (ROOT / "deploy/ssh-target/Dockerfile.manager-review-candidate").read_text()
    compose = (ROOT / "deploy/compose/compose.dev-ssh.yaml").read_text()
    assert "ssh-over-mcp-fs-only-launcher.py" not in current + manager + compose
    assert "sshd_config.fs-only-review-candidate" not in current + manager + compose
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in current
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-manager-hold"]' in manager
    assert compose.count('security_opt: ["no-new-privileges:true"]') == 2
    assert compose.count('cap_drop: ["ALL"]') == 2


def test_no_extra_argv_or_ssh_client_command(monkeypatch):
    entry = _entry()
    monkeypatch.setattr(entry.os, "environ", {"SSH_ORIGINAL_COMMAND": "mcp-v1"})
    monkeypatch.setattr(entry, "_kernel_identity", lambda: pytest.fail("no probe"))
    with pytest.raises(entry.FsOnlyStartRefused, match="arguments"):
        entry.main(argv=("--write-outside",))
    monkeypatch.setattr(entry.os, "environ", {"SSH_ORIGINAL_COMMAND": "/bin/sh"})
    with pytest.raises(entry.FsOnlyStartRefused, match="fixed SSH"):
        entry.main(argv=())


def test_mutable_or_symlinked_trusted_code_is_denied(tmp_path, monkeypatch):
    entry = _entry()
    file = tmp_path / "module.py"
    file.write_text("pass\n")
    # Substitute only leaf metadata; Linux guest must prove real root ownership.
    monkeypatch.setattr(
        entry.os,
        "lstat",
        lambda path: SimpleNamespace(
            st_uid=0,
            st_mode=(stat.S_IFLNK | 0o777) if str(path) == str(file) else (stat.S_IFDIR | 0o755),
            st_nlink=1,
        ),
    )
    with pytest.raises(entry.FsOnlyStartRefused, match="linked"):
        entry._trusted(str(file))


@pytest.mark.parametrize(
    "name,mode,accepted",
    [
        ("cli.py", stat.S_IFREG | 0o644, True),
        ("cli.py", stat.S_IFREG | 0o666, False),
        ("cli.py", stat.S_IFLNK | 0o777, False),
        ("cli.pyc", stat.S_IFREG | 0o444, False),
        ("__pycache__", stat.S_IFDIR | 0o555, False),
    ],
)
def test_full_import_tree_rejects_writable_symlinked_and_cached_code(
    monkeypatch, name, mode, accepted
):
    from contextlib import nullcontext

    entry = _entry()
    item = SimpleNamespace(
        name=name,
        path="/review/root/" + name,
        stat=lambda *, follow_symlinks: SimpleNamespace(st_uid=0, st_mode=mode, st_nlink=1),
    )
    monkeypatch.setattr(entry, "_trusted", lambda _path, directory: None)
    monkeypatch.setattr(entry.os, "scandir", lambda _directory: nullcontext([item]))
    if accepted:
        entry._trusted_import_tree("/review/root")
    else:
        with pytest.raises(entry.FsOnlyStartRefused):
            entry._trusted_import_tree("/review/root")


def test_main_checks_complete_import_tree_before_application(monkeypatch):
    entry = _entry()
    trace = []
    monkeypatch.setattr(entry.os, "environ", {"SSH_ORIGINAL_COMMAND": "mcp-v1"})
    monkeypatch.setattr(entry, "_kernel_identity", lambda: trace.append("kernel"))
    monkeypatch.setattr(entry, "_data_root", lambda: trace.append("volume"))
    monkeypatch.setattr(entry, "_trusted", lambda *_args, **_kwargs: None)

    def deny_tree(path):
        trace.append(path)
        raise entry.FsOnlyStartRefused("full module closure untrusted")

    monkeypatch.setattr(entry, "_trusted_import_tree", deny_tree)
    with pytest.raises(entry.FsOnlyStartRefused, match="module closure"):
        entry.main(argv=())
    assert trace == ["kernel", "volume", entry.SOURCE]
