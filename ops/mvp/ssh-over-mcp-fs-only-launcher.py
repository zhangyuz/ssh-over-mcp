"""TEST-ONLY non-sudo SSH filesystem entrypoint; not a runtime admission.

Does not touch cgroups, change credentials, invoke sudo, or execute commands.
The guest must independently prove sshd can authenticate/drop to this identity
under its actual OCI NNP/capability boundary before wiring this ForceCommand.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

SSH_UID = 2201
SSH_GID = 3201
SOURCE = "/opt/ssh-over-mcp-e2e/workspace/src"
SITE_PACKAGES = "/opt/ssh-over-mcp-e2e/venv/lib/python3.14/site-packages"
POLICY_FILE = "/etc/ssh-over-mcp/host-policy.yaml"
DATA_ROOT = "/srv/data"


class FsOnlyStartRefused(RuntimeError):
    """The immutable filesystem-only trust boundary was not verified."""


def _trusted(path: str, *, directory: bool = False) -> None:
    current = Path("/")
    for part in Path(path).parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise FsOnlyStartRefused("trusted image component unavailable") from exc
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise FsOnlyStartRefused("mutable or linked image component")
        if current == Path(path) and not directory:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise FsOnlyStartRefused("untrusted image file")
        elif not stat.S_ISDIR(info.st_mode):
            raise FsOnlyStartRefused("untrusted image directory")


def _kernel_identity() -> None:
    if sys.platform != "linux" or not sys.flags.isolated or not sys.flags.no_site:
        raise FsOnlyStartRefused("isolated Linux Python -I -S required")
    if os.getresuid() != (SSH_UID,) * 3 or os.getresgid() != (SSH_GID,) * 3:
        raise FsOnlyStartRefused("nonroot SSH identity mismatch")
    if not set(os.getgroups()) <= {SSH_GID}:
        raise FsOnlyStartRefused("unexpected supplementary group")
    needed = {"Uid", "Gid", "NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
    found: dict[str, str] = {}
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                key, sep, value = line.partition(":")
                if sep and key in needed:
                    if key in found:
                        raise FsOnlyStartRefused("duplicate privilege field")
                    found[key] = value.strip()
    except (OSError, UnicodeError) as exc:
        raise FsOnlyStartRefused("kernel privilege evidence unavailable") from exc
    zero = "0000000000000000"
    if (
        set(found) != needed
        or found["Uid"] != ("\t".join([str(SSH_UID)] * 4))
        or found["Gid"] != ("\t".join([str(SSH_GID)] * 4))
        or found["NoNewPrivs"] != "1"
        or any(found[name] != zero for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    ):
        raise FsOnlyStartRefused("NNP, filesystem identity or zero caps unverified")


def _trusted_import_tree(root: str) -> None:
    """Require immutable full source/venv import closure, not only __init__."""
    _trusted(root, directory=True)
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name == "__pycache__" or entry.name.endswith((".pyc", ".pyo")):
                        raise FsOnlyStartRefused("unreviewed import bytecode")
                    info = entry.stat(follow_symlinks=False)
                    if (
                        info.st_uid != 0
                        or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
                        or stat.S_ISLNK(info.st_mode)
                    ):
                        raise FsOnlyStartRefused("mutable or linked imported code")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(entry.path)
                    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise FsOnlyStartRefused("untrusted import tree component")
        except (OSError, UnicodeError) as exc:
            raise FsOnlyStartRefused("trusted import tree unavailable") from exc


def _data_root() -> None:
    # The separately provisioned, per-node volume must not silently retain
    # the old privileged agent's 2202:3202 ownership.
    try:
        info = os.lstat(DATA_ROOT)
    except OSError as exc:
        raise FsOnlyStartRefused("node data root unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != SSH_UID
        or info.st_gid != SSH_GID
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise FsOnlyStartRefused("untrusted filesystem-only data root")


def _fixed_policy(policy: object) -> None:
    """Reject a v4/executable, expanded profile or widened filesystem policy."""
    if (
        getattr(policy, "version", None) != 3
        or getattr(policy, "containment", None) is not None
        or getattr(policy, "allowed_profiles", None) != {"rw-operator"}
        or set(getattr(policy, "filesystem", {})) != {"rw-operator"}
    ):
        raise FsOnlyStartRefused("not fixed filesystem-only policy")
    fs = policy.filesystem["rw-operator"]
    if (
        any(
            getattr(fs, name) != (DATA_ROOT,)
            for name in ("stat_roots", "read_roots", "mkdir_roots", "write_create_roots")
        )
        or fs.max_read_bytes != 4096
        or fs.max_write_bytes != 4096
    ):
        raise FsOnlyStartRefused("filesystem policy unexpectedly expanded")

    # v3 currently refuses execution, but do not admit a silently broadened
    # command or environment policy should a later Host Agent gain a backend.
    commands = policy.commands
    command = commands.get("/usr/bin/true")
    limits = policy.child_limits
    if (
        set(commands) != {"/usr/bin/true"}
        or command is None
        or command.resolved_path != "/usr/bin/true"
        or len(command.argv) != 1
        or command.argv[0].mode != "exact"
        or command.argv[0].args != ()
        or command.cwd_roots != ()
        or not command.allow_no_cwd
        or not command.require_root_owned
        or command.allow_group_or_world_writable
        or command.allow_setuid_or_setgid
        or command.allow_file_capabilities
        or policy.env_allow
        or policy.max_timeout_seconds != 10
        or policy.max_output_bytes != 8192
        or policy.max_stdin_bytes != 0
        or (
            limits.cpu_seconds,
            limits.address_space_bytes,
            limits.max_processes,
            limits.file_size_bytes,
            limits.open_files,
        )
        != (10, 536870912, 8, 4194304, 64)
    ):
        raise FsOnlyStartRefused("filesystem-only policy limits unexpectedly expanded")


def _fixed_v5_policy(config: object) -> None:
    """v2 listing cannot widen the earlier fixed /srv/data FS-only authority."""
    if getattr(config, "version", None) != 5 or getattr(config, "enabled", None) is not True:
        raise FsOnlyStartRefused("v5 trusted policy unavailable")
    visibility = getattr(config, "visibility", None)
    operations = getattr(visibility, "operations", None)
    if getattr(visibility, "enabled", None) is not True or not isinstance(operations, dict):
        raise FsOnlyStartRefused("v5 visibility operations unavailable")
    if set(operations) != {"fs_list", "fs_search"}:
        raise FsOnlyStartRefused("unexpected v5 visibility operations")
    for rules in operations.values():
        roots = getattr(rules, "allow_roots", ())
        if not roots or any(
            not isinstance(root, str)
            or (root != DATA_ROOT and not root.startswith(DATA_ROOT + "/"))
            for root in roots
        ):
            raise FsOnlyStartRefused("v5 filesystem roots exceed FS-only authority")


def main(argv: tuple[str, ...] | None = None) -> int:
    if tuple(sys.argv[1:] if argv is None else argv):
        raise FsOnlyStartRefused("no CLI arguments permitted")
    if os.environ.get("SSH_ORIGINAL_COMMAND") not in {"mcp-v1", "mcp-v2"} or os.environ.get(
        "SSH_TTY"
    ):
        raise FsOnlyStartRefused("not a fixed SSH command")
    _kernel_identity()
    _data_root()
    for target, directory in (
        (SOURCE, True),
        (SOURCE + "/ssh_over_mcp/__init__.py", False),
        (SOURCE + "/ssh_over_mcp/host_agent/__init__.py", False),
        (SITE_PACKAGES, True),
        (POLICY_FILE, False),
    ):
        _trusted(target, directory=directory)
    _trusted_import_tree(SOURCE)
    _trusted_import_tree(SITE_PACKAGES)
    # The application dependencies are imported only after identity, NNP and
    # immutable policy/code paths are checked. These paths are not SSH input.
    sys.dont_write_bytecode = True
    sys.path.insert(0, SOURCE)
    sys.path.insert(1, SITE_PACKAGES)
    from ssh_over_mcp.host_agent.cli import run
    from ssh_over_mcp.host_agent.policy import load_host_policy

    policy = load_host_policy(Path(POLICY_FILE))
    _fixed_policy(policy)
    saved_command = os.environ["SSH_ORIGINAL_COMMAND"]
    os.environ.clear()
    os.environ.update(
        SSH_ORIGINAL_COMMAND=saved_command,
        HOME="/nonexistent",
        PATH="/usr/bin:/bin",
        LANG="C.UTF-8",
    )
    if saved_command == "mcp-v2":
        # A distinct, fully trusted v5 config is mandatory. No v1 fallback.
        # This is source-only until an operator approves a new image and
        # independently proves the actual immutable mounts/host SSH identity.
        from ssh_over_mcp.host_agent.cli_v2 import DEFAULT_POLICY_V2, run_v2
        from ssh_over_mcp.host_agent.visibility_runtime_v5 import (
            load_host_visibility_runtime,
        )

        _trusted(str(DEFAULT_POLICY_V2))
        local_v5 = load_host_visibility_runtime(DEFAULT_POLICY_V2)
        _fixed_v5_policy(local_v5)
        return run_v2(
            env=dict(os.environ),
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr,
            execution_stderr=sys.stderr.buffer,
            policy_path=DEFAULT_POLICY_V2,
        )

    return run(
        env=dict(os.environ),
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr,
        execution_stderr=sys.stderr.buffer,
        policy=policy,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FsOnlyStartRefused, OSError, ValueError, RuntimeError):
        sys.stderr.write("ssh-over-mcp FS-only candidate refused\n")
        raise SystemExit(78) from None
