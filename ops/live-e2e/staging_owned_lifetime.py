"""ADR 0019 Slice 2A: unbound live API and disposable FD-scoped fixture primitives.

There is deliberately NO connection to the fixed provider marker, the
already-main orchestrator, QEMU or any production path. Private fixture
methods cannot authorize a real provider allocation, reap or cleanup.
"""

from __future__ import annotations

import os
import platform
import secrets
import stat
from dataclasses import dataclass

from staging_namespace_types import NamespaceError

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CLAIM_NAME = ".adr19-disposable-claim"
_FIXED_MISSING = ("Application Support", "ssh-over-mcp-e2e", "staging-v1")
_RUN_PREFIX = "ssh-over-mcp-e2e-"


def create_owned_workspace() -> None:
    """No original trusted-main O_EXCL handoff exists: NEVER mkdir."""
    raise NamespaceError("unbound")


class OwnedWorkspace:
    """Reserved live lifecycle; no trusted run-completion receipt issuer exists."""

    def __init__(self) -> None:
        raise NamespaceError("unbound")

    def dispose(self, receipt: object) -> None:
        raise NamespaceError("unbound")

    def close(self) -> None:
        """A live handle cannot be created until reviewed 2B."""


def _identity(fd: int) -> tuple[int, int, int, int, int, int, int]:
    st = os.fstat(fd)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_mtime_ns, st.st_ctime_ns)


def _stable_id(identity: tuple[int, ...]) -> tuple[int, ...]:
    return identity[:5]


def _validate_private_dir(fd: int) -> None:
    ident = _identity(fd)
    if not stat.S_ISDIR(ident[4]) or ident[2] != os.getuid() or stat.S_IMODE(ident[4]) != 0o700:
        raise NamespaceError("namespace")
    if platform.system() == "Darwin":
        from staging_namespace_native import read_acl

        if read_acl(fd).tags:
            raise NamespaceError("namespace")


@dataclass(slots=True)
class _FixtureClaimPermit:
    """Test-owned exclusive O_EXCL claim, NEVER a provider capability."""

    library_fd: int
    claim_fd: int
    library_identity: tuple[int, ...]
    claim_identity: tuple[int, ...]
    consumed: bool = False

    def close(self) -> None:
        for attr in ("claim_fd", "library_fd"):
            fd = getattr(self, attr)
            if fd >= 0:
                setattr(self, attr, -1)
                os.close(fd)


def _claim_disposable_fixture(library_fd: int) -> _FixtureClaimPermit:
    """Create a *different*, test-only marker in a disposable Library.

    Requires the test harness to own the parent FD. The fixed production
    active-run.json is NEVER opened, inspected, created or deleted here.
    """
    owned_fd = -1
    claim_fd = -1
    try:
        owned_fd = os.open(".", _DIR_FLAGS, dir_fd=library_fd)
        _validate_private_dir(owned_fd)
        if os.listdir(owned_fd):
            raise NamespaceError("residual")
        claim_fd = os.open(_CLAIM_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=owned_fd)
        claimed = _identity(claim_fd)
        if not stat.S_ISREG(claimed[4]) or claimed[2] != os.getuid() or stat.S_IMODE(claimed[4]) != 0o600:
            raise NamespaceError("namespace")
        os.fsync(claim_fd)
        return _FixtureClaimPermit(owned_fd, claim_fd, _identity(owned_fd), claimed)
    except (OSError, ValueError, TypeError) as exc:
        raise NamespaceError("namespace", cleanup_uncertain=not isinstance(exc, OSError)) from None
    finally:
        # An exception after O_EXCL leaves a test-only marker as evidence.
        if claim_fd >= 0 and "claimed" not in locals():
            os.close(claim_fd)
        if owned_fd >= 0 and "claimed" not in locals():
            os.close(owned_fd)


class _FixtureOwnedWorkspace:
    """Only a disposable, never-launched fixture; NOT a live OwnedWorkspace."""

    def __init__(self, permit: _FixtureClaimPermit, staging_fd: int, root_fd: int,
                 name: str) -> None:
        self._permit = permit
        self._staging_fd = staging_fd
        self._root_fd = root_fd
        self.name = name
        self.root_identity = _identity(root_fd)
        self.parent_identity = _identity(staging_fd)
        self._closed = False
        self._cleanup_state = "new"
        self._receipt_token = object()

    def verify_single_owned_child(self) -> None:
        if self._closed or self._root_fd < 0 or self._staging_fd < 0:
            raise NamespaceError("unbound")
        if _identity(self._staging_fd) != self.parent_identity:
            raise NamespaceError("drift")
        if _stable_id(_identity(self._root_fd)) != _stable_id(self.root_identity):
            raise NamespaceError("drift")
        actual = os.stat(self.name, dir_fd=self._staging_fd, follow_symlinks=False)
        if (actual.st_dev, actual.st_ino) != self.root_identity[:2] or not stat.S_ISDIR(actual.st_mode):
            raise NamespaceError("drift")
        if os.listdir(self._staging_fd) != [self.name]:
            raise NamespaceError("residual")
        _validate_private_dir(self._root_fd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        uncertain = False
        for attr in ("_root_fd", "_staging_fd"):
            fd = getattr(self, attr)
            setattr(self, attr, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except (OSError, RuntimeError):
                    uncertain = True
        try:
            self._permit.close()
        except (OSError, RuntimeError, NamespaceError):
            uncertain = True
        if uncertain:
            self._cleanup_state = "uncertain"
            raise NamespaceError("namespace", cleanup_uncertain=True) from None

    def __del__(self) -> None:
        # No filesystem mutation, guest signal or cleanup retry in a destructor.
        try:
            self.close()
        except (OSError, RuntimeError, AttributeError, NamespaceError):
            pass


def _create_for_fixture(permit: _FixtureClaimPermit) -> _FixtureOwnedWorkspace:
    """Internal test adapter: held-FD creation after an actual disposable O_EXCL.

    The user-facing production entrypoint never calls this function.
    No arbitrary path, production-marker or provider identity is accepted.
    """
    if type(permit) is not _FixtureClaimPermit or permit.consumed:
        raise NamespaceError("unbound")
    stage_fd = -1
    root_fd = -1
    current_fd = permit.library_fd
    try:
        if current_fd < 0 or permit.claim_fd < 0:
            raise NamespaceError("unbound")
        if _identity(current_fd) != permit.library_identity:
            raise NamespaceError("drift")
        if _identity(permit.claim_fd) != permit.claim_identity:
            raise NamespaceError("drift")
        original = os.stat(_CLAIM_NAME, dir_fd=current_fd, follow_symlinks=False)
        if (original.st_dev, original.st_ino) != permit.claim_identity[:2]:
            raise NamespaceError("unbound")
        if os.listdir(current_fd) != [_CLAIM_NAME]:
            raise NamespaceError("residual")
        permit.consumed = True  # no reuse or collision adoption
        for expected in _FIXED_MISSING:
            _validate_private_dir(current_fd)
            entries = set(os.listdir(current_fd))
            allowed = {_CLAIM_NAME} if expected == _FIXED_MISSING[0] else set()
            if entries != allowed:
                raise NamespaceError("residual")
            parent_before = _identity(current_fd)
            os.mkdir(expected, mode=0o700, dir_fd=current_fd)
            next_fd = os.open(expected, _DIR_FLAGS, dir_fd=current_fd)
            _validate_private_dir(next_fd)
            if set(os.listdir(current_fd)) != allowed | {expected}:
                os.close(next_fd)
                raise NamespaceError("drift")
            parent_after = _identity(current_fd)
            if _stable_id(parent_before) != _stable_id(parent_after):
                os.close(next_fd)
                raise NamespaceError("drift")
            if current_fd != permit.library_fd:
                os.close(current_fd)
            current_fd = next_fd
        stage_fd = current_fd
        name = _RUN_PREFIX + secrets.token_hex(16)
        os.mkdir(name, mode=0o700, dir_fd=stage_fd)
        root_fd = os.open(name, _DIR_FLAGS, dir_fd=stage_fd)
        _validate_private_dir(root_fd)
        if os.fstat(root_fd).st_dev != os.fstat(stage_fd).st_dev:
            raise NamespaceError("namespace")
        workspace = _FixtureOwnedWorkspace(permit, stage_fd, root_fd, name)
        workspace.verify_single_owned_child()
        return workspace
    except NamespaceError:
        raise
    except (OSError, ValueError, TypeError):
        raise NamespaceError("namespace", cleanup_uncertain=True) from None
    finally:
        # Failed mutations are intentionally NOT rolled back (uncertain evidence).
        if "workspace" not in locals():
            if root_fd >= 0:
                os.close(root_fd)
            if current_fd >= 0 and current_fd != permit.library_fd:
                os.close(current_fd)


@dataclass(frozen=True, slots=True)
class _NeverStartedEvidence:
    """Unexported, fixture-only token: not a real QEMU reaping witness."""
    token: object


def _fixture_never_started_receipt(workspace: _FixtureOwnedWorkspace) -> _NeverStartedEvidence:
    if type(workspace) is not _FixtureOwnedWorkspace or workspace._closed:
        raise NamespaceError("unbound")
    if workspace._cleanup_state != "new":
        raise NamespaceError("unbound")
    return _NeverStartedEvidence(workspace._receipt_token)


def _remove_fixture_descendants(root_fd: int, budget: list[int], depth: int = 0) -> None:
    """Bounded, no-follow delete of *test-only* original held fixture descendants."""
    if depth >= 10:
        raise NamespaceError("budget", cleanup_uncertain=True)
    _validate_private_dir(root_fd)
    scan_fd = os.open(".", _DIR_FLAGS, dir_fd=root_fd)
    try:
        with os.scandir(scan_fd) as stream:
            entries = list(stream)
    finally:
        os.close(scan_fd)
    if len(entries) > 128:
        raise NamespaceError("budget", cleanup_uncertain=True)
    for entry in entries:
        budget[0] += 1
        if budget[0] > 512:
            raise NamespaceError("budget", cleanup_uncertain=True)
        name = entry.name
        if (type(name) is not str or not name or name in (".", "..")
                or "/" in name or "\x00" in name):
            raise NamespaceError("namespace", cleanup_uncertain=True)
        metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if metadata.st_uid != os.getuid():
            raise NamespaceError("namespace", cleanup_uncertain=True)
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = os.open(name, _DIR_FLAGS, dir_fd=root_fd)
            try:
                child = os.fstat(child_fd)
                if (child.st_dev, child.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise NamespaceError("drift", cleanup_uncertain=True)
                _remove_fixture_descendants(child_fd, budget, depth + 1)
                check = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if (check.st_dev, check.st_ino) != (child.st_dev, child.st_ino):
                    raise NamespaceError("drift", cleanup_uncertain=True)
                os.rmdir(name, dir_fd=root_fd)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise NamespaceError("namespace", cleanup_uncertain=True)
            check = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (check.st_dev, check.st_ino, check.st_mode) != (
                metadata.st_dev, metadata.st_ino, metadata.st_mode
            ):
                raise NamespaceError("drift", cleanup_uncertain=True)
            os.unlink(name, dir_fd=root_fd)
        else:
            raise NamespaceError("namespace", cleanup_uncertain=True)


def _dispose_never_started_fixture(
    workspace: _FixtureOwnedWorkspace,
    receipt: _NeverStartedEvidence,
) -> None:
    """Single-use test cleanup; NEVER a guest-run or production provider API."""
    if (
        type(workspace) is not _FixtureOwnedWorkspace
        or type(receipt) is not _NeverStartedEvidence
        or receipt.token is not workspace._receipt_token
        or workspace._cleanup_state != "new"
    ):
        raise NamespaceError("unbound")
    workspace.verify_single_owned_child()
    # No marker deletion and no automatic retry, even if one unlink succeeded.
    workspace._cleanup_state = "disposing"
    try:
        _remove_fixture_descendants(workspace._root_fd, [0])
        workspace.verify_single_owned_child()
        os.rmdir(workspace.name, dir_fd=workspace._staging_fd)
        if os.listdir(workspace._staging_fd):
            raise NamespaceError("residual", cleanup_uncertain=True)
        workspace._cleanup_state = "disposed"
        workspace.close()
    except BaseException:  # noqa: BLE001 - even interrupt must prohibit cleanup retry
        workspace._cleanup_state = "uncertain"
        raise NamespaceError("namespace", cleanup_uncertain=True) from None
