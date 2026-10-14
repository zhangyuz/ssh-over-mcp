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
        uncertain = False
        for attr in ("claim_fd", "library_fd"):
            fd = getattr(self, attr)
            if fd >= 0:
                setattr(self, attr, -1)
                try:
                    os.close(fd)
                except (OSError, RuntimeError):
                    uncertain = True
        if uncertain:
            raise NamespaceError("namespace", cleanup_uncertain=True) from None


def _claim_disposable_fixture(library_fd: int) -> _FixtureClaimPermit:
    """Create a *different*, test-only marker in a disposable Library.

    Requires the test harness to own the parent FD. The fixed production
    active-run.json is NEVER opened, inspected, created or deleted here.
    """
    owned_fd = -1
    claim_fd = -1
    transferred = False
    try:
        owned_fd = os.open(".", _DIR_FLAGS, dir_fd=library_fd)
        _validate_private_dir(owned_fd)
        if _bounded_names(owned_fd, maximum=0):
            raise NamespaceError("residual")
        claim_fd = os.open(_CLAIM_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=owned_fd)
        claimed = _identity(claim_fd)
        if not stat.S_ISREG(claimed[4]) or claimed[2] != os.getuid() or stat.S_IMODE(claimed[4]) != 0o600:
            raise NamespaceError("namespace")
        os.fsync(claim_fd)
        permit = _FixtureClaimPermit(owned_fd, claim_fd, _identity(owned_fd), claimed)
        transferred = True
        return permit
    except (OSError, ValueError, TypeError) as exc:
        raise NamespaceError("namespace", cleanup_uncertain=not isinstance(exc, OSError)) from None
    finally:
        # On failure, close FDs but keep the O_EXCL marker as forensic evidence.
        if not transferred:
            for fd in (claim_fd, owned_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        # Descriptor state unknown; never retry or delete a marker.
                        pass



@dataclass(frozen=True, slots=True)
class _FixtureEdge:
    parent_fd: int
    name: str
    child_fd: int
    identity: tuple[int, ...]


def _bounded_names(fd: int, *, maximum: int) -> list[str]:
    """Enumerate only up to maximum+1, never materialize a whole foreign dir."""
    if not 0 <= maximum <= 128:
        raise NamespaceError("budget")
    scan_fd = os.open(".", _DIR_FLAGS, dir_fd=fd)
    names: list[str] = []
    try:
        with os.scandir(scan_fd) as stream:
            for entry in stream:
                if len(names) >= maximum:
                    raise NamespaceError("budget", cleanup_uncertain=True)
                if type(entry.name) is not str or not entry.name or "/" in entry.name:
                    raise NamespaceError("namespace", cleanup_uncertain=True)
                names.append(entry.name)
        return names
    finally:
        os.close(scan_fd)


class _FixtureOwnedWorkspace:
    """Only a disposable, never-launched fixture; NOT a live OwnedWorkspace."""

    def __init__(
        self,
        permit: _FixtureClaimPermit,
        staging_fd: int,
        root_fd: int,
        name: str,
        ancestors: tuple[_FixtureEdge, ...],
    ) -> None:
        self._permit = permit
        self._staging_fd = staging_fd
        self._root_fd = root_fd
        self._ancestors = ancestors
        self.name = name
        self.root_identity = _identity(root_fd)
        self.parent_identity = _identity(staging_fd)
        self._closed = False
        self._cleanup_state = "new"
        self._receipt_token = object()

    def _verify_claim_and_ancestors(self) -> None:
        permit = self._permit
        if self._closed or permit.library_fd < 0 or permit.claim_fd < 0:
            raise NamespaceError("unbound")
        if _identity(permit.library_fd) != permit.library_identity:
            raise NamespaceError("drift")
        if _identity(permit.claim_fd) != permit.claim_identity:
            raise NamespaceError("drift")
        claim = os.stat(_CLAIM_NAME, dir_fd=permit.library_fd, follow_symlinks=False)
        if (
            (claim.st_dev, claim.st_ino, claim.st_uid, claim.st_gid, claim.st_mode)
            != _stable_id(permit.claim_identity)
            or not stat.S_ISREG(claim.st_mode)
            or claim.st_nlink != 1
        ):
            raise NamespaceError("unbound")
        if len(self._ancestors) != len(_FIXED_MISSING):
            raise NamespaceError("unbound")
        for pos, edge in enumerate(self._ancestors):
            if edge.name != _FIXED_MISSING[pos]:
                raise NamespaceError("unbound")
            parent = permit.library_fd if pos == 0 else self._ancestors[pos - 1].child_fd
            if parent != edge.parent_fd or edge.child_fd < 0:
                raise NamespaceError("unbound")
            if _identity(edge.child_fd) != edge.identity:
                raise NamespaceError("drift")
            observed = os.stat(edge.name, dir_fd=parent, follow_symlinks=False)
            if (
                (observed.st_dev, observed.st_ino, observed.st_uid,
                 observed.st_gid, observed.st_mode)
                != _stable_id(edge.identity)
                or not stat.S_ISDIR(observed.st_mode)
            ):
                raise NamespaceError("drift")
            _validate_private_dir(edge.child_fd)
            allowed = {_CLAIM_NAME, _FIXED_MISSING[0]} if pos == 0 else {
                _FIXED_MISSING[pos]
            }
            if set(_bounded_names(parent, maximum=len(allowed))) != allowed:
                raise NamespaceError("residual")
        if self._ancestors[-1].child_fd != self._staging_fd:
            raise NamespaceError("unbound")
        _validate_private_dir(permit.library_fd)

    def verify_single_owned_child(self) -> None:
        if self._closed or self._root_fd < 0 or self._staging_fd < 0:
            raise NamespaceError("unbound")
        self._verify_claim_and_ancestors()
        if _identity(self._staging_fd) != self.parent_identity:
            raise NamespaceError("drift")
        if _stable_id(_identity(self._root_fd)) != _stable_id(self.root_identity):
            raise NamespaceError("drift")
        actual = os.stat(self.name, dir_fd=self._staging_fd, follow_symlinks=False)
        if (
            (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_gid, actual.st_mode)
            != _stable_id(self.root_identity)
            or not stat.S_ISDIR(actual.st_mode)
        ):
            raise NamespaceError("drift")
        if _bounded_names(self._staging_fd, maximum=1) != [self.name]:
            raise NamespaceError("residual")
        _validate_private_dir(self._staging_fd)
        _validate_private_dir(self._root_fd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        uncertain = False
        unique_fds: set[int] = set()
        for fd in (self._root_fd, *(edge.child_fd for edge in self._ancestors)):
            if fd >= 0:
                unique_fds.add(fd)
        self._root_fd = -1
        self._staging_fd = -1
        self._ancestors = ()
        for fd in unique_fds:
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
    """Never a provider capability: fixture-only held-FD create and verify."""
    if type(permit) is not _FixtureClaimPermit or permit.consumed:
        raise NamespaceError("unbound")
    current_fd = permit.library_fd
    opened: list[int] = []
    owned: _FixtureOwnedWorkspace | None = None
    modified = False
    failure: BaseException | None = None
    try:
        if current_fd < 0 or permit.claim_fd < 0:
            raise NamespaceError("unbound")
        if _identity(current_fd) != permit.library_identity:
            raise NamespaceError("drift")
        if _identity(permit.claim_fd) != permit.claim_identity:
            raise NamespaceError("drift")
        original = os.stat(_CLAIM_NAME, dir_fd=current_fd, follow_symlinks=False)
        if (
            (original.st_dev, original.st_ino) != permit.claim_identity[:2]
            or original.st_mode != permit.claim_identity[4]
            or original.st_uid != permit.claim_identity[2]
        ):
            raise NamespaceError("unbound")
        if _bounded_names(current_fd, maximum=1) != [_CLAIM_NAME]:
            raise NamespaceError("residual")
        permit.consumed = True
        edges: list[_FixtureEdge] = []
        for expected in _FIXED_MISSING:
            _validate_private_dir(current_fd)
            allowed = {_CLAIM_NAME} if expected == _FIXED_MISSING[0] else set()
            if set(_bounded_names(current_fd, maximum=len(allowed))) != allowed:
                raise NamespaceError("residual")
            before = _identity(current_fd)
            modified = True
            os.mkdir(expected, mode=0o700, dir_fd=current_fd)
            next_fd = os.open(expected, _DIR_FLAGS, dir_fd=current_fd)
            opened.append(next_fd)  # ownership is recorded BEFORE validation
            _validate_private_dir(next_fd)
            if set(_bounded_names(current_fd, maximum=len(allowed) + 1)) != (
                allowed | {expected}
            ):
                raise NamespaceError("drift")
            after = _identity(current_fd)
            if _stable_id(before) != _stable_id(after):
                raise NamespaceError("drift")
            edges.append(_FixtureEdge(current_fd, expected, next_fd, _identity(next_fd)))
            current_fd = next_fd
        staging_fd = current_fd
        name = _RUN_PREFIX + secrets.token_hex(16)
        modified = True
        os.mkdir(name, mode=0o700, dir_fd=staging_fd)
        root_fd = os.open(name, _DIR_FLAGS, dir_fd=staging_fd)
        opened.append(root_fd)
        _validate_private_dir(root_fd)
        if os.fstat(root_fd).st_dev != os.fstat(staging_fd).st_dev:
            raise NamespaceError("namespace")
        # The only explicitly allowed parent timestamp changes are these
        # witnessed mkdir operations, followed by exact child inventories.
        permit.library_identity = _identity(permit.library_fd)
        refreshed = tuple(
            _FixtureEdge(e.parent_fd, e.name, e.child_fd, _identity(e.child_fd))
            for e in edges
        )
        owned = _FixtureOwnedWorkspace(permit, staging_fd, root_fd, name, refreshed)
        owned.verify_single_owned_child()
        opened.clear()  # transferred to the owned workspace
        return owned
    except BaseException as exc:  # noqa: BLE001 - close all FDs even on interrupt
        failure = exc
        raise NamespaceError(
            "namespace" if not isinstance(exc, NamespaceError) else exc.reason,
            cleanup_uncertain=modified or getattr(exc, "cleanup_uncertain", False),
        ) from None
    finally:
        if failure is not None:
            close_uncertain = False
            # Every local FD is tracked when opened, not after its validation.
            for fd in reversed(opened):
                try:
                    os.close(fd)
                except (OSError, RuntimeError):
                    close_uncertain = True
            opened.clear()
            try:
                permit.close()
            except (OSError, RuntimeError, NamespaceError):
                close_uncertain = True
            if owned is not None:
                # All owned FDs were in opened; do not close them a second time.
                owned._closed = True
                owned._root_fd = -1
                owned._staging_fd = -1
                owned._ancestors = ()
                owned._cleanup_state = "uncertain"
            if close_uncertain:
                # An uncertain close cannot be retried or treated as success.
                raise NamespaceError("namespace", cleanup_uncertain=True) from None


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
    """Stream at most 129 names/level, never materialize an unbounded directory."""
    if depth >= 10 or budget[0] >= 512:
        raise NamespaceError("budget", cleanup_uncertain=True)
    _validate_private_dir(root_fd)
    names = _bounded_names(root_fd, maximum=min(128, 512 - budget[0]))
    for name in names:
        budget[0] += 1
        if budget[0] > 512:
            raise NamespaceError("budget", cleanup_uncertain=True)
        if name in (".", "..") or "\\x00" in name:
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
        if _bounded_names(workspace._staging_fd, maximum=0):
            raise NamespaceError("residual", cleanup_uncertain=True)
        workspace._cleanup_state = "disposed"
        workspace.close()
    except BaseException:  # noqa: BLE001 - even interrupt must prohibit cleanup retry
        workspace._cleanup_state = "uncertain"
        raise NamespaceError("namespace", cleanup_uncertain=True) from None
