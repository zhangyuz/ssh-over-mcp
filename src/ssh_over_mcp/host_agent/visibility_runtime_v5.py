"""Restricted local v5 trust inputs and persistent anti-replay store.

No active Host Agent or MCP code imports this module. Enabling it requires
a separately reviewed private config, key provisioning and epoch ACK plan.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .visibility_policy_v5 import VisibilityPolicyV5, canonical_visibility_path

_NONCE_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_NONCES = 100_000


class VisibilityRuntimeError(RuntimeError):
    """The local v5 runtime trust state is unavailable or unsafe."""


def _file_path(value: str) -> str:
    try:
        path = canonical_visibility_path(value)
    except ValueError as exc:
        raise ValueError("unsafe local v5 file path") from exc
    if path == "/":
        raise ValueError("local v5 file path needs a basename")
    return path


class HostVisibilityRuntimeV5(BaseModel):
    """Explicit local capability, distinct from legacy Host Policy v3/v4."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    version: Literal[5]
    enabled: Literal[True]
    host: str = Field(min_length=1, max_length=128)
    host_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signer_key_path: str
    nonce_db_path: str
    visibility: VisibilityPolicyV5

    @field_validator("signer_key_path", "nonce_db_path")
    @classmethod
    def canonical_file_path(cls, value: str) -> str:
        return _file_path(value)

    @model_validator(mode="after")
    def match_host(self) -> HostVisibilityRuntimeV5:
        if (
            not self.visibility.enabled
            or self.visibility.host != self.host
            or self.nonce_db_path == self.signer_key_path
        ):
            raise ValueError("invalid v5 host visibility runtime binding")
        return self


def _require_protected_parent(path: Path) -> None:
    try:
        info = path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise VisibilityRuntimeError("v5 private parent is unsafe")
        if path.parent.resolve(strict=True) != path.parent:
            raise VisibilityRuntimeError("v5 private parent is unsafe")
    except OSError as exc:
        raise VisibilityRuntimeError("v5 private parent is unsafe") from exc


def _require_owned_regular(info: os.stat_result, *, key: bool) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) not in ({0o400, 0o600} if key else {0o600})
        or info.st_nlink != 1
    ):
        raise VisibilityRuntimeError("v5 private file identity is unsafe")


def load_trusted_visibility_key(path: Path | str) -> bytes:
    """Read a separately provisioned 32-byte key without following symlinks."""

    try:
        text = _file_path(str(path))
        file = Path(text)
        _require_protected_parent(file)
        fd = os.open(
            file,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            before = os.fstat(fd)
            _require_owned_regular(before, key=True)
            if before.st_size != 32:
                raise VisibilityRuntimeError("v5 trusted key length invalid")
            data = os.read(fd, 33)
            after = os.fstat(fd)
            if len(data) != 32 or (
                before.st_dev,
                before.st_ino,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise VisibilityRuntimeError("v5 trusted key changed")
            return data
        finally:
            os.close(fd)
    except VisibilityRuntimeError:
        raise
    except (OSError, ValueError) as exc:
        raise VisibilityRuntimeError("v5 trusted key unavailable") from exc


class PersistentSnapshotNonces:
    """An atomic on-disk nonce ledger under a private, owner-only directory.

    A bounded store refusing new work when full is safer than silently
    forgetting old nonce history after host restart or clock rollback.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(_file_path(str(db_path)))

    def _open_db(self) -> sqlite3.Connection:
        _require_protected_parent(self.db_path)
        try:
            try:
                fd = os.open(self.db_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            except FileNotFoundError:
                try:
                    fd = os.open(
                        self.db_path,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0o600,
                    )
                except FileExistsError:
                    fd = os.open(self.db_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                _require_owned_regular(os.fstat(fd), key=False)
            finally:
                os.close(fd)
            # Parent is private 0700 with the same UID. No untrusted actor
            # can swap the filename between this check and SQLite's open.
            connection = sqlite3.connect(str(self.db_path), timeout=2.0, isolation_level=None)
            connection.execute("PRAGMA busy_timeout=2000")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS nonces "
                "(id TEXT PRIMARY KEY NOT NULL, expires_at INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS policy_epoch_state "
                "(id INTEGER PRIMARY KEY CHECK (id = 1), "
                "epoch INTEGER NOT NULL, digest TEXT NOT NULL)"
            )
            return connection
        except (sqlite3.Error, OSError, VisibilityRuntimeError) as exc:
            raise VisibilityRuntimeError("v5 nonce persistence unavailable") from exc

    def consume(self, snapshot_id: str, *, expires_at: int, now: int) -> bool:
        if (
            not isinstance(snapshot_id, str)
            or _NONCE_ID.fullmatch(snapshot_id) is None
            or type(expires_at) is not int
            or type(now) is not int
            or expires_at <= now
        ):
            raise VisibilityRuntimeError("invalid v5 nonce claim")
        connection = self._open_db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            (count,) = connection.execute("SELECT COUNT(*) FROM nonces").fetchone()
            if count >= _MAX_NONCES:
                raise VisibilityRuntimeError("v5 nonce resource limit reached")
            before = connection.total_changes
            connection.execute(
                "INSERT OR IGNORE INTO nonces(id, expires_at) VALUES (?,?)",
                (snapshot_id, expires_at),
            )
            accepted = connection.total_changes == before + 1
            connection.execute("COMMIT")
            return accepted
        except (sqlite3.Error, VisibilityRuntimeError) as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise VisibilityRuntimeError("v5 nonce persistence unavailable") from exc
        finally:
            connection.close()

    def consume_bound(
        self,
        snapshot_id: str,
        *,
        expires_at: int,
        now: int,
        policy_epoch: int,
        central_policy_sha256: str,
    ) -> bool:
        """Atomically consume a request and retain a nondecreasing policy epoch.

        This is a host-local rollback floor, NOT a central policy revocation
        ACK. The database must survive restarts and must not be reset during
        a downgrade. The host policy must be independently trusted.
        """

        if (
            not isinstance(snapshot_id, str)
            or _NONCE_ID.fullmatch(snapshot_id) is None
            or type(expires_at) is not int
            or type(now) is not int
            or expires_at <= now
            or type(policy_epoch) is not int
            or policy_epoch < 1
            or type(central_policy_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", central_policy_sha256) is None
        ):
            raise VisibilityRuntimeError("invalid v5 snapshot epoch binding")

        connection = self._open_db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT epoch, digest FROM policy_epoch_state WHERE id=1"
            ).fetchone()
            if row is not None and (
                policy_epoch < row[0]
                or (policy_epoch == row[0] and central_policy_sha256 != row[1])
            ):
                raise VisibilityRuntimeError("v5 policy epoch rollback refused")

            (count,) = connection.execute("SELECT COUNT(*) FROM nonces").fetchone()
            if count >= _MAX_NONCES:
                raise VisibilityRuntimeError("v5 nonce resource limit reached")
            before = connection.total_changes
            connection.execute(
                "INSERT OR IGNORE INTO nonces(id, expires_at) VALUES (?,?)",
                (snapshot_id, expires_at),
            )
            accepted = connection.total_changes == before + 1
            if accepted and (row is None or policy_epoch > row[0]):
                connection.execute(
                    "INSERT INTO policy_epoch_state (id, epoch, digest) VALUES (1, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch, "
                    "digest=excluded.digest",
                    (policy_epoch, central_policy_sha256),
                )
            connection.execute("COMMIT")
            return accepted
        except (sqlite3.Error, VisibilityRuntimeError) as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise VisibilityRuntimeError("v5 snapshot epoch persistence unavailable") from exc
        finally:
            connection.close()


def load_host_visibility_runtime(path: Path | str) -> HostVisibilityRuntimeV5:
    """Read an owner-protected v5 JSON policy and reject duplicate keys.

    Active v1/v3/v4 policy loading remains unchanged. A separate trusted
    ForceCommand configuration must select this loader for a v2 request.
    """

    import json

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise VisibilityRuntimeError("duplicate v5 policy member")
            result[key] = value
        return result

    try:
        path = Path(_file_path(str(path)))
        _require_protected_parent(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            _require_owned_regular(before, key=True)
            if not 1 <= before.st_size <= 64 * 1024:
                raise VisibilityRuntimeError("v5 policy size invalid")
            raw = os.read(fd, 64 * 1024 + 1)
            after = os.fstat(fd)
            before_id = (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            after_id = (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
            if len(raw) != before.st_size or before_id != after_id:
                raise VisibilityRuntimeError("v5 policy changed during read")
        finally:
            os.close(fd)
        parsed = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs)
        return HostVisibilityRuntimeV5.model_validate_json(
            json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
        )
    except Exception as exc:
        raise VisibilityRuntimeError("trusted v5 host policy unavailable") from exc
