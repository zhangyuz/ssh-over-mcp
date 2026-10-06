from __future__ import annotations

import importlib
import importlib.util
import os
import stat
from pathlib import Path
from types import ModuleType

import pytest


def _keyfile() -> ModuleType:
    name = "ssh_over_mcp.approvals.keyfile"
    assert importlib.util.find_spec(name) is not None, "shared key writer must exist"
    return importlib.import_module(name)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_complete_short_writes_and_file_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    keyfile = _keyfile()
    payload = b"SYNTHETIC_KEY_WRITE_TEST_PAYLOAD"
    token_requests: list[int] = []
    writes: list[int] = []
    synced: list[int] = []
    lengths = iter((7, 9, 16))
    real_write = os.write
    real_fsync = os.fsync

    def token_bytes(length: int) -> bytes:
        token_requests.append(length)
        return payload

    def short_write(fd: int, data: memoryview) -> int:
        written = real_write(fd, data[: next(lengths)])
        writes.append(written)
        return written

    def fsync(fd: int) -> None:
        real_fsync(fd)
        synced.append(fd)

    monkeypatch.setattr(keyfile.secrets, "token_bytes", token_bytes)
    monkeypatch.setattr(os, "write", short_write)
    monkeypatch.setattr(os, "fsync", fsync)
    path = tmp_path / "key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        keyfile.write_hmac_key(fd, uid=os.getuid(), gid=os.getgid(), mode=mode)
        info = os.fstat(fd)
        assert synced == [fd]
        assert info.st_size == 32
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == mode
        assert (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
    finally:
        os.close(fd)

    assert token_requests == [32]
    assert writes == [7, 9, 16]
    assert path.read_bytes() == payload


@pytest.mark.parametrize("failure", ["zero-write", "write", "fchmod", "fchown", "fsync"])
def test_io_failure_has_only_safe_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    keyfile = _keyfile()
    secret = "SYNTHETIC_KEY_FAILURE_PAYLOAD"
    monkeypatch.setattr(keyfile.secrets, "token_bytes", lambda _: secret.encode().ljust(32))

    def fail(*args: object) -> None:
        raise OSError(secret)

    if failure == "zero-write":
        monkeypatch.setattr(os, "write", lambda *_: 0)
    else:
        monkeypatch.setattr(os, failure, fail)
    fd = os.open(tmp_path / "key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with pytest.raises(keyfile.KeyFileError) as error:
            keyfile.write_hmac_key(fd, uid=os.getuid(), gid=os.getgid(), mode=0o600)
        assert str(error.value) == "Security Ledger key write failed"
        assert secret not in str(error.value)
        assert error.value.__suppress_context__
    finally:
        os.close(fd)
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize("mismatch", ["mode", "uid", "gid"])
def test_requested_metadata_is_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    keyfile = _keyfile()
    uid, gid, mode = os.getuid(), os.getgid(), 0o600
    if mismatch == "mode":
        mode = 0o400
        monkeypatch.setattr(os, "fchmod", lambda *_: None)
    else:
        monkeypatch.setattr(os, "fchown", lambda *_: None)
        uid += mismatch == "uid"
        gid += mismatch == "gid"
    fd = os.open(tmp_path / "key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with pytest.raises(keyfile.KeyFileError, match="^Security Ledger key write failed$"):
            keyfile.write_hmac_key(fd, uid=uid, gid=gid, mode=mode)
    finally:
        os.close(fd)
