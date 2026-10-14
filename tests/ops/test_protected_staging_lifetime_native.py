"""Real Darwin APFS fixture smoke, never the provider's marker or protected root.

UID502-specific acceptance must be run separately with the dedicated account;
ordinary Yuz.local UID501 tests must never be reported as UID502 results.
"""
from __future__ import annotations

import os
import platform
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops/live-e2e"))

from staging_namespace_native import read_acl
from staging_namespace_types import NamespaceError
from staging_owned_lifetime import (
    _claim_disposable_fixture,
    _create_for_fixture,
    _dispose_never_started_fixture,
    _fixture_never_started_receipt,
    create_owned_workspace,
)

_MAC_INTEL = platform.system() == "Darwin" and platform.machine() == "x86_64"


@pytest.mark.skipif(not _MAC_INTEL, reason="real Darwin x86_64 APFS only")
def test_real_apfs_disposable_fd_acl_original_owned_root(tmp_path: Path) -> None:
    lib = tmp_path / "Library"
    lib.mkdir(mode=0o700)
    fd = os.open(lib, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        permit = _claim_disposable_fixture(fd)
        owned = _create_for_fixture(permit)
        try:
            assert read_acl(owned._staging_fd).tags == ()
            assert read_acl(owned._root_fd).tags == ()
            st = os.fstat(owned._root_fd)
            assert st.st_uid == os.getuid()
            assert stat.S_IMODE(st.st_mode) == 0o700
            receipt = _fixture_never_started_receipt(owned)
            _dispose_never_started_fixture(owned, receipt)
            assert os.listdir(fd) != []  # fixture marker/descendants remain
        finally:
            owned.close()
        with pytest.raises(NamespaceError) as exc:
            create_owned_workspace()
        assert exc.value.reason == "unbound"
        assert (lib / ".adr19-disposable-claim").is_file()
    finally:
        os.close(fd)


@pytest.mark.skipif(
    not _MAC_INTEL or os.getuid() != 502 or os.geteuid() != 502,
    reason="requires dedicated non-admin UID502 execution; UID501 is NOT proof",
)
def test_actual_uid502_disposable_acl_and_unbound_provider(tmp_path: Path) -> None:
    """The same fixture smoke, only when explicitly executed as real UID502."""
    test_real_apfs_disposable_fd_acl_original_owned_root(tmp_path)
