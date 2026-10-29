"""Linux-only safety checks for an inert future fs_list directory primitive."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.filesystem import FilesystemAccessError
from ssh_over_mcp.host_agent.visibility_listing_candidate import list_directory_candidate

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "O_PATH"),
    reason="require Linux descriptor-safe O_PATH and procfs",
)


def _list(root: Path, *, traverse=None, directory=None, child=None, max_entries=64):
    return list_directory_candidate(
        str(root),
        authorize_traverse=traverse or (lambda _: True),
        authorize_directory=directory or (lambda _: True),
        authorize_child=child or (lambda _: True),
        max_entries=max_entries,
    )


def test_only_authorized_regular_children_are_returned_in_utf8_byte_order(
    tmp_path: Path,
) -> None:
    (tmp_path / "z.txt").write_bytes(b"z")
    (tmp_path / "a.txt").write_bytes(b"a")
    (tmp_path / "hidden").mkdir()
    checks: list[str] = []

    def authorized(path: str) -> bool:
        checks.append(path)
        return path != str(tmp_path / "hidden")

    result = _list(tmp_path, child=authorized)

    assert tuple(item.path for item in result) == (
        str(tmp_path / "a.txt"),
        str(tmp_path / "z.txt"),
    )
    assert tuple(item.kind for item in result) == ("regular", "regular")
    assert checks == [
        str(tmp_path / "a.txt"),
        str(tmp_path / "hidden"),
        str(tmp_path / "z.txt"),
    ]


def test_denied_child_is_not_opened_or_statted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "private").write_bytes(b"SECRET")
    (tmp_path / "public").write_bytes(b"okay")
    real_open = os.open
    opened: list[str] = []

    def tracking_open(path, flags, *args, **kwargs):
        if isinstance(path, str):
            opened.append(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    result = _list(
        tmp_path,
        child=lambda path: not path.endswith("/private"),
    )

    assert [Path(item.path).name for item in result] == ["public"]
    assert "private" not in opened


def test_denied_traversal_prefix_prevents_path_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "blocked" / "leaf"
    target.mkdir(parents=True)
    real_open = os.open
    opened: list[str] = []

    def tracking_open(path, flags, *args, **kwargs):
        if isinstance(path, str):
            opened.append(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    with pytest.raises(FilesystemAccessError):
        _list(target, traverse=lambda p: not p.endswith("/blocked"))

    assert "blocked" not in opened
    assert "leaf" not in opened


def test_denied_directory_does_not_open_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opens: list[object] = []
    real_open = os.open

    def tracking_open(path, flags, *args, **kwargs):
        opens.append(path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, directory=lambda _: False)
    assert not opens


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_unsupported_child_fails_before_any_data_capable_child_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    if kind == "symlink":
        (tmp_path / "unsafe").symlink_to("/etc/passwd")
    else:
        os.mkfifo(tmp_path / "unsafe")
    real_open = os.open
    child_opens: list[int] = []

    def tracking_open(path, flags, *args, **kwargs):
        if path == "unsafe":
            child_opens.append(flags)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path)
    assert child_opens
    assert all(flags & os.O_PATH and flags & os.O_NOFOLLOW for flags in child_opens)


def test_visible_entry_bound_refuses_instead_of_truncating(
    tmp_path: Path,
) -> None:
    for index in range(65):
        (tmp_path / f"x{index:02d}").write_bytes(b"")
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, max_entries=64)


@pytest.mark.parametrize("hidden", [0, 1, 64])
def test_caller_bound_outcome_does_not_reveal_denied_sibling_count(
    tmp_path: Path, hidden: int
) -> None:
    (tmp_path / "public.txt").write_bytes(b"ok")
    for index in range(hidden):
        (tmp_path / f"secret{index:02d}").write_bytes(b"")

    def child(path: str) -> bool:
        return not Path(path).name.startswith("secret")

    for bound in (1, 2, 64):
        result = _list(tmp_path, child=child, max_entries=bound)
        assert tuple(item.path for item in result) == (str(tmp_path / "public.txt"),)


def test_fixed_physical_scan_ceiling_refuses_oversized_directory(tmp_path: Path) -> None:
    from ssh_over_mcp.host_agent.visibility_listing_candidate import (
        MAX_LIST_PHYSICAL_ENTRIES,
    )

    for index in range(MAX_LIST_PHYSICAL_ENTRIES + 1):
        (tmp_path / f"d{index:05d}").write_bytes(b"")
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, child=lambda _: False, max_entries=64)


def test_changed_directory_during_scan_refuses_all_partial_results(
    tmp_path: Path,
) -> None:
    (tmp_path / "one").write_bytes(b"a")
    mutated = False

    def change(path: str) -> bool:
        nonlocal mutated
        if not mutated:
            mutated = True
            (tmp_path / "two").write_bytes(b"b")
        return True

    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, child=change)
    assert mutated


@pytest.mark.parametrize("bound", [0, -1, 65, True, 1.5, "64"])
def test_max_entries_is_strict_int_with_hard_cap(tmp_path: Path, bound) -> None:
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, max_entries=bound)


def test_noncanonical_root_refuses_before_authority_or_io() -> None:
    callbacks: list[str] = []

    def called(path: str) -> bool:
        callbacks.append(path)
        return True

    with pytest.raises(FilesystemAccessError):
        list_directory_candidate(
            "/tmp/../etc",
            authorize_traverse=called,
            authorize_directory=called,
            authorize_child=called,
        )
    assert callbacks == []


def test_all_authority_callbacks_require_explicit_true(tmp_path: Path) -> None:
    (tmp_path / "one").write_bytes(b"a")
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, directory=lambda _: 1)
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path, traverse=lambda _: 1)
    assert _list(tmp_path, child=lambda _: 1) == ()


def test_filenames_with_invalid_utf8_refuse_entire_list(tmp_path: Path) -> None:
    fd = os.open(os.fsencode(str(tmp_path)) + b"/\xff", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with pytest.raises(FilesystemAccessError):
        _list(tmp_path)


def test_open_time_check_runs_once_per_visible_child_only(tmp_path: Path) -> None:
    (tmp_path / "public.txt").write_bytes(b"ok")
    for index in range(50):
        (tmp_path / f"secret{index:02d}").write_bytes(b"")
    opened: list[str] = []

    def before_open(path: str) -> bool:
        opened.append(path)
        return True

    result = list_directory_candidate(
        str(tmp_path),
        authorize_traverse=lambda _: True,
        authorize_directory=lambda _: True,
        authorize_child=lambda path: not Path(path).name.startswith("secret"),
        before_child_open=before_open,
        max_entries=64,
    )
    assert opened == [str(tmp_path / "public.txt")]
    assert tuple(item.path for item in result) == (str(tmp_path / "public.txt"),)


def test_open_time_refusal_returns_no_partial_result(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"a")
    (tmp_path / "b.txt").write_bytes(b"b")
    with pytest.raises(FilesystemAccessError):
        list_directory_candidate(
            str(tmp_path),
            authorize_traverse=lambda _: True,
            authorize_directory=lambda _: True,
            authorize_child=lambda _: True,
            before_child_open=lambda path: not path.endswith("b.txt"),
            max_entries=64,
        )
