"""Platform-neutral checks that listing bounds never reveal denied siblings."""

from __future__ import annotations

import pytest

from ssh_over_mcp.host_agent.filesystem import FilesystemAccessError
from ssh_over_mcp.host_agent.visibility_listing_candidate import (
    MAX_LIST_PHYSICAL_ENTRIES,
    select_visible_children,
)

ROOT = "/srv/data"


def _select(names, *, denied=frozenset(), max_entries=64):
    return select_visible_children(
        ROOT,
        names,
        authorize_child=lambda path: path.rsplit("/", 1)[1] not in denied,
        max_entries=max_entries,
    )


@pytest.mark.parametrize("hidden", [0, 1, 7, 63, 500])
def test_outcome_for_every_bound_is_independent_of_denied_sibling_count(hidden):
    denied = frozenset(f"secret{i:03d}" for i in range(hidden))
    names = ["public.txt", *sorted(denied)]
    for bound in (1, 2, 64):
        assert [path for _, _, path in _select(names, denied=denied, max_entries=bound)] == [
            "/srv/data/public.txt"
        ]


def test_visible_entries_above_bound_refuse_instead_of_truncating():
    names = [f"x{i:02d}" for i in range(3)]
    with pytest.raises(FilesystemAccessError):
        _select(names, max_entries=2)
    assert len(_select(names, max_entries=3)) == 3


def test_fixed_physical_ceiling_is_not_caller_tunable():
    names = [f"d{i:05d}" for i in range(MAX_LIST_PHYSICAL_ENTRIES + 1)]
    everything = frozenset(names)
    for bound in (1, 64):
        with pytest.raises(FilesystemAccessError):
            _select(names, denied=everything, max_entries=bound)
    assert _select(names[:-1], denied=everything, max_entries=1) == []


def test_children_are_authorized_in_utf8_byte_order_and_returned_sorted():
    checks: list[str] = []

    def authorize(path: str) -> bool:
        checks.append(path)
        return not path.endswith("/hidden")

    result = select_visible_children(
        ROOT, ["z.txt", "hidden", "a.txt"], authorize_child=authorize, max_entries=2
    )
    assert [path for _, _, path in result] == ["/srv/data/a.txt", "/srv/data/z.txt"]
    assert checks == ["/srv/data/a.txt", "/srv/data/hidden", "/srv/data/z.txt"]


@pytest.mark.parametrize("name", ["a[1].txt", "star*", "q?", "back\\slash", "ctl\x01", "\udcff"])
def test_unrepresentable_name_refuses_whole_listing_without_authorization(name):
    # Denied subtrees are canonical paths, so an unrepresentable name is never
    # a denied entry: refusing reveals nothing about denied children.
    calls: list[str] = []

    def authorize(path: str) -> bool:
        calls.append(path)
        return True

    with pytest.raises(FilesystemAccessError):
        select_visible_children(ROOT, ["ok", name], authorize_child=authorize, max_entries=64)
    assert calls == []


def test_authorization_failure_fails_closed():
    def broken(_: str) -> bool:
        raise RuntimeError("policy store unavailable")

    with pytest.raises(FilesystemAccessError):
        select_visible_children(ROOT, ["a"], authorize_child=broken, max_entries=64)


def test_open_time_hook_is_required_not_silently_allow_all():
    from ssh_over_mcp.host_agent.visibility_listing_candidate import list_directory_candidate

    with pytest.raises(TypeError):
        list_directory_candidate(
            ROOT,
            authorize_traverse=lambda _: True,
            authorize_directory=lambda _: True,
            authorize_child=lambda _: True,
            max_entries=1,
        )
