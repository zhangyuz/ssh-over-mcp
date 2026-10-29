"""The live epoch guard must not run once per denied name (timing oracle)."""

from __future__ import annotations

import pytest

import ssh_over_mcp.host_agent.visibility_listing_candidate as module
from ssh_over_mcp.host_agent.filesystem import FilesystemAccessError
from ssh_over_mcp.host_agent.visibility_policy_v5 import VisibilityPolicyV5
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    VerifiedVisibilitySnapshot,
    VisibilitySnapshotV5,
)

ROOT = "/srv/data"


def _verified() -> VerifiedVisibilitySnapshot:
    snapshot = VisibilitySnapshotV5.model_validate(
        {
            "version": 5,
            "request_id": "list-req-0123456789",
            "host": "node01",
            "host_key_sha256": "1" * 64,
            "principal": "alice",
            "profile": "operator",
            "operation": "fs_list",
            "root": ROOT,
            "policy_epoch": 11,
            "central_policy_sha256": "a" * 64,
            "snapshot_id": "b" * 32,
            "issued_at": 1_800_000_000,
            "expires_at": 1_800_000_030,
            "max_entries": 64,
            "rules": {"allow_roots": (ROOT,), "deny_subtrees": (ROOT + "/secret",)},
        }
    )
    policy = VisibilityPolicyV5.model_validate(
        {
            "version": 5,
            "host": "node01",
            "profile": "operator",
            "policy_epoch": 11,
            "central_policy_sha256": "a" * 64,
            "enabled": True,
            "operations": {
                "fs_list": {"allow_roots": (ROOT,), "deny_subtrees": ()},
                "fs_search": {"allow_roots": (ROOT,), "deny_subtrees": ()},
            },
        }
    )
    return VerifiedVisibilitySnapshot(snapshot=snapshot, active_host_policy=policy)


def _fake_primitive(denied: int):
    # Mirrors the primitive's callback order: root checks, one lexical check
    # per physical name, then the open-time check for each visible child.
    def fake(path, *, authorize_traverse, authorize_directory, authorize_child,
             before_child_open, max_entries):
        assert authorize_traverse("/") and authorize_directory(path)
        for _ in range(denied):
            assert authorize_child(ROOT + "/secret") is False
        assert authorize_child(ROOT + "/public.txt") is True
        assert before_child_open(ROOT + "/public.txt") is True
        return ()

    return fake


@pytest.mark.parametrize("denied", [1, 64, 4000])
def test_epoch_guard_count_is_independent_of_denied_sibling_count(monkeypatch, denied):
    counts = {}
    for n in (0, denied):
        calls = 0

        def active() -> bool:
            nonlocal calls
            calls += 1
            return True

        monkeypatch.setattr(module, "list_directory_candidate", _fake_primitive(n))
        module.list_verified_directory_candidate(_verified(), is_epoch_active=active)
        counts[n] = calls
    assert counts[0] == counts[denied]


def test_revoked_epoch_still_refuses_before_visible_child_open(monkeypatch):
    state = {"active": True}

    def fake(path, *, authorize_traverse, authorize_directory, authorize_child,
             before_child_open, max_entries):
        assert authorize_child(ROOT + "/public.txt")
        state["active"] = False
        before_child_open(ROOT + "/public.txt")
        raise AssertionError("revocation must refuse before opening")

    monkeypatch.setattr(module, "list_directory_candidate", fake)
    with pytest.raises(FilesystemAccessError):
        module.list_verified_directory_candidate(
            _verified(), is_epoch_active=lambda: state["active"]
        )
