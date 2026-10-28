"""Tests for the opt-in immutable per-host central visibility signer."""

import asyncssh
import pytest

from ssh_over_mcp.host_agent.visibility_snapshot_v5 import VisibilitySnapshotV5
from ssh_over_mcp.ssh.immutable_visibility_authority import (
    ImmutableVisibilityAuthority,
    VisibilityAuthorityUnavailable,
)


def fixture():
    public = {
        host: asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
        for host in ("node01", "node02")
    }
    # Use a genuine policy engine to ensure the signer never accepts an
    # untrusted fake implementation.
    from ssh_over_mcp.inventory.models import Host, Inventory
    from ssh_over_mcp.policy.engine import PolicyEngine
    from ssh_over_mcp.policy.models import PolicyDocument, RoleSpec

    inventory = Inventory(
        hosts={
            name: Host(
                address="127.0.0.1", ssh_user="fs", credential_ref="test",
                host_key=key, allowed_roles=frozenset({"operator"}),
            )
            for name, key in public.items()
        }
    )
    engine = PolicyEngine(
        inventory=inventory,
        policy=PolicyDocument(roles={"operator": RoleSpec()}, rules=()),
    )
    active = [True]
    signer = ImmutableVisibilityAuthority(
        engine=engine, epoch=11,
        host_keys={"node01": b"a" * 32, "node02": b"b" * 32},
        generation_active=lambda: active[0],
    )
    return signer, engine, active


def snapshot(engine, host="node01", epoch=11):
    from ssh_over_mcp.host_agent.visibility_policy_v5 import VisibilityRules
    from ssh_over_mcp.ssh.filesystem_list_v2 import pinned_host_identity

    return VisibilitySnapshotV5(
        version=5, request_id="request-12345678", host=host,
        host_key_sha256=pinned_host_identity(engine.inventory.hosts[host].host_key),
        principal="trusted:test", profile="operator", operation="fs_list",
        root="/srv/data", policy_epoch=epoch,
        central_policy_sha256=engine.policy_version[7:],
        snapshot_id="a" * 32, issued_at=1800000000, expires_at=1800000020,
        max_entries=8, rules=VisibilityRules(allow_roots=("/srv/data",), deny_subtrees=()),
    )


def test_two_hosts_independent_signatures_and_epochs():
    signer, engine, active = fixture()
    one = snapshot(engine)
    two = snapshot(engine, "node02")
    assert signer.current_epoch(host="node01", policy_sha256=engine.policy_version[7:]) == 11
    assert signer.sign(one).mac_sha256 != signer.sign(two).mac_sha256
    assert signer.is_active(one)
    active[0] = False
    assert not signer.is_active(one)
    with pytest.raises(VisibilityAuthorityUnavailable):
        signer.sign(one)


@pytest.mark.parametrize("invalid", [0, True, -1, "11"])
def test_bad_epoch_refused(invalid):
    _, engine, _ = fixture()
    with pytest.raises(VisibilityAuthorityUnavailable):
        ImmutableVisibilityAuthority(
            engine=engine, epoch=invalid,
            host_keys={"node01": b"a" * 32, "node02": b"b" * 32},
            generation_active=lambda: True,
        )


def test_incomplete_or_shared_keys_refused():
    _, engine, _ = fixture()
    for keys in (
        {"node01": b"a" * 32},
        {"node01": b"a" * 32, "node02": b"a" * 32},
        {"node01": b"a" * 31, "node02": b"b" * 32},
    ):
        with pytest.raises(VisibilityAuthorityUnavailable):
            ImmutableVisibilityAuthority(
                engine=engine, epoch=11, host_keys=keys,
                generation_active=lambda: True,
            )


def test_stale_epoch_or_unpinned_identity_fails_closed():
    signer, engine, _ = fixture()
    with pytest.raises(VisibilityAuthorityUnavailable):
        signer.sign(snapshot(engine, epoch=10))
    changed = snapshot(engine).model_copy(update={"host_key_sha256": "f" * 64})
    with pytest.raises(VisibilityAuthorityUnavailable):
        signer.sign(changed)
    assert not signer.is_active(changed)


def test_no_default_active_release():
    _, engine, _ = fixture()
    signer = ImmutableVisibilityAuthority(
        engine=engine, epoch=11,
        host_keys={"node01": b"a" * 32, "node02": b"b" * 32},
        generation_active=lambda: None,
    )
    with pytest.raises(VisibilityAuthorityUnavailable):
        signer.current_epoch(host="node01", policy_sha256=engine.policy_version[7:])
