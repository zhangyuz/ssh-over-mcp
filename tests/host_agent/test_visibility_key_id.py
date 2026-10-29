"""One shared, domain-separated key identity for central signer and host verifier.

ADR0028 steps 6-7 compare key IDs. They are only meaningful if both sides
derive them from real key material with the same function, so an attestation
adapter cannot pass merely by echoing the expected value.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from ssh_over_mcp.host_agent.visibility_snapshot_v5 import visibility_key_id

_KEY = bytes(range(32))
# Spec vector: SHA-256(b"ssh-over-mcp/v5/hmac-key-id/v1\x00" || key).
_VECTOR = "c3e403ac1a1ecf1f1cd1f1483e4e7fd56b3418528fe24103cf6c3eb8f0106ac9"


def test_key_id_matches_the_documented_vector():
    assert visibility_key_id(_KEY) == _VECTOR


def test_key_id_is_domain_separated_from_plain_digests():
    # A host-key pin hashes public material with no tag; a key ID must never
    # equal that (or a bare hash of the key), or the two could be confused.
    assert visibility_key_id(_KEY) != hashlib.sha256(_KEY).hexdigest()
    assert visibility_key_id(_KEY) != hashlib.sha256(_KEY[::-1]).hexdigest()


def test_key_id_changes_with_every_key_byte():
    seen = {visibility_key_id(_KEY)}
    for index in range(32):
        mutated = bytearray(_KEY)
        mutated[index] ^= 1
        seen.add(visibility_key_id(bytes(mutated)))
    assert len(seen) == 33


@pytest.mark.parametrize(
    "key", [b"", b"short", bytes(31), bytes(33), bytearray(32), "k" * 32, None, 5]
)
def test_key_id_refuses_anything_but_exactly_32_bytes(key):
    with pytest.raises(ValueError):
        visibility_key_id(key)


def test_authority_reports_the_shared_ids_without_exposing_keys():
    from ssh_over_mcp.inventory.models import Host, Inventory
    from ssh_over_mcp.policy.engine import PolicyEngine
    from ssh_over_mcp.policy.models import Effect, PolicyDocument, PolicyRule, RoleSpec
    from ssh_over_mcp.ssh.immutable_visibility_authority import ImmutableVisibilityAuthority

    hosts = {
        name: Host(
            address="127.0.0.1",
            credential_ref=name,
            host_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C7rvYIXuX0wbEZ9a",
            ssh_user="fs",
            allowed_roles=frozenset({"operator"}),
        )
        for name in ("node01", "node02")
    }
    engine = PolicyEngine(
        inventory=Inventory(hosts=hosts),
        policy=PolicyDocument(
            roles={"operator": RoleSpec()},
            rules=(
                PolicyRule(
                    id="allow",
                    effect=Effect.ALLOW,
                    roles=("operator",),
                    tools=("fs_list",),
                    paths=("/srv/data", "/srv/data/**"),
                ),
            ),
        ),
    )
    keys = {"node01": bytes([1]) * 32, "node02": bytes([2]) * 32}
    authority = ImmutableVisibilityAuthority(
        engine=engine, epoch=3, host_keys=keys, generation_active=lambda: True
    )
    ids = authority.signer_key_ids()
    assert ids == {host: visibility_key_id(key) for host, key in keys.items()}
    assert len(set(ids.values())) == 2
    ids["node01"] = "tampered"  # a returned copy must not alias internal state
    assert authority.signer_key_ids()["node01"] == visibility_key_id(keys["node01"])
    for secret in keys.values():
        assert secret.hex() not in repr(ids)


def test_host_derives_its_verifier_key_id_from_the_real_key_file(tmp_path, monkeypatch):
    import ssh_over_mcp.host_agent.visibility_runtime_v5 as runtime

    monkeypatch.setattr(runtime, "_TRUSTED_ADMIN_UID", os.geteuid())
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    key_file = trusted / "signer.key"
    key_file.write_bytes(_KEY)
    os.chmod(key_file, 0o400)
    assert runtime.local_verifier_key_id(key_file) == _VECTOR

    # A different file yields a different ID: nothing is echoed or cached.
    other = trusted / "other.key"
    other.write_bytes(bytes([9]) * 32)
    os.chmod(other, 0o400)
    assert runtime.local_verifier_key_id(other) == visibility_key_id(bytes([9]) * 32)
    assert runtime.local_verifier_key_id(other) != _VECTOR


def test_host_key_id_refuses_unsafe_or_missing_key_files(tmp_path, monkeypatch):
    import ssh_over_mcp.host_agent.visibility_runtime_v5 as runtime

    monkeypatch.setattr(runtime, "_TRUSTED_ADMIN_UID", os.geteuid())
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    loose = trusted / "loose.key"
    loose.write_bytes(_KEY)
    os.chmod(loose, 0o644)
    with pytest.raises(runtime.VisibilityRuntimeError):
        runtime.local_verifier_key_id(loose)
    with pytest.raises(runtime.VisibilityRuntimeError):
        runtime.local_verifier_key_id(trusted / "absent.key")
