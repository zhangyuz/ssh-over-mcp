"""Linux integration of isolated candidate policy→signature→FD→central recheck.

This is **not** MCP, Ledger or OpenSSH end-to-end acceptance. The signer key,
host-key digest and nonce store here are synthetic and supplied by the test.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.visibility_listing_candidate import (
    list_verified_directory_candidate,
)
from ssh_over_mcp.host_agent.visibility_policy_v5 import VisibilityPolicyV5
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import (
    SnapshotBinding,
    SnapshotVerificationError,
    VisibilitySnapshotV5,
    sign_snapshot,
    verify_snapshot,
)
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import Effect, PolicyDocument, PolicyRule, RoleSpec
from ssh_over_mcp.policy.visibility_compiler_v5 import (
    VisibilityCompilationDenied,
    compile_visibility_rules,
    reauthorize_list_paths,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "O_PATH"),
    reason="requires real Linux descriptor-pinned filesystem traversal",
)
_KEY = bytes(range(32))


def _engine(roots: tuple[str, str]) -> PolicyEngine:
    return PolicyEngine(
        inventory=Inventory(
            hosts={
                host: Host(
                    address="127.0.0.1",
                    credential_ref=host,
                    host_key=f"ssh-ed25519 TEST-{host}",
                    ssh_user="fs",
                    allowed_roles=frozenset({"operator"}),
                )
                for host in ("node01", "node02")
            }
        ),
        policy=PolicyDocument(
            roles={"operator": RoleSpec()},
            rules=tuple(
                PolicyRule(
                    id=f"allow-{index}",
                    effect=Effect.ALLOW,
                    tools=("fs_list",),
                    hosts=(host,),
                    roles=("operator",),
                    paths=(root, root + "/**"),
                )
                for index, (host, root) in enumerate(zip(("node01", "node02"), roots, strict=True))
            )
            + tuple(
                PolicyRule(
                    id=f"deny-{index}",
                    effect=Effect.DENY,
                    tools=("fs_list",),
                    hosts=(host,),
                    roles=("operator",),
                    paths=(root + "/secret/**",),
                )
                for index, (host, root) in enumerate(zip(("node01", "node02"), roots, strict=True))
            ),
        ),
    )


def _verified(engine: PolicyEngine, host: str, root: str):
    compiled = compile_visibility_rules(
        engine, host=host, profile="operator", operation="fs_list", root=root
    )
    pinned_key_hash = hashlib.sha256(
        engine.inventory.hosts[host].host_key.encode("utf-8")
    ).hexdigest()
    raw = {
        "version": 5,
        "request_id": "list-req-0123456789",
        "host": host,
        "host_key_sha256": pinned_key_hash,
        "principal": "operator@example.test",
        "profile": "operator",
        "operation": "fs_list",
        "root": root,
        "policy_epoch": 11,
        "central_policy_sha256": compiled.policy_sha256,
        "snapshot_id": hashlib.sha256(host.encode()).hexdigest()[:32],
        "issued_at": 1_800_000_000,
        "expires_at": 1_800_000_030,
        "max_entries": 64,
        "rules": compiled.rules,
    }
    signed = sign_snapshot(VisibilitySnapshotV5.model_validate(raw), key=_KEY)
    policy = VisibilityPolicyV5.model_validate(
        {
            "version": 5,
            "host": host,
            "profile": "operator",
            "policy_epoch": 11,
            "central_policy_sha256": compiled.policy_sha256,
            "enabled": True,
            "operations": {
                "fs_list": {
                    "allow_roots": (root,),
                    "deny_subtrees": (root + "/host-secret",),
                },
                "fs_search": {
                    "allow_roots": (root,),
                    "deny_subtrees": (),
                },
            },
        }
    )
    expected = SnapshotBinding.model_validate(
        {k: v for k, v in raw.items() if k in SnapshotBinding.model_fields}
    )
    verified = verify_snapshot(
        signed,
        trusted_key=_KEY,
        expected=expected,
        active_host_policy=policy,
        now=1_800_000_015,
        consume_snapshot_id=lambda _: True,  # Test-only; NOT durable.
    )
    return signed, expected, policy, verified


def test_two_independent_roots_signed_visited_and_rechecked(tmp_path: Path) -> None:
    roots = (str(tmp_path / "node01"), str(tmp_path / "node02"))
    engine = _engine(roots)
    for host, root in zip(("node01", "node02"), roots, strict=True):
        directory = Path(root)
        directory.mkdir()
        (directory / "visible").write_bytes(host.encode("ascii"))
        (directory / "secret").mkdir()
        (directory / "secret" / "denied.txt").write_bytes(b"SECRET")
        (directory / "host-secret").write_bytes(b"HOST SECRET")

        _, _, _, verified = _verified(engine, host, root)
        result = list_verified_directory_candidate(verified, is_epoch_active=lambda: True)
        paths = tuple(stat.path for stat in result)
        assert paths == (root + "/visible",)
        assert (
            reauthorize_list_paths(
                engine,
                host=host,
                profile="operator",
                root=root,
                response_policy_sha256=verified.snapshot.central_policy_sha256,
                result_paths=paths,
                max_entries=64,
                is_epoch_active=lambda: True,
            )
            == paths
        )


def test_host_identity_cross_signer_replay_is_rejected(tmp_path: Path) -> None:
    roots = (str(tmp_path / "node01"), str(tmp_path / "node02"))
    engine = _engine(roots)
    signed, _, _, _ = _verified(engine, "node01", roots[0])
    _, expected_node02, node02_policy, _ = _verified(engine, "node02", roots[1])
    with pytest.raises(SnapshotVerificationError):
        verify_snapshot(
            signed,
            trusted_key=_KEY,
            expected=expected_node02,
            active_host_policy=node02_policy,
            now=1_800_000_015,
            consume_snapshot_id=lambda _: True,
        )


def test_central_recheck_rejects_remote_injection_of_denied_child(tmp_path: Path) -> None:
    roots = (str(tmp_path / "node01"), str(tmp_path / "node02"))
    engine = _engine(roots)
    with pytest.raises(VisibilityCompilationDenied):
        reauthorize_list_paths(
            engine,
            host="node01",
            profile="operator",
            root=roots[0],
            response_policy_sha256=engine.policy_version.removeprefix("sha256:"),
            result_paths=(roots[0] + "/secret",),
            max_entries=64,
            is_epoch_active=lambda: True,
        )
