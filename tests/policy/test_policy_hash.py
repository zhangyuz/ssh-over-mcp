import os
import subprocess
import sys
from pathlib import Path

from ssh_over_mcp.policy.engine import PolicyEngine

_SRC = Path(__file__).resolve().parents[2] / "src"

# Remote hosts pin this digest; it must not depend on per-process set order.
_DIGEST_PROGRAM = """
from ssh_over_mcp.inventory.models import Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import PolicyDocument

policy = PolicyDocument.model_validate({
    "version": 1,
    "default": "deny",
    "roles": {"operator": {}},
    "risk": {"approval_required": ["low", "medium", "high", "critical"]},
    "rules": [{"id": "r", "effect": "allow", "roles": ["operator"],
               "hosts": ["h"], "tools": ["fs_list"], "paths": ["/srv/**"]}],
})
inventory = Inventory.model_validate({"hosts": {"h": {
    "address": "h.example", "ssh_user": "agent", "credential_ref": "c",
    "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C7rvYIXuX0wbEZ9a",
    "allowed_roles": ["operator"],
}}})
print(PolicyEngine(inventory=inventory, policy=policy).policy_version)
"""


def test_policy_hash_is_deterministic(inventory, policy):
    first = PolicyEngine(inventory=inventory, policy=policy).policy_version
    second = PolicyEngine(inventory=inventory, policy=policy).policy_version
    assert first == second
    assert first.startswith("sha256:")


def test_policy_hash_is_stable_across_process_hash_seeds():
    digests = set()
    for seed in ("0", "1", "2", "3", "4", "5", "6", "7"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(_SRC)}
        result = subprocess.run(
            [sys.executable, "-c", _DIGEST_PROGRAM],
            env=env,
            capture_output=True,
            check=True,
            timeout=30,
        )
        digests.add(result.stdout.decode().strip())
    assert len(digests) == 1, digests
