"""Nonce-bound v5 state attestation (ADR0028 step 6/7 ruling).

The host and the central authority compute the SAME proof from the same key
for a fresh nonce, so the controller can compare them without ever holding a
key, and an echoed, replayed or stale report cannot match.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest

import ssh_over_mcp.host_agent.visibility_runtime_v5 as runtime
from ssh_over_mcp.host_agent import attest_v5
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import visibility_key_id

_KEY = bytes(range(32))
_NONCE = "0123456789abcdef0123456789abcdef"
_PIN = hashlib.sha256(b"pinned test hostkey").hexdigest()
_DIGEST = "a" * 64
_FIELDS = {
    "version": 1,
    "host": "node01",
    "host_key_sha256": _PIN,
    "profile": "rw-operator",
    "policy_epoch": 12,
    "central_policy_sha256": _DIGEST,
    "verifier_key_id": visibility_key_id(_KEY),
    "nonce": _NONCE,
}


@pytest.fixture(autouse=True)
def admin_owner(monkeypatch):
    monkeypatch.setattr(runtime, "_TRUSTED_ADMIN_UID", os.geteuid())


def _trust(tmp_path: Path, *, key: bytes = _KEY, epoch: int = 12, host: str = "node01") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    private = tmp_path / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700, exist_ok=True)
    key_file = trusted / "signer.key"
    key_file.write_bytes(key)
    os.chmod(key_file, 0o400)
    policy = {
        "version": 5,
        "enabled": True,
        "host": host,
        "host_key_sha256": _PIN,
        "signer_key_path": str(key_file),
        "nonce_db_path": str(private / "nonces.sqlite"),
        "visibility": {
            "version": 5,
            "enabled": True,
            "host": host,
            "profile": "rw-operator",
            "policy_epoch": epoch,
            "central_policy_sha256": _DIGEST,
            "operations": {
                "fs_list": {"allow_roots": ["/srv/data"], "deny_subtrees": []},
                "fs_search": {"allow_roots": ["/srv/data"], "deny_subtrees": []},
            },
        },
    }
    path = trusted / "host-v5.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    os.chmod(path, 0o400)
    return path


# ------------------------------------------------------------------ proof


def test_proof_is_deterministic_canonical_and_key_dependent():
    proof = attest_v5.attestation_proof(_KEY, _FIELDS)
    assert proof == attest_v5.attestation_proof(_KEY, dict(reversed(list(_FIELDS.items()))))
    assert len(proof) == 64 and int(proof, 16) >= 0
    assert proof != attest_v5.attestation_proof(bytes([7]) * 32, _FIELDS)


def test_proof_covers_every_field_including_the_nonce():
    base = attest_v5.attestation_proof(_KEY, _FIELDS)
    for name, other in (
        ("version", 2),
        ("host", "node02"),
        ("host_key_sha256", "b" * 64),
        ("profile", "other"),
        ("policy_epoch", 11),
        ("central_policy_sha256", "c" * 64),
        ("verifier_key_id", "d" * 64),
        ("nonce", "f" * 32),
    ):
        assert attest_v5.attestation_proof(_KEY, {**_FIELDS, name: other}) != base, name


def test_proof_is_domain_separated_from_snapshot_macs():
    import hmac

    plain = hmac.new(_KEY, json.dumps(_FIELDS, sort_keys=True, separators=(",", ":")).encode(),
                     hashlib.sha256).hexdigest()
    assert attest_v5.attestation_proof(_KEY, _FIELDS) != plain


@pytest.mark.parametrize("key", [b"", b"x" * 31, b"x" * 33, bytearray(32), "k" * 32, None])
def test_proof_refuses_anything_but_a_32_byte_key(key):
    with pytest.raises(ValueError):
        attest_v5.attestation_proof(key, _FIELDS)


@pytest.mark.parametrize("nonce", ["", "short", "G" * 32, "A" * 32, "a" * 31, "a" * 33, None, 5])
def test_nonce_must_be_exactly_32_lowercase_hex(nonce):
    with pytest.raises(ValueError):
        attest_v5.require_nonce(nonce)


# ------------------------------------------------------------------ host side


def test_host_report_derives_everything_from_protected_files(tmp_path):
    policy = _trust(tmp_path)
    report = attest_v5.attest_host_state(policy, _NONCE)
    assert {k: v for k, v in report.items() if k not in {"proof", "config_sha256"}} == _FIELDS
    assert report["proof"] == attest_v5.attestation_proof(_KEY, _FIELDS)
    assert len(report["config_sha256"]) == 64
    assert _KEY.hex() not in json.dumps(report)


def test_host_report_changes_with_nonce_key_epoch_and_config(tmp_path):
    policy = _trust(tmp_path / "a")
    base = attest_v5.attest_host_state(policy, _NONCE)
    assert attest_v5.attest_host_state(policy, "f" * 32)["proof"] != base["proof"]
    other_key = attest_v5.attest_host_state(_trust(tmp_path / "b", key=bytes([9]) * 32), _NONCE)
    assert other_key["proof"] != base["proof"] and other_key["verifier_key_id"] != base["verifier_key_id"]
    other_epoch = attest_v5.attest_host_state(_trust(tmp_path / "c", epoch=13), _NONCE)
    assert other_epoch["proof"] != base["proof"]
    assert other_epoch["config_sha256"] != base["config_sha256"]


def test_host_report_refuses_unsafe_or_missing_inputs(tmp_path):
    policy = _trust(tmp_path)
    with pytest.raises(ValueError):
        attest_v5.attest_host_state(policy, "not-a-nonce")
    os.chmod(policy.parent / "signer.key", 0o644)
    with pytest.raises(runtime.VisibilityRuntimeError):
        attest_v5.attest_host_state(policy, _NONCE)
    with pytest.raises(runtime.VisibilityRuntimeError):
        attest_v5.attest_host_state(tmp_path / "absent.json", _NONCE)


# ------------------------------------------------------------------ cli


def _cli(argv, capsys):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = attest_v5.main(argv, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_prints_one_json_line_and_exits_zero(tmp_path, capsys):
    policy = _trust(tmp_path)
    code, out, err = _cli(["--policy", str(policy), "--nonce", _NONCE], capsys)
    assert code == 0 and err == "" and out.endswith("\n") and out.count("\n") == 1
    assert json.loads(out) == attest_v5.attest_host_state(policy, _NONCE)


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--nonce", _NONCE],
        ["--policy", "/x/y.json"],
        ["--policy", "/x/y.json", "--nonce", "bad"],
        ["--policy", "/x/y.json", "--nonce", _NONCE, "--extra", "1"],
        ["--policy", "/x/y.json", "--nonce", _NONCE],
    ],
)
def test_cli_refuses_bad_arguments_and_unavailable_state_without_output(argv, capsys):
    code, out, err = _cli(argv, capsys)
    assert code != 0 and out == ""
    assert _KEY.hex() not in err and "Traceback" not in err


def test_cli_reads_no_stdin_and_never_writes_files(tmp_path, monkeypatch, capsys):
    policy = _trust(tmp_path)
    monkeypatch.setattr("sys.stdin", None)
    before = sorted(p.name for p in tmp_path.rglob("*"))
    code, _, _ = _cli(["--policy", str(policy), "--nonce", _NONCE], capsys)
    assert code == 0
    assert sorted(p.name for p in tmp_path.rglob("*")) == before  # read-only: no nonce DB created


# ------------------------------------------------------------------ central side


def _authority(keys, epoch=12):
    import asyncssh

    from ssh_over_mcp.inventory.models import Host, Inventory
    from ssh_over_mcp.policy.engine import PolicyEngine
    from ssh_over_mcp.policy.models import Effect, PolicyDocument, PolicyRule, RoleSpec
    from ssh_over_mcp.ssh.filesystem_list_v2 import pinned_host_identity
    from ssh_over_mcp.ssh.immutable_visibility_authority import ImmutableVisibilityAuthority

    pub = {}
    for name in keys:
        pub[name] = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    engine = PolicyEngine(
        inventory=Inventory(
            hosts={
                name: Host(
                    address="127.0.0.1",
                    credential_ref=name,
                    host_key=pub[name],
                    ssh_user="fs",
                    allowed_roles=frozenset({"rw-operator"}),
                )
                for name in keys
            }
        ),
        policy=PolicyDocument(
            roles={"rw-operator": RoleSpec()},
            rules=(
                PolicyRule(
                    id="allow",
                    effect=Effect.ALLOW,
                    roles=("rw-operator",),
                    tools=("fs_list",),
                    paths=("/srv/data", "/srv/data/**"),
                ),
            ),
        ),
    )
    active = {"on": True}
    authority = ImmutableVisibilityAuthority(
        engine=engine, epoch=epoch, host_keys=keys, generation_active=lambda: active["on"]
    )
    pins = {name: pinned_host_identity(pub[name]) for name in keys}
    return authority, active, pins


def test_central_report_matches_host_report_exactly_when_the_key_is_the_same():
    keys = {"node01": _KEY, "node02": bytes([2]) * 32}
    authority, _, pins = _authority(keys)
    reports = authority.attest(nonce=_NONCE, profile="rw-operator")
    assert set(reports) == {"node01", "node02"}
    digest = authority.engine.policy_version.removeprefix("sha256:")
    for host, key in keys.items():
        fields = {
            "version": 1,
            "host": host,
            "host_key_sha256": pins[host],
            "profile": "rw-operator",
            "policy_epoch": 12,
            "central_policy_sha256": digest,
            "verifier_key_id": visibility_key_id(key),
            "nonce": _NONCE,
        }
        assert reports[host] == {**fields, "proof": attest_v5.attestation_proof(key, fields)}
    assert reports["node01"]["proof"] != reports["node02"]["proof"]
    assert _KEY.hex() not in json.dumps(reports)


def test_central_report_refuses_bad_nonce_inactive_release_and_odd_profiles():
    authority, active, _ = _authority({"node01": _KEY, "node02": bytes([2]) * 32})
    with pytest.raises(ValueError):
        authority.attest(nonce="bad", profile="rw-operator")
    with pytest.raises(ValueError):
        authority.attest(nonce=_NONCE, profile="")
    active["on"] = False
    from ssh_over_mcp.ssh.immutable_visibility_authority import VisibilityAuthorityUnavailable

    with pytest.raises(VisibilityAuthorityUnavailable):
        authority.attest(nonce=_NONCE, profile="rw-operator")


def test_a_different_key_or_stale_nonce_cannot_reproduce_the_central_proof():
    authority, _, _ = _authority({"node01": _KEY, "node02": bytes([2]) * 32})
    central = authority.attest(nonce=_NONCE, profile="rw-operator")["node01"]
    fields = {k: v for k, v in central.items() if k != "proof"}
    assert attest_v5.attestation_proof(bytes([8]) * 32, fields) != central["proof"]
    replay = authority.attest(nonce="f" * 32, profile="rw-operator")["node01"]
    assert replay["proof"] != central["proof"]
