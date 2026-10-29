"""Attestation adapter for the Mode A rotation, tested only through fakes.

A recording runner stands in for ``limactl shell ... docker exec``; the host
and control reports are produced with the REAL ``attest_v5`` proof functions, so
equality of proofs here means the same thing as in production. Nothing talks to
launchd, Lima or Docker.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ssh_over_mcp.host_agent import attest_v5
from ssh_over_mcp.ops.mode_a_v5_attestation import (
    AttestationConfig,
    LimaDockerAttestor,
)
from ssh_over_mcp.ops.mode_a_v5_lima_primitives import (
    AdapterConfig,
    CommandResult,
    LimaDockerPrimitives,
)
from ssh_over_mcp.ops.mode_a_v5_rotation import (
    HostReceipt,
    RotationFailure,
    RotationSpec,
    generation_id,
    run_rotation,
)

LAUNCHCTL = "/bin/launchctl"
LIMACTL = "/opt/homebrew/bin/limactl"
VM = "som-isolated-accept-1"
KEYS = {"node01": bytes([1]) * 32, "node02": bytes([2]) * 32}
PINS = {"node01": "c" * 64, "node02": "d" * 64}
DIGEST = "a" * 64
EPOCH = 12
PROFILE = "rw-operator"
CONTAINERS = {"node01": "somfsl-node01-1", "node02": "somfsl-node02-1"}
POLICY_PATH = "/etc/ssh-over-mcp/v5/host-visibility.json"
PYTHON = "/opt/ssh-over-mcp-e2e/venv/bin/python"
KEY_IDS = {h: attest_v5.visibility_key_id(k) for h, k in KEYS.items()}


def make_spec(**overrides):
    fields = {
        "epoch": EPOCH,
        "policy_sha256": DIGEST,
        "host_keys": dict(PINS),
        "signer_key_ids": dict(KEY_IDS),
    }
    fields.update(overrides)
    return RotationSpec(generation_sha256=generation_id(**fields), **fields)


def fields_for(host, nonce, *, key=None, changes=None):
    key = KEYS[host] if key is None else key
    base = attest_v5.attestation_fields(
        host=host,
        host_key_sha256=PINS[host],
        profile=PROFILE,
        policy_epoch=EPOCH,
        central_policy_sha256=DIGEST,
        key=key,
        nonce=nonce,
    )
    base.update(changes or {})
    return base


def host_report(host, nonce, *, key=None, changes=None):
    key = KEYS[host] if key is None else key
    fields = fields_for(host, nonce, key=key, changes=changes)
    return {**fields, "config_model_sha256": "e" * 64, "proof": attest_v5.attestation_proof(key, fields)}


def central_reports(nonce, *, keys=None, changes=None):
    keys = keys or KEYS
    out = {}
    for host in KEYS:
        fields = fields_for(host, nonce, key=keys[host], changes=changes)
        out[host] = {**fields, "proof": attest_v5.attestation_proof(keys[host], fields)}
    return out


class FakeRunner:
    def __init__(self):
        self.calls: list[tuple[str, ...]] = []
        self.health = {"somfsl-mcp-1": "healthy"}  # the ledger service has no healthcheck
        self.status = {"somfsl-ledger-1": "exited", "somfsl-mcp-1": "exited"}  # control is stopped
        self.inspect_failures: set[str] = set()
        self.override = None  # callable(argv, nonce) -> CommandResult | None
        self.keys = dict(KEYS)

    async def run(self, argv, *, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        docker = argv[6:]
        if docker[:1] == ("exec",):
            nonce = argv[-1]
            container = argv[argv.index("exec") + 3]  # exec --user U NAME
            host = next(h for h, c in CONTAINERS.items() if c == container)
            if self.override:
                result = self.override(argv, nonce)
                if result is not None:
                    return result
            body = json.dumps(host_report(host, nonce, key=self.keys[host]), sort_keys=True) + "\n"
            return CommandResult(returncode=0, stdout=body.encode(), stderr=b"", timed_out=False)
        if docker[:1] == ("inspect",):
            name = docker[-1]
            if name in self.inspect_failures:
                return CommandResult(returncode=1, stdout=b"", stderr=b"template error", timed_out=False)
            table = self.health if "{{.State.Health.Status}}" in docker else self.status
            if name not in table:
                return CommandResult(returncode=1, stdout=b"", stderr=b"no such value", timed_out=False)
            return CommandResult(returncode=0, stdout=table[name].encode() + b"\n", stderr=b"", timed_out=False)
        raise AssertionError(argv)


def attest_execs(runner):
    """Only the attest_v5 exec commands (state inspects are not attestations)."""

    return [c for c in runner.calls if "ssh_over_mcp.host_agent.attest_v5" in c]


def start_control(runner):
    runner.status["somfsl-ledger-1"] = "running"
    runner.status["somfsl-mcp-1"] = "running"


def adapter_config():
    return AdapterConfig(
        limactl_path=LIMACTL,
        vm_name=VM,
        launchd_label="com.som.modea.isolated",
        launchd_plist="/Users/yuz/Library/LaunchAgents/com.som.modea.isolated.plist",
        uid=501,
        tunnel_port=18911,
        mcp_container="somfsl-mcp-1",
        ledger_container="somfsl-ledger-1",
        node_containers=dict(CONTAINERS),
    )


def attest_config(**overrides):
    base = {"profile": PROFILE, "python_path": PYTHON}
    base.update(overrides)
    return AttestationConfig(**base)


def nonces():
    counter = iter(range(1, 1000))
    return lambda: f"{next(counter):032x}"


def make(runner=None, *, source=None, **kw):
    runner = runner or FakeRunner()
    calls = []

    async def default_source(nonce, profile):
        calls.append((nonce, profile))
        return central_reports(nonce)

    attestor = LimaDockerAttestor(
        adapter_config(),
        attest_config(),
        runner=runner,
        central_reports=source or default_source,
        nonce_factory=kw.get("nonce_factory", nonces()),
    )
    return attestor, runner, calls


# ------------------------------------------------------------------ config


@pytest.mark.parametrize(
    "overrides",
    [
        {"exec_user": "0:0"},
        {"exec_user": "0:3201"},
        {"exec_user": "2201:0"},
        {"exec_user": "root"},
        {"exec_user": "2201"},
        {"exec_user": "2201:3201; id"},
        {"python_path": "python3"},
        {"python_path": "/usr/bin/../bin/python3"},
        {"policy_path": "relative.json"},
        {"policy_path": "/etc/../x.json"},
        {"profile": ""},
        {"profile": "a b"},
    ],
)
def test_config_refuses_root_exec_relative_paths_and_odd_profiles(overrides):
    with pytest.raises(ValidationError):
        attest_config(**overrides)


# ------------------------------------------------------------------ attest_host


@pytest.mark.asyncio
async def test_host_exec_runs_as_the_agent_identity_with_a_fixed_argv():
    attestor, runner, _ = make()
    receipt = await attestor.attest_host("node01", make_spec())
    argv = runner.calls[0]
    assert argv[:6] == (LIMACTL, "shell", VM, "--", "sudo", "docker")
    assert argv[6:] == (
        "exec",
        "--user",
        "2201:3201",
        CONTAINERS["node01"],
        PYTHON,
        "-I",
        "-m",
        "ssh_over_mcp.host_agent.attest_v5",
        "--policy",
        POLICY_PATH,
        "--nonce",
        f"{1:032x}",
    )
    assert isinstance(receipt, HostReceipt)
    assert receipt.host == "node01" and receipt.host_key_sha256 == PINS["node01"]
    assert receipt.epoch == EPOCH and receipt.policy_sha256 == DIGEST
    assert receipt.verifier_key_id == KEY_IDS["node01"]
    assert receipt.generation_sha256 == make_spec().generation_sha256


@pytest.mark.asyncio
async def test_every_round_uses_a_fresh_nonce_and_never_reuses_one():
    attestor, runner, _ = make()
    spec = make_spec()
    for host in ("node01", "node02", "node01"):
        await attestor.attest_host(host, spec)
    used = [c[-1] for c in attest_execs(runner)]
    assert len(used) == 3 and len(set(used)) == 3


@pytest.mark.asyncio
async def test_a_nonce_source_that_repeats_or_returns_garbage_is_refused():
    spec = make_spec()
    attestor, runner, _ = make(nonce_factory=lambda: "a" * 32)  # always the same nonce
    await attestor.attest_host("node01", spec)
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node02", spec)  # a replayed nonce must not run a second round
    assert len(attest_execs(runner)) == 1

    for bad in ("", "short", "A" * 32, "g" * 32, None, 5):
        attestor, runner, _ = make(nonce_factory=lambda bad=bad: bad)
        with pytest.raises(RotationFailure):
            await attestor.attest_host("node01", spec)
        assert attest_execs(runner) == []  # nothing is exec'd with an unusable nonce


@pytest.mark.asyncio
async def test_control_and_host_rounds_never_share_a_nonce():
    attestor, runner, calls = make()
    spec = make_spec()
    start_control(runner)
    await attestor.attest_control(spec)
    await attestor.attest_host("node01", spec)
    await attestor.attest_host("node02", spec)
    used = [calls[0][0], calls[1][0], calls[2][0]]
    assert len(set(used)) == 3


@pytest.mark.asyncio
async def test_unknown_host_is_refused_before_any_command():
    attestor, runner, _ = make()
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node03", make_spec())
    assert runner.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"host": "node02"},
        {"host_key_sha256": "9" * 64},
        {"profile": "someone-else"},
        {"policy_epoch": EPOCH - 1},
        {"central_policy_sha256": "9" * 64},
        {"verifier_key_id": "9" * 64},
        {"nonce": "f" * 32},
        {"version": 2},
    ],
)
async def test_a_host_report_that_differs_from_the_release_is_refused(change):
    attestor, runner, _ = make()

    def lie(argv, nonce):
        host = "node01"
        report = host_report(host, nonce, changes=change)
        return CommandResult(returncode=0, stdout=(json.dumps(report) + "\n").encode(), stderr=b"", timed_out=False)

    runner.override = lie
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node01", make_spec())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stdout,returncode,stderr,timed_out,truncated",
    [
        (b"", 0, b"", False, False),
        (b"not json\n", 0, b"", False, False),
        (b"[]\n", 0, b"", False, False),
        (b'{"a":1}\n', 0, b"", False, False),
        (b"{}\n{}\n", 0, b"", False, False),
        (b'{"proof":"x","proof":"y"}\n', 0, b"", False, False),
        (b"x" * 5000, 0, b"", False, False),
        (b"ok\n", 69, b"attest_v5: trusted state unavailable\n", False, False),
        (b"ok\n", 0, b"warning: something\n", False, False),
        (b"", -9, b"", True, False),
        (b"truncated", 0, b"", False, True),
    ],
)
async def test_unparseable_failed_or_noisy_host_output_is_refused(
    stdout, returncode, stderr, timed_out, truncated
):
    attestor, runner, _ = make()
    runner.override = lambda argv, nonce: CommandResult(
        returncode=returncode, stdout=stdout, stderr=stderr, timed_out=timed_out, truncated=truncated
    )
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node01", make_spec())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: {k: v for k, v in r.items() if k != "proof"},
        lambda r: {**r, "extra": 1},
        lambda r: {**r, "policy_epoch": True},
        lambda r: {**r, "policy_epoch": str(EPOCH)},
        lambda r: {**r, "proof": r["proof"].upper()},
        lambda r: {**r, "proof": "short"},
        lambda r: {**r, "host_key_sha256": "Z" * 64},
        lambda r: {**r, "config_model_sha256": 5},
    ],
)
async def test_report_shape_and_types_are_validated_strictly(mutate):
    attestor, runner, _ = make()

    def shaped(argv, nonce):
        report = mutate(host_report("node01", nonce))
        return CommandResult(returncode=0, stdout=(json.dumps(report) + "\n").encode(), stderr=b"", timed_out=False)

    runner.override = shaped
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node01", make_spec())


# ------------------------------------------------------------------ attest_control and proof equality


@pytest.mark.asyncio
async def test_control_receipt_carries_the_controls_own_values_not_the_specs():
    attestor, runner, calls = make()
    start_control(runner)
    spec = make_spec()
    receipt = await attestor.attest_control(spec)
    assert calls == [(f"{1:032x}", PROFILE)]
    assert receipt.epoch == EPOCH and receipt.policy_sha256 == DIGEST
    assert receipt.host_keys == PINS and receipt.signer_key_ids == KEY_IDS
    assert receipt.generation_sha256 == spec.generation_sha256
    assert receipt.ledger_available is True and receipt.audit_available is True
    # The ledger service has no healthcheck; MCP readiness (/readyz) pings it.
    health = [c[-1] for c in runner.calls if c[6] == "inspect" and "{{.State.Health.Status}}" in c]
    status = [c[-1] for c in runner.calls if c[6] == "inspect" and "{{.State.Status}}" in c]
    assert health == ["somfsl-mcp-1"]
    assert "somfsl-ledger-1" in status


@pytest.mark.asyncio
async def test_control_receipt_reports_the_controls_own_pins_ids_and_generation():
    # Each field the control reports must reach the receipt unchanged, never be
    # replaced by the release's value, so run_rotation can see the difference.
    other_pins = {"node01": "7" * 64, "node02": "8" * 64}
    other_ids = {"node01": "5" * 64, "node02": "6" * 64}

    async def different(nonce, profile):
        out = {}
        for host, key in KEYS.items():
            fields = fields_for(host, nonce, changes={
                "host_key_sha256": other_pins[host], "verifier_key_id": other_ids[host]})
            out[host] = {**fields, "proof": attest_v5.attestation_proof(key, fields)}
        return out

    attestor, runner, _ = make(source=different)
    start_control(runner)
    spec = make_spec()
    receipt = await attestor.attest_control(spec)
    assert receipt.host_keys == other_pins and receipt.signer_key_ids == other_ids
    assert receipt.generation_sha256 != spec.generation_sha256
    assert receipt.generation_sha256 == generation_id(
        epoch=EPOCH, policy_sha256=DIGEST, host_keys=other_pins, signer_key_ids=other_ids
    )


@pytest.mark.asyncio
async def test_an_unready_mcp_means_neither_ledger_nor_audit_is_proven():
    # /readyz pings the ledger, so an unready mcp leaves the ledger unproven too.
    attestor, runner, _ = make()
    start_control(runner)
    runner.health["somfsl-mcp-1"] = "unhealthy"
    receipt = await attestor.attest_control(make_spec())
    assert (receipt.ledger_available, receipt.audit_available) == (False, False)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["exited", "created", "restarting", "paused", "dead"])
async def test_a_ledger_that_is_not_running_is_never_available(state):
    attestor, runner, _ = make()
    start_control(runner)
    runner.status["somfsl-ledger-1"] = state
    receipt = await attestor.attest_control(make_spec())
    assert receipt.ledger_available is False and receipt.audit_available is False


@pytest.mark.asyncio
@pytest.mark.parametrize("health", ["starting", "unhealthy", "none", "", "HEALTHY", "healthy-ish"])
async def test_only_the_exact_word_healthy_counts_as_ready(health):
    attestor, runner, _ = make()
    start_control(runner)
    runner.health["somfsl-mcp-1"] = health
    receipt = await attestor.attest_control(make_spec())
    assert receipt.ledger_available is False and receipt.audit_available is False


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", ["somfsl-mcp-1", "somfsl-ledger-1"])
async def test_a_failing_docker_inspect_is_a_rotation_failure_not_a_guess(failing):
    attestor, runner, _ = make()
    start_control(runner)
    runner.inspect_failures = {failing}
    with pytest.raises(RotationFailure):
        await attestor.attest_control(make_spec())


@pytest.mark.asyncio
async def test_control_receipt_reports_what_it_sees_when_the_control_differs():
    async def stale(nonce, profile):
        return central_reports(nonce, changes={"policy_epoch": EPOCH - 1})

    attestor, _, _ = make(source=stale)
    receipt = await attestor.attest_control(make_spec())
    assert receipt.epoch == EPOCH - 1  # not echoed from the spec; the sequencer will refuse it


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "build",
    [
        lambda n: {"node01": central_reports(n)["node01"]},
        lambda n: {**central_reports(n), "node03": central_reports(n)["node01"]},
        lambda n: central_reports("f" * 32),
        lambda n: {h: {k: v for k, v in r.items() if k != "proof"} for h, r in central_reports(n).items()},
        lambda n: {h: {**r, "extra": 1} for h, r in central_reports(n).items()},
        lambda n: {"node01": central_reports(n)["node02"], "node02": central_reports(n)["node01"]},
    ],
)
async def test_a_malformed_or_foreign_central_report_set_is_refused(build):
    async def source(nonce, profile):
        return build(nonce)

    attestor, _, _ = make(source=source)
    with pytest.raises(RotationFailure):
        await attestor.attest_control(make_spec())


@pytest.mark.asyncio
async def test_a_failing_central_source_is_a_rotation_failure():
    async def source(nonce, profile):
        raise RuntimeError("control exec failed")

    attestor, _, _ = make(source=source)
    with pytest.raises(RotationFailure):
        await attestor.attest_control(make_spec())


@pytest.mark.asyncio
async def test_host_proofs_must_equal_the_control_proofs_whenever_control_is_running():
    attestor, runner, calls = make()
    spec = make_spec()
    await attestor.attest_host("node01", spec)  # control stopped: fields only
    assert calls == []
    start_control(runner)
    await attestor.attest_control(spec)
    calls.clear()
    receipt = await attestor.attest_host("node01", spec)
    assert receipt.verifier_key_id == KEY_IDS["node01"]
    assert len(calls) == 1 and calls[0][1] == PROFILE  # control asked for the SAME fresh nonce
    assert calls[0][0] == [c for c in runner.calls if "attest_v5" in " ".join(c)][-1][-1]


@pytest.mark.asyncio
async def test_a_fresh_attestor_instance_still_requires_equality_when_control_runs():
    # Round 2 must not depend on per-instance memory: a different instance, or
    # attest_host called on its own, sees control running and enforces equality.
    spec = make_spec()
    first, runner, _ = make()
    start_control(runner)
    await first.attest_control(spec)
    runner.keys["node02"] = bytes([9]) * 32

    def forged(argv, nonce):
        fields = fields_for("node02", nonce)
        report = {**fields, "config_model_sha256": "e" * 64,
                  "proof": attest_v5.attestation_proof(bytes([9]) * 32, fields)}
        return CommandResult(returncode=0, stdout=(json.dumps(report) + "\n").encode(), stderr=b"", timed_out=False)

    runner.override = forged
    second, _, _ = make(runner=runner)  # never saw attest_control
    with pytest.raises(RotationFailure):
        await second.attest_host("node02", spec)


@pytest.mark.asyncio
async def test_a_second_rotation_on_the_same_instance_starts_in_round_one_again():
    attestor, runner, calls = make()
    spec = make_spec()
    start_control(runner)
    await attestor.attest_control(spec)
    await attestor.attest_host("node01", spec)  # equality enforced while control runs
    runner.status["somfsl-ledger-1"] = "exited"  # the next rotation stops control again
    runner.status["somfsl-mcp-1"] = "exited"
    calls.clear()
    await attestor.attest_host("node01", spec)  # fields-only again; no stale "attested" state
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["created", "restarting", "paused", "removing", "dead", "running"])
async def test_only_a_fully_exited_control_relaxes_to_fields_only(state):
    # Anything that is not clearly stopped must keep equality required.
    attestor, runner, calls = make()
    runner.status["somfsl-mcp-1"] = state
    runner.status["somfsl-ledger-1"] = "exited"
    await attestor.attest_host("node01", make_spec())
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_unobservable_control_state_keeps_equality_required():
    attestor, runner, calls = make()
    runner.inspect_failures = {"somfsl-mcp-1"}
    await attestor.attest_host("node01", make_spec())
    assert len(calls) == 1  # could not prove it is stopped, so the control proof is demanded


@pytest.mark.asyncio
async def test_a_host_holding_a_different_key_is_caught_once_control_is_attested():
    attestor, runner, _ = make()
    spec = make_spec()
    start_control(runner)
    await attestor.attest_control(spec)
    runner.keys["node02"] = bytes([9]) * 32  # same fields and key ID claim, different key bytes

    def forged_id(argv, nonce):
        # The host reports the EXPECTED key ID but proves with another key.
        fields = fields_for("node02", nonce)
        report = {**fields, "config_model_sha256": "e" * 64,
                  "proof": attest_v5.attestation_proof(bytes([9]) * 32, fields)}
        return CommandResult(returncode=0, stdout=(json.dumps(report) + "\n").encode(), stderr=b"", timed_out=False)

    runner.override = forged_id
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node02", spec)


@pytest.mark.asyncio
async def test_an_echoed_stale_or_replayed_proof_cannot_match_a_fresh_nonce():
    attestor, runner, _ = make()
    spec = make_spec()
    start_control(runner)
    await attestor.attest_control(spec)
    stale = host_report("node01", "0" * 32)  # a proof recorded in an earlier round

    runner.override = lambda argv, nonce: CommandResult(
        returncode=0, stdout=(json.dumps(stale) + "\n").encode(), stderr=b"", timed_out=False
    )
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node01", spec)


@pytest.mark.asyncio
async def test_control_proof_missing_for_the_host_fails_closed():
    attestor, runner, _ = make()
    spec = make_spec()
    start_control(runner)
    await attestor.attest_control(spec)

    async def only_node02(nonce, profile):
        return {"node02": central_reports(nonce)["node02"]}

    attestor._central_reports = only_node02
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node01", spec)


# ------------------------------------------------------------------ guards pinned one by one


def _valid_stdout(nonce, host="node01"):
    return (json.dumps(host_report(host, nonce)) + "\n").encode()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "flags",
    [
        {"returncode": 1},
        {"returncode": 69},
        {"stderr": b"a warning\n"},
        {"timed_out": True},
        {"truncated": True},
    ],
)
async def test_each_command_failure_flag_alone_refuses_an_otherwise_valid_report(flags):
    # JSON parsing must not be what rejects these: stdout is a perfectly valid report.
    attestor, runner, _ = make()

    def only_the_flag(argv, nonce):
        base = {"returncode": 0, "stdout": _valid_stdout(nonce), "stderr": b"", "timed_out": False}
        base.update(flags)
        return CommandResult(**base)

    runner.override = only_the_flag
    with pytest.raises(RotationFailure):
        await attestor.attest_host("node01", make_spec())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "build",
    [
        lambda n: {**central_reports(n), "node02": central_reports(n, changes={"policy_epoch": EPOCH + 1})["node02"]},
        lambda n: {**central_reports(n), "node02": central_reports(n, changes={"central_policy_sha256": "9" * 64})["node02"]},
        lambda n: {**central_reports(n), "node02": central_reports(n, changes={"profile": "other"})["node02"]},
        lambda n: central_reports(n, changes={"profile": "other"}),
    ],
    ids=["epoch-disagrees", "digest-disagrees", "one-profile-wrong", "both-profiles-wrong"],
)
async def test_the_two_control_reports_must_agree_on_epoch_digest_and_profile(build):
    async def source(nonce, profile):
        return build(nonce)

    attestor, runner, _ = make(source=source)
    start_control(runner)
    with pytest.raises(RotationFailure):
        await attestor.attest_control(make_spec())


@pytest.mark.asyncio
async def test_a_control_report_with_an_unsupported_version_is_refused():
    async def source(nonce, profile):
        return central_reports(nonce, changes={"version": 2})

    attestor, runner, _ = make(source=source)
    start_control(runner)
    with pytest.raises(RotationFailure):
        await attestor.attest_control(make_spec())


@pytest.mark.asyncio
async def test_a_config_built_around_the_validators_is_revalidated_in_the_constructor():
    runner = FakeRunner()

    async def source(nonce, profile):
        return central_reports(nonce)

    root_cfg = attest_config().model_copy(update={"exec_user": "0:0"})
    with pytest.raises(ValidationError):
        LimaDockerAttestor(adapter_config(), root_cfg, runner=runner, central_reports=source)
    live_cfg = adapter_config().model_copy(update={"vm_name": "som-mode-a-netpilot-oct27"})
    with pytest.raises(ValidationError):
        LimaDockerAttestor(live_cfg, attest_config(), runner=runner, central_reports=source)
    relative = attest_config().model_copy(update={"python_path": "python3"})
    with pytest.raises(ValidationError):
        LimaDockerAttestor(adapter_config(), relative, runner=runner, central_reports=source)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["attest_host", "attest_control"])
async def test_a_spec_built_around_the_validators_is_refused_before_any_command(method):
    attestor, runner, calls = make()
    bad = make_spec().model_copy(update={"generation_sha256": "b" * 64})
    with pytest.raises(ValidationError):
        if method == "attest_host":
            await attestor.attest_host("node01", bad)
        else:
            await attestor.attest_control(bad)
    assert runner.calls == [] and calls == []


def test_generation_id_is_pinned_to_its_documented_domain_tag():
    import hashlib

    fields = {
        "epoch": EPOCH,
        "policy_sha256": DIGEST,
        "host_keys": dict(PINS),
        "signer_key_ids": dict(KEY_IDS),
    }
    body = json.dumps(
        {
            "epoch": EPOCH,
            "policy_sha256": DIGEST,
            "hosts": {h: {"host_key_sha256": PINS[h], "signer_key_id": KEY_IDS[h]} for h in sorted(PINS)},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    expected = hashlib.sha256(b"ssh-over-mcp/v5/generation/v1\x00" + body).hexdigest()
    assert generation_id(**fields) == expected
    assert generation_id(**fields) != hashlib.sha256(body).hexdigest()  # the tag is not optional


# ------------------------------------------------------------------ whole sequence


class FullOps:
    """Primitives + attestor + a TEST-ONLY install, to prove the sequencing composes."""

    def __init__(self, primitives, attestor):
        self.p, self.a = primitives, attestor
        self.installed = []

    async def freeze_ingress(self):
        return await self.p.freeze_ingress()

    async def drain_inflight(self):
        return await self.p.drain_inflight()

    async def stop_control(self):
        return await self.p.stop_control()

    async def stop_host(self, host):
        return await self.p.stop_host(host)

    async def install(self, host, spec):  # TEST ONLY: real install is not implemented
        self.installed.append(host)
        return True

    async def start_host(self, host):
        return await self.p.start_host(host)

    async def attest_host(self, host, spec):
        return await self.a.attest_host(host, spec)

    async def start_control(self):
        return await self.p.start_control()

    async def attest_control(self, spec):
        return await self.a.attest_control(spec)

    async def open_ingress(self):
        return await self.p.open_ingress()


class FullRunner:
    """Combines the primitives fake and the attestation fake over one call log."""

    def __init__(self):
        self.attest = FakeRunner()
        self.calls = []
        self.disabled = False
        self.loaded = True
        self.state = {}

    async def run(self, argv, *, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        ok = CommandResult(returncode=0, stdout=b"", stderr=b"", timed_out=False)
        if argv[0] == LAUNCHCTL:
            verb = argv[1]
            if verb == "disable":
                self.disabled = True
            elif verb == "enable":
                self.disabled = False
            elif verb == "bootout":
                self.loaded = False
            elif verb == "bootstrap":
                self.loaded = True
            elif verb == "print":
                return CommandResult(returncode=0 if self.loaded else 113, stdout=b"", stderr=b"", timed_out=False)
            elif verb == "print-disabled":
                out = b'\t"com.som.modea.isolated" => disabled\n' if self.disabled else b"\tdisabled services = {\n\t}\n"
                return CommandResult(returncode=0, stdout=out, stderr=b"", timed_out=False)
            return ok
        docker = argv[6:]
        if docker[0] in {"stop", "start"}:
            self.state[docker[-1]] = "exited" if docker[0] == "stop" else "running"
            return ok
        if docker[0] == "inspect":
            if "{{.State.Health.Status}}" in docker:
                return await self.attest.run(argv, timeout=timeout)
            self.sync_status()
            if docker[-1] in self.attest.status:
                return await self.attest.run(argv, timeout=timeout)
            return CommandResult(
                returncode=0, stdout=self.state.get(docker[-1], "running").encode() + b"\n", stderr=b"", timed_out=False
            )
        if docker[0] == "exec" and "cat" in docker:
            header = b"  sl  local_address rem_address   st\n"
            return CommandResult(returncode=0, stdout=header, stderr=b"", timed_out=False)
        if docker[0] == "exec":
            return await self.attest.run(argv, timeout=timeout)
        raise AssertionError(argv)

    def sync_status(self):
        for name in ("somfsl-ledger-1", "somfsl-mcp-1"):
            self.attest.status[name] = self.state.get(name, "running")


class Probe:
    def __init__(self):
        self.listening = False

    async def is_listening(self, host, port):
        return self.listening


async def _full(runner=None):
    runner = runner or FullRunner()
    probe = Probe()

    async def yes():
        return True

    async def nosleep(_):
        return None

    prims = LimaDockerPrimitives(
        adapter_config(),
        runner=runner,
        probe=probe,
        sleep=nosleep,
        operator_confirms_open=yes,
        plist_label_reader=lambda _p: "com.som.modea.isolated",
    )

    async def source(nonce, profile):
        return central_reports(nonce)

    attestor = LimaDockerAttestor(
        adapter_config(), attest_config(), runner=runner, central_reports=source, nonce_factory=nonces()
    )
    original_open = prims.open_ingress

    async def open_after_listening():
        probe.listening = True
        return await original_open()

    prims.open_ingress = open_after_listening
    return FullOps(prims, attestor), runner, probe


@pytest.mark.asyncio
async def test_a_full_rotation_composes_and_requires_equal_proofs_in_the_second_round():
    ops, runner, _ = await _full()
    await run_rotation(make_spec(), ops)
    execs = [c for c in runner.calls if len(c) > 6 and c[6] == "exec" and "attest_v5" in " ".join(c)]
    hosts = [next(h for h, n in CONTAINERS.items() if n in c) for c in execs]
    assert hosts == ["node01", "node02", "node01", "node02"]  # before and after control starts
    assert runner.disabled is False and runner.loaded is True  # reopened only at the end


@pytest.mark.asyncio
async def test_a_wrong_key_on_one_node_stops_the_rotation_before_ingress_reopens():
    runner = FullRunner()
    runner.attest.keys["node02"] = bytes([9]) * 32

    def keep_expected_key_id(argv, nonce):
        container = argv[argv.index("exec") + 3]
        if container != CONTAINERS["node02"]:
            return None
        fields = fields_for("node02", nonce)
        report = {**fields, "config_model_sha256": "e" * 64,
                  "proof": attest_v5.attestation_proof(bytes([9]) * 32, fields)}
        return CommandResult(returncode=0, stdout=(json.dumps(report) + "\n").encode(), stderr=b"", timed_out=False)

    runner.attest.override = keep_expected_key_id
    ops, runner, _ = await _full(runner)
    with pytest.raises(RotationFailure):
        await run_rotation(make_spec(), ops)
    assert runner.disabled is True and runner.loaded is False  # still fenced
    assert not any(c[:2] == (LAUNCHCTL, "enable") for c in runner.calls)


def test_module_has_no_live_entrypoint():
    from pathlib import Path

    import ssh_over_mcp.ops.mode_a_v5_attestation as module

    source = Path(module.__file__).read_text()
    assert "__main__" not in source and "def main" not in source


@pytest.mark.asyncio
async def test_host_and_control_proofs_are_compared_with_the_constant_time_helper(monkeypatch):
    # The behaviour of `==` and compare_digest is identical, so pin the call site:
    # the attestor must go through attest_v5.proofs_equal (hmac.compare_digest).
    import ssh_over_mcp.ops.mode_a_v5_attestation as module

    seen = []
    real = module.proofs_equal
    monkeypatch.setattr(module, "proofs_equal", lambda a, b: seen.append((a, b)) or real(a, b))
    attestor, runner, _ = make()
    start_control(runner)
    spec = make_spec()
    await attestor.attest_control(spec)
    await attestor.attest_host("node01", spec)
    assert len(seen) == 1 and seen[0][0] == seen[0][1]
