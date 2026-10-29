"""RED -> GREEN: plan A may reopen ingress only after two trusted host attestations.

Synthetic orchestration is not proof that an SSH host actually rotated.
"""

from __future__ import annotations

import pytest

from ssh_over_mcp.ops.mode_a_v5_rotation import (
    ControlReceipt,
    HostReceipt,
    RotationFailure,
    RotationSpec,
    run_rotation,
)

D = "a" * 64
G = "b" * 64
K1 = "c" * 64
K2 = "d" * 64
# Signer/verifier key IDs (fingerprints only; never key bytes).
S1 = "e" * 64
S2 = "f" * 64
SIGNERS = {"node01": S1, "node02": S2}


class RecordingOps:
    def __init__(self):
        self.calls = []
        self.bad = None
        self.bad_control = None
        self.bad_reattest = False

    async def freeze_ingress(self):
        self.calls.append("freeze")
        return True  # confirmed durable gate, not just command exit 0

    async def drain_inflight(self):
        self.calls.append("drain")
        return True  # has verified zero active operations

    async def stop_control(self):
        self.calls.append("stop_control")
        return True

    async def stop_host(self, host):
        self.calls.append("stop_" + host)
        return True

    async def install(self, host, spec):
        self.calls.append("install_" + host)
        return True

    async def start_host(self, host):
        self.calls.append("start_" + host)
        return True

    async def attest_host(self, host, spec):
        self.calls.append("attest_" + host)
        key = {"node01": K1, "node02": K2}[host]
        r = HostReceipt(
            host=host,
            host_key_sha256=key,
            epoch=12,
            policy_sha256=D,
            generation_sha256=G,
            verifier_key_id=SIGNERS[host],
        )
        if self.bad == "verifier":
            return r.model_copy(update={"verifier_key_id": "0" * 64})
        if self.bad_reattest and "start_control" in self.calls and host == "node02":
            return r.model_copy(update={"generation_sha256": "0" * 64})
        if self.bad == "spoof":
            return r.model_copy(update={"host": "node01"})
        if self.bad == "rollback":
            return r.model_copy(update={"epoch": 11})
        if self.bad == "digest":
            return r.model_copy(update={"policy_sha256": "0" * 64})
        return r

    async def start_control(self):
        self.calls.append("start_control")
        return True

    async def attest_control(self, spec):
        self.calls.append("attest_control")
        receipt = ControlReceipt(
            epoch=12,
            policy_sha256=D,
            generation_sha256=G,
            host_keys={"node01": K1, "node02": K2},
            signer_key_ids=dict(SIGNERS),
            ledger_available=True,
            audit_available=True,
        )
        if self.bad_control == "epoch":
            return receipt.model_copy(update={"epoch": 11})
        if self.bad_control == "digest":
            return receipt.model_copy(update={"policy_sha256": "0" * 64})
        if self.bad_control == "pins":
            return receipt.model_copy(update={"host_keys": {"node01": K2, "node02": K1}})
        if self.bad_control == "signer":
            return receipt.model_copy(update={"signer_key_ids": {"node01": S2, "node02": S1}})
        if self.bad_control == "ledger":
            return receipt.model_copy(update={"ledger_available": False})
        if self.bad_control == "audit":
            return receipt.model_copy(update={"audit_available": False})
        if self.bad_control == "type":
            return True
        return receipt

    async def open_ingress(self):
        self.calls.append("open")
        return True


def spec():
    return RotationSpec(
        epoch=12,
        policy_sha256=D,
        generation_sha256=G,
        host_keys={"node01": K1, "node02": K2},
        signer_key_ids=dict(SIGNERS),
    )


@pytest.mark.asyncio
async def test_success_requires_quiescence_and_both_attestations_before_resume():
    ops = RecordingOps()
    await run_rotation(spec(), ops)
    assert ops.calls == [
        "freeze",
        "drain",
        "stop_control",
        "stop_node01",
        "stop_node02",
        "install_node01",
        "install_node02",
        "start_node01",
        "start_node02",
        "attest_node01",
        "attest_node02",
        "start_control",
        "attest_control",
        "attest_node01",
        "attest_node02",
        "open",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", ["epoch", "digest", "pins", "signer", "ledger", "audit", "type"]
)
async def test_control_post_start_evidence_must_match_before_unfreeze(bad):
    ops = RecordingOps()
    ops.bad_control = bad
    with pytest.raises(RotationFailure):
        await run_rotation(spec(), ops)
    assert "open" not in ops.calls


@pytest.mark.asyncio
async def test_host_receipts_are_rechecked_after_control_start():
    ops = RecordingOps()
    ops.bad_reattest = True
    with pytest.raises(RotationFailure):
        await run_rotation(spec(), ops)
    assert "open" not in ops.calls
    assert ops.calls.count("attest_node02") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failing",
    [
        "freeze",
        "drain",
        "stop_control",
        "stop_node01",
        "stop_node02",
        "install_node01",
        "install_node02",
        "start_node01",
        "start_node02",
        "attest_node01",
        "attest_node02",
        "start_control",
    ],
)
async def test_failure_never_unfreezes_even_if_one_host_started(failing):
    ops = RecordingOps()

    class FailingOps(RecordingOps):
        def __getattribute__(self, name):
            attr = super().__getattribute__(name)
            if name in {
                "freeze_ingress",
                "drain_inflight",
                "stop_control",
                "stop_host",
                "install",
                "start_host",
                "attest_host",
                "start_control",
            }:

                async def wrapper(*args):
                    key = {
                        "freeze_ingress": "freeze",
                        "drain_inflight": "drain",
                        "stop_host": "stop_" + args[0] if args else "",
                        "install": "install_" + args[0] if args else "",
                        "start_host": "start_" + args[0] if args else "",
                        "attest_host": "attest_" + args[0] if args else "",
                    }.get(name, name)
                    if key == failing:
                        self.calls.append(key)
                        raise OSError("maintenance transport failure")
                    return await attr(*args)

                return wrapper
            return attr

    ops = FailingOps()
    with pytest.raises(RotationFailure):
        await run_rotation(spec(), ops)
    assert "open" not in ops.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["spoof", "rollback", "digest", "verifier"])
async def test_wrong_ack_prevents_control_or_ingress_restart(bad):
    ops = RecordingOps()
    ops.bad = bad
    with pytest.raises(RotationFailure):
        await run_rotation(spec(), ops)
    assert "start_control" not in ops.calls
    assert "open" not in ops.calls


def test_refuse_non_distinct_or_invalid_host_inventory():
    for keys in (
        {"node01": K1},
        {"node01": K1, "node02": K1},
        {"node01": K1, "node03": K2},
    ):
        with pytest.raises(ValueError):
            RotationSpec(
                epoch=12,
                policy_sha256=D,
                generation_sha256=G,
                host_keys=keys,
                signer_key_ids=dict(SIGNERS),
            )


def test_refuse_shared_missing_or_invalid_signer_key_ids():
    for ids in (
        {"node01": S1},
        {"node01": S1, "node02": S1},
        {"node01": S1, "node03": S2},
        {"node01": S1, "node02": "not-hex"},
        {"node01": K1, "node02": S2},  # signer ID must differ from a host-key pin
    ):
        with pytest.raises(ValueError):
            RotationSpec(
                epoch=12,
                policy_sha256=D,
                generation_sha256=G,
                host_keys={"node01": K1, "node02": K2},
                signer_key_ids=ids,
            )


@pytest.mark.asyncio
async def test_false_drain_receipt_fail_closed():
    class NotDrained(RecordingOps):
        async def drain_inflight(self):
            self.calls.append("drain")
            return False

    ops = NotDrained()
    with pytest.raises(RotationFailure):
        await run_rotation(spec(), ops)
    assert ops.calls == ["freeze", "drain"]


@pytest.mark.asyncio
async def test_host_key_pin_mutation_during_install_is_rejected():
    class TamperingOps(RecordingOps):
        async def install(self, host, release):
            self.calls.append("install_" + host)
            release.host_keys["node02"] = "e" * 64
            return True

    ops = TamperingOps()
    with pytest.raises(RotationFailure):
        await run_rotation(spec(), ops)
    assert "open" not in ops.calls


@pytest.mark.asyncio
async def test_spec_object_is_not_mutated_in_place_during_rotation():
    class TamperingOps(RecordingOps):
        async def install(self, host, release):
            self.calls.append("install_" + host)
            release.host_keys["node02"] = "e" * 64
            return True

    value = spec()
    with pytest.raises(RotationFailure):
        await run_rotation(value, TamperingOps())
    assert value.host_keys["node02"] == K2
