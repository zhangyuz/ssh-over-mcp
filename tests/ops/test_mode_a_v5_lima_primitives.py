"""Fixed-argv Mode A maintenance primitives, tested only through fakes.

Nothing here talks to launchd, Lima or Docker: a recording runner and a fake
port probe stand in. These tests prove ordering, preconditions, argv shape and
fail-closed verification, not that a real VM was rotated.
"""

from __future__ import annotations

import asyncio
import socket
import sys

import pytest
from pydantic import ValidationError

from ssh_over_mcp.ops.mode_a_v5_lima_primitives import (
    AdapterConfig,
    CommandResult,
    LimaDockerPrimitives,
    SubprocessRunner,
    TcpPortProbe,
    read_plist_label,
)
from ssh_over_mcp.ops.mode_a_v5_rotation import RotationFailure

LAUNCHCTL = "/bin/launchctl"
LIMACTL = "/opt/homebrew/bin/limactl"
LABEL = "com.som.modea.isolated"
UID = 501
DISABLED_OUT = f'\tdisabled services = {{\n\t\t"{LABEL}" => disabled\n\t}}\n'.encode()
ENABLED_OUT = b'\tdisabled services = {\n\t\t"com.other.job" => enabled\n\t}\n'
HEADER = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"


def tcp_table(*rows: tuple[int, str]) -> bytes:
    """Rows are (local_port, state_hex); other columns are filler."""

    lines = [HEADER]
    for index, (port, state) in enumerate(rows):
        lines.append(
            f"   {index}: 0100007F:{port:04X} 0200000A:C350 {state} 00000000:00000000 "
            "00:00000000 00000000     0        0 12345 1 0000000000000000 20 4 30 10 -1\n".encode()
        )
    return b"".join(lines)


def config(**overrides) -> AdapterConfig:
    base = {
        "limactl_path": LIMACTL,
        "vm_name": "som-isolated-accept-1",
        "launchd_label": LABEL,
        "launchd_plist": f"/Users/yuz/Library/LaunchAgents/{LABEL}.plist",
        "uid": UID,
        "tunnel_port": 18911,
        "mcp_container": "somfsl-mcp-1",
        "ledger_container": "somfsl-ledger-1",
        "node_containers": {
            "node01": "somfsl-node01-1",
            "node02": "somfsl-node02-1",
        },
    }
    base.update(overrides)
    return AdapterConfig(**base)


class FakeRunner:
    def __init__(self):
        self.calls: list[tuple[str, ...]] = []
        self.rules: list = []  # (predicate, CommandResult | callable)
        self.state: dict[str, str] = {}  # container -> docker State.Status
        self.launchd_loaded = True
        self.disabled = False
        self.tcp: dict[tuple[str, str], list[bytes]] = {}

    def on(self, predicate, result):
        self.rules.append((predicate, result))

    async def run(self, argv, *, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        for predicate, result in self.rules:
            if predicate(argv):
                return result(argv) if callable(result) else result
        return self.default(argv)

    def default(self, argv):
        ok = CommandResult(returncode=0, stdout=b"", stderr=b"", timed_out=False)
        if argv[0] == LAUNCHCTL:
            verb = argv[1]
            if verb == "disable":
                self.disabled = True
            elif verb == "enable":
                self.disabled = False
            elif verb == "bootout":
                self.launchd_loaded = False
            elif verb == "bootstrap":
                self.launchd_loaded = True
            elif verb == "print":
                rc = 0 if self.launchd_loaded else 113
                return CommandResult(returncode=rc, stdout=b"", stderr=b"", timed_out=False)
            elif verb == "print-disabled":
                out = DISABLED_OUT if self.disabled else ENABLED_OUT
                return CommandResult(returncode=0, stdout=out, stderr=b"", timed_out=False)
            return ok
        assert argv[:3] == (LIMACTL, "shell", "som-isolated-accept-1"), argv
        assert argv[3:6] == ("--", "sudo", "docker"), argv
        docker = argv[6:]
        if docker[0] == "stop":
            self.state[docker[-1]] = "exited"
            return ok
        if docker[0] == "start":
            self.state[docker[-1]] = "running"
            return ok
        if docker[0] == "inspect":
            status = self.state.get(docker[-1], "running")
            return CommandResult(returncode=0, stdout=status.encode() + b"\n", stderr=b"", timed_out=False)
        if docker[0] == "exec":
            key = (docker[1], docker[3])
            queue = self.tcp.get(key)
            body = queue.pop(0) if queue and len(queue) > 1 else (queue[0] if queue else tcp_table())
            return CommandResult(returncode=0, stdout=body, stderr=b"", timed_out=False)
        raise AssertionError(argv)


class FakeProbe:
    def __init__(self, listening: bool | Exception = False):
        self.listening = listening
        self.calls = []

    async def is_listening(self, host, port):
        self.calls.append((host, port))
        if isinstance(self.listening, Exception):
            raise self.listening
        return self.listening


async def nosleep(_):
    return None


def make(runner=None, probe=None, confirm=None, plist_label=None, **cfg):
    runner = runner or FakeRunner()
    probe = probe or FakeProbe(False)

    async def yes():
        return True

    configured = config(**cfg)
    return (
        LimaDockerPrimitives(
            configured,
            runner=runner,
            probe=probe,
            sleep=nosleep,
            operator_confirms_open=confirm or yes,
            plist_label_reader=lambda _path: plist_label or configured.launchd_label,
        ),
        runner,
        probe,
    )


# ---------------------------------------------------------------- config


@pytest.mark.parametrize(
    "field,value",
    [
        ("vm_name", "vm; rm -rf /"),
        ("vm_name", "Vm Name"),
        ("launchd_label", "com.x y"),
        ("launchd_plist", "relative/path.plist"),
        ("launchd_plist", "/Users/yuz/../etc/x.plist"),
        ("launchd_plist", "/Users/yuz/Library/LaunchAgents/x.txt"),
        ("tunnel_port", 0),
        ("tunnel_port", 70000),
        ("mcp_container", "a b"),
        ("ledger_container", "$(id)"),
        ("uid", -1),
        ("uid", True),
        ("drain_attempts", 0),
        ("stop_timeout_seconds", 0),
    ],
)
def test_config_refuses_unsafe_or_malformed_values(field, value):
    with pytest.raises(ValidationError):
        config(**{field: value})


@pytest.mark.parametrize(
    "overrides",
    [
        {"vm_name": "som-mode-a-netpilot-oct27"},
        {"launchd_label": "com.som.modea.loopback"},
        {"launchd_plist": "/Users/yuz/Library/LaunchAgents/com.som.modea.loopback.plist"},
        {"tunnel_port": 18801},
        {"mcp_container": "som342-mode-a-mcp-1"},
        {"ledger_container": "som342-mode-a-ledger-1"},
        {"node_containers": {"node01": "som342-mode-a-node01-1", "node02": "somfsl-node02-1"}},
    ],
)
def test_config_can_never_target_the_live_pilot(overrides):
    # Rotating the live pilot is not authorized by any ADR, so there is no flag.
    with pytest.raises(ValidationError):
        config(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"limactl_path": "limactl"},
        {"limactl_path": "/opt/homebrew/bin/../bin/limactl"},
        {"limactl_path": "/opt/homebrew/bin/limactl; id"},
        {"launchctl_path": "launchctl"},
        {"stop_timeout_seconds": 60, "command_timeout_seconds": 60.0},
        {"stop_timeout_seconds": 300, "command_timeout_seconds": 305.0},
    ],
)
def test_config_requires_absolute_tools_and_a_command_deadline_beyond_stop(overrides):
    with pytest.raises(ValidationError):
        config(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        # APFS is case-insensitive: these resolve to the live files.
        {"launchd_plist": "/Users/yuz/Library/LaunchAgents/COM.SOM.MODEA.LOOPBACK.plist"},
        {"launchd_label": "COM.SOM.MODEA.LOOPBACK"},
        {"vm_name": "SOM-MODE-A-NETPILOT-OCT27"},
        {"mcp_container": "SOM342-MODE-A-MCP-1"},
        # The plist file name must be exactly "<label>.plist".
        {"launchd_plist": "/Users/yuz/Library/LaunchAgents/other.plist"},
        {"launchd_plist": "/Users/yuz/Library/LaunchAgents/com.som.modea.isolated.PLIST"},
    ],
)
def test_guard_is_case_insensitive_and_binds_the_plist_to_the_label(overrides):
    with pytest.raises(ValidationError):
        config(**overrides)


@pytest.mark.parametrize(
    "build",
    [
        lambda c: c.model_copy(update={"vm_name": "som-mode-a-netpilot-oct27"}),
        lambda c: c.model_copy(update={"tunnel_port": 18801}),
        lambda c: c.model_copy(update={"limactl_path": "limactl"}),
        lambda c: type(c).model_construct(**{**c.model_dump(), "vm_name": "som-mode-a-netpilot-oct27"}),
    ],
)
def test_primitives_revalidate_a_config_built_around_the_validators(build):
    async def yes():
        return True

    with pytest.raises(ValidationError):
        LimaDockerPrimitives(
            build(config()), runner=FakeRunner(), probe=FakeProbe(False), operator_confirms_open=yes
        )


@pytest.mark.asyncio
async def test_open_refuses_a_plist_whose_embedded_label_is_not_the_configured_one():
    prim, runner, _ = make(plist_label="com.som.modea.loopback")
    await prim.freeze_ingress()
    runner.calls.clear()
    with pytest.raises(RotationFailure):
        await prim.open_ingress()
    # Nothing may be enabled or bootstrapped from a mismatching plist.
    assert not any(c[:2] in {(LAUNCHCTL, "enable"), (LAUNCHCTL, "bootstrap")} for c in runner.calls)


def test_plist_label_reader_is_bounded_and_refuses_unsafe_files(tmp_path):
    import plistlib

    good = tmp_path / "a.plist"
    good.write_bytes(plistlib.dumps({"Label": "com.x.y", "RunAtLoad": True}))
    assert read_plist_label(str(good)) == "com.x.y"

    for name, data in (
        ("nolabel.plist", plistlib.dumps({"RunAtLoad": True})),
        ("intlabel.plist", plistlib.dumps({"Label": 5})),
        ("garbage.plist", b"not a plist"),
        ("huge.plist", plistlib.dumps({"Label": "x", "pad": "y" * 200000})),
    ):
        path = tmp_path / name
        path.write_bytes(data)
        with pytest.raises(RotationFailure):
            read_plist_label(str(path))
    link = tmp_path / "link.plist"
    link.symlink_to(good)
    with pytest.raises(RotationFailure):
        read_plist_label(str(link))
    with pytest.raises(RotationFailure):
        read_plist_label(str(tmp_path / "absent.plist"))


def test_config_refuses_duplicate_or_wrong_node_set():
    with pytest.raises(ValidationError):
        config(node_containers={"node01": "same-1", "node02": "same-1"})
    with pytest.raises(ValidationError):
        config(node_containers={"node01": "a-1"})
    with pytest.raises(ValidationError):
        config(mcp_container="somfsl-node01-1")


def test_primitives_are_not_a_full_rotation_adapter():
    # install/attest are an undecided trust-boundary design; without them this
    # object cannot be handed to run_rotation and strand the system half-rotated.
    for name in ("install", "attest_host", "attest_control"):
        assert not hasattr(LimaDockerPrimitives, name)


# ---------------------------------------------------------------- freeze


@pytest.mark.asyncio
async def test_freeze_disables_boots_out_and_verifies_everything():
    prim, runner, probe = make()
    assert await prim.freeze_ingress() is True
    verbs = [c[1] for c in runner.calls if c[0] == LAUNCHCTL]
    assert verbs[:2] == ["disable", "bootout"]
    assert {"print", "print-disabled"} <= set(verbs)
    assert probe.calls == [("127.0.0.1", 18911), ("::1", 18911)]


@pytest.mark.asyncio
async def test_every_command_is_a_fixed_argv_without_a_shell():
    prim, runner, _ = make()
    await prim.freeze_ingress()
    await prim.drain_inflight()
    await prim.stop_control()
    await prim.stop_host("node01")
    for argv in runner.calls:
        assert argv[0] in {LAUNCHCTL, LIMACTL}
        assert all(type(part) is str and part == part.strip() and "\n" not in part for part in argv)
        assert not any(part in {"sh", "bash", "-c"} for part in argv)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "break_it",
    [
        lambda r, p: r.on(lambda a: a[:2] == (LAUNCHCTL, "disable"), CommandResult(returncode=1, stdout=b"", stderr=b"", timed_out=False)),
        lambda r, p: r.on(lambda a: a[:2] == (LAUNCHCTL, "print"), CommandResult(returncode=0, stdout=b"", stderr=b"", timed_out=False)),
        lambda r, p: r.on(lambda a: a[:2] == (LAUNCHCTL, "print"), CommandResult(returncode=1, stdout=b"", stderr=b"", timed_out=False)),
        lambda r, p: r.on(lambda a: a[:2] == (LAUNCHCTL, "print-disabled"), CommandResult(returncode=0, stdout=ENABLED_OUT, stderr=b"", timed_out=False)),
        lambda r, p: r.on(lambda a: a[:2] == (LAUNCHCTL, "print-disabled"), CommandResult(returncode=1, stdout=DISABLED_OUT, stderr=b"", timed_out=False)),
        lambda r, p: r.on(lambda a: a[:2] == (LAUNCHCTL, "bootout"), CommandResult(returncode=-9, stdout=b"", stderr=b"", timed_out=True)),
        lambda r, p: setattr(p, "listening", True),
        lambda r, p: setattr(p, "listening", OSError("network unreachable")),
    ],
)
async def test_freeze_fails_closed_unless_every_check_is_proven(break_it):
    prim, runner, probe = make()
    break_it(runner, probe)
    with pytest.raises(RotationFailure):
        await prim.freeze_ingress()
    # A failed freeze must not unlock later stages.
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()


# ---------------------------------------------------------------- drain


async def fenced(**kw):
    prim, runner, probe = make(**kw)
    await prim.freeze_ingress()
    runner.calls.clear()
    return prim, runner, probe


@pytest.mark.asyncio
async def test_drain_requires_a_verified_fence_and_runs_no_command_without_it():
    prim, runner, _ = make()
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()
    assert runner.calls == []


@pytest.mark.asyncio
async def test_drain_counts_only_established_connections_on_the_service_port():
    prim, runner, _ = await fenced()
    mcp = "somfsl-mcp-1"
    node = "somfsl-node01-1"
    # Listening sockets (0A) and other ports' connections must be ignored.
    runner.tcp[(mcp, "/proc/net/tcp")] = [tcp_table((8000, "0A"), (443, "01"), (8000, "06"))]
    runner.tcp[(node, "/proc/net/tcp")] = [tcp_table((2222, "0A"))]
    assert await prim.drain_inflight() is True
    inspected = {c[7] for c in runner.calls if c[6:8] == ("exec", c[7])}
    assert len(inspected) == 3  # control and both Host Agents


@pytest.mark.asyncio
async def test_drain_waits_then_succeeds_when_connections_close():
    prim, runner, _ = await fenced()
    node = "somfsl-node02-1"
    runner.tcp[(node, "/proc/net/tcp")] = [tcp_table((2222, "01")), tcp_table((2222, "01")), tcp_table()]
    assert await prim.drain_inflight() is True


@pytest.mark.asyncio
async def test_drain_fails_when_a_connection_never_closes():
    prim, runner, _ = await fenced(drain_attempts=3)
    runner.tcp[("somfsl-mcp-1", "/proc/net/tcp6")] = [tcp_table((8000, "01"))]
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()
    with pytest.raises(RotationFailure):  # drain unproven -> stop is refused
        await prim.stop_control()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result",
    [
        CommandResult(returncode=1, stdout=b"", stderr=b"cat: no such file", timed_out=False),
        CommandResult(returncode=0, stdout=b"not a tcp table\n", stderr=b"", timed_out=False),
        CommandResult(returncode=0, stdout=HEADER + b"garbage line\n", stderr=b"", timed_out=False),
        CommandResult(returncode=0, stdout=HEADER + b"0: 0100007F:ZZZZ x 01 y\n", stderr=b"", timed_out=False),
        CommandResult(returncode=-9, stdout=tcp_table(), stderr=b"", timed_out=True),
        CommandResult(returncode=0, stdout=b"", stderr=b"", timed_out=False),
    ],
)
async def test_drain_cannot_prove_zero_from_unreadable_or_malformed_tables(result):
    prim, runner, _ = await fenced(drain_attempts=2)
    runner.on(lambda a: "exec" in a and a[-1] == "/proc/net/tcp6", result)
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()


@pytest.mark.asyncio
async def test_a_truncated_connection_table_can_never_prove_a_drain():
    prim, runner, _ = await fenced(drain_attempts=2)
    runner.on(
        lambda a: "exec" in a and a[-1] == "/proc/net/tcp",
        CommandResult(returncode=0, stdout=tcp_table(), stderr=b"", timed_out=False, truncated=True),
    )
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()
    with pytest.raises(RotationFailure):
        await prim.stop_control()


@pytest.mark.asyncio
async def test_a_truncated_launchctl_listing_can_never_prove_the_fence_or_reopen():
    prim, runner, _ = make()
    runner.on(
        lambda a: a[:2] == (LAUNCHCTL, "print-disabled"),
        CommandResult(returncode=0, stdout=DISABLED_OUT, stderr=b"", timed_out=False, truncated=True),
    )
    with pytest.raises(RotationFailure):
        await prim.freeze_ingress()


# ---------------------------------------------------------------- stop / start


async def drained():
    prim, runner, probe = await fenced()
    assert await prim.drain_inflight()
    runner.calls.clear()
    return prim, runner, probe


@pytest.mark.asyncio
async def test_stop_order_verification_and_preconditions():
    prim, runner, _ = await drained()
    with pytest.raises(RotationFailure):  # hosts may not stop before control
        await prim.stop_host("node01")
    assert await prim.stop_control()
    stops = [c[-1] for c in runner.calls if c[6] == "stop"]
    assert stops == ["somfsl-mcp-1", "somfsl-ledger-1"]
    assert await prim.stop_host("node01") and await prim.stop_host("node02")
    with pytest.raises(RotationFailure):
        await prim.stop_host("node03")


@pytest.mark.asyncio
async def test_stop_is_not_trusted_without_observing_an_exited_state():
    prim, runner, _ = await drained()
    runner.on(
        lambda a: a[6] == "inspect" and a[-1] == "somfsl-ledger-1",
        CommandResult(returncode=0, stdout=b"running\n", stderr=b"", timed_out=False),
    )
    with pytest.raises(RotationFailure):
        await prim.stop_control()


@pytest.mark.asyncio
async def test_start_requires_fence_and_observes_running_state():
    prim, runner, _ = make()
    with pytest.raises(RotationFailure):
        await prim.start_host("node01")
    prim, runner, _ = await drained()
    assert await prim.stop_control()
    assert await prim.stop_host("node01")
    assert await prim.start_host("node01")
    assert await prim.start_control()
    starts = [c[-1] for c in runner.calls if c[6] == "start"]
    assert starts == [
        "somfsl-node01-1",
        "somfsl-ledger-1",  # ledger before MCP
        "somfsl-mcp-1",
    ]
    runner.state["somfsl-node01-1"] = "restarting"
    runner.on(
        lambda a: a[6] == "inspect" and a[-1] == "somfsl-node01-1",
        CommandResult(returncode=0, stdout=b"restarting\n", stderr=b"", timed_out=False),
    )
    with pytest.raises(RotationFailure):
        await prim.start_host("node01")


# ---------------------------------------------------------------- open ingress


async def ready_to_open():
    prim, runner, probe = await drained()
    for step in (prim.stop_control(), prim.stop_host("node01"), prim.stop_host("node02")):
        await step
    for step in (prim.start_host("node01"), prim.start_host("node02"), prim.start_control()):
        await step
    runner.calls.clear()
    probe.listening = True  # the tunnel answers once bootstrapped
    return prim, runner, probe


@pytest.mark.asyncio
async def test_open_ingress_requires_explicit_operator_confirmation():
    async def refuse():
        return False

    prim, runner, _ = make(confirm=refuse)
    await prim.freeze_ingress()
    runner.calls.clear()
    with pytest.raises(RotationFailure):
        await prim.open_ingress()
    assert not any(c[:2] == (LAUNCHCTL, "enable") for c in runner.calls)


@pytest.mark.asyncio
async def test_open_ingress_without_a_fence_does_nothing():
    prim, runner, _ = make()
    with pytest.raises(RotationFailure):
        await prim.open_ingress()
    assert runner.calls == []


@pytest.mark.asyncio
async def test_open_ingress_only_after_every_container_is_observed_running():
    prim, runner, _ = await ready_to_open()
    runner.on(
        lambda a: a[6:7] == ("inspect",) and a[-1] == "somfsl-node02-1",
        CommandResult(returncode=0, stdout=b"exited\n", stderr=b"", timed_out=False),
    )
    with pytest.raises(RotationFailure):
        await prim.open_ingress()
    assert not any(c[:2] == (LAUNCHCTL, "enable") for c in runner.calls)


@pytest.mark.asyncio
async def test_open_ingress_enables_bootstraps_and_verifies_the_tunnel():
    prim, runner, _ = await ready_to_open()
    assert await prim.open_ingress() is True
    verbs = [c[1] for c in runner.calls if c[0] == LAUNCHCTL]
    assert verbs.index("enable") < verbs.index("bootstrap")
    bootstrap = next(c for c in runner.calls if c[:2] == (LAUNCHCTL, "bootstrap"))
    assert bootstrap[2:] == (f"gui/{UID}", f"/Users/yuz/Library/LaunchAgents/{LABEL}.plist")
    # Once reopened the fence is gone: later stages must be refused again.
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()


@pytest.mark.asyncio
async def test_cancellation_during_open_still_fences_again_and_propagates():
    prim, runner, probe = await ready_to_open()

    async def cancelled(host, port):
        raise asyncio.CancelledError

    probe.is_listening = cancelled
    with pytest.raises(asyncio.CancelledError):
        await prim.open_ingress()
    verbs = [c[1] for c in runner.calls if c[0] == LAUNCHCTL]
    assert verbs.index("bootstrap") < len(verbs) - 1 - verbs[::-1].index("disable")
    assert runner.disabled is True and runner.launchd_loaded is False
    with pytest.raises(RotationFailure):
        await prim.start_control()


@pytest.mark.asyncio
async def test_a_second_cancellation_does_not_abandon_the_refence():
    prim, runner, probe = await ready_to_open()
    started = asyncio.Event()

    async def hangs(host, port):
        started.set()
        await asyncio.sleep(30)

    probe.is_listening = hangs
    original = runner.run

    async def slow_refence(argv, *, timeout):
        if argv[:2] in {(LAUNCHCTL, "disable"), (LAUNCHCTL, "bootout")} and started.is_set():
            await asyncio.sleep(0.3)
        return await original(argv, timeout=timeout)

    runner.run = slow_refence
    task = asyncio.ensure_future(prim.open_ingress())
    await started.wait()
    task.cancel()
    await asyncio.sleep(0.05)
    task.cancel()  # second cancel while the shielded re-fence is still running
    with pytest.raises(asyncio.CancelledError):
        await task
    # The cancellation only propagated after the label was fenced again.
    assert runner.disabled is True and runner.launchd_loaded is False


@pytest.mark.asyncio
async def test_unexpected_runner_exception_during_open_is_a_rotation_failure():
    prim, runner, _ = await ready_to_open()

    async def boom(argv, *, timeout):
        if argv[:2] == (LAUNCHCTL, "bootstrap"):
            raise RuntimeError("unexpected")
        return await FakeRunner.run(runner, argv, timeout=timeout)

    runner.run = boom
    with pytest.raises(RotationFailure):
        await prim.open_ingress()
    assert runner.disabled is True


@pytest.mark.asyncio
async def test_open_ingress_fails_when_the_tunnel_does_not_answer():
    prim, runner, probe = await ready_to_open()
    probe.listening = False
    with pytest.raises(RotationFailure):
        await prim.open_ingress()
    # A half-opened ingress must be fenced again, not left enabled for login.
    verbs = [c[1] for c in runner.calls if c[0] == LAUNCHCTL]
    assert verbs.index("bootstrap") < len(verbs) - 1 - verbs[::-1].index("disable")
    assert runner.disabled is True and runner.launchd_loaded is False
    # The failed attempt must not leave a trusted fence behind: later stages
    # need a fresh freeze proof, and the retry re-verifies and re-asks.
    with pytest.raises(RotationFailure):
        await prim.start_control()
    with pytest.raises(RotationFailure):
        await prim.drain_inflight()
    runner.calls.clear()
    probe.listening = False
    await prim.freeze_ingress()
    runner.calls.clear()
    probe.listening = True
    assert await prim.open_ingress() is True
    first_inspect = next(i for i, c in enumerate(runner.calls) if c[0] == LIMACTL)
    first_enable = next(i for i, c in enumerate(runner.calls) if c[:2] == (LAUNCHCTL, "enable"))
    assert first_inspect < first_enable


# ---------------------------------------------------------------- real runner / probe


@pytest.mark.asyncio
async def test_subprocess_runner_is_shell_free_bounded_and_times_out():
    runner = SubprocessRunner(max_output_bytes=1024)
    result = await runner.run((sys.executable, "-c", "print('ok; echo injected')"), timeout=10)
    assert result.returncode == 0 and result.stdout == b"ok; echo injected\n"

    big = await runner.run((sys.executable, "-c", "print('x' * 100000)"), timeout=10)
    assert len(big.stdout) <= 1024 and big.truncated is True

    slow = await runner.run((sys.executable, "-c", "import time; time.sleep(30)"), timeout=0.3)
    assert slow.timed_out is True and slow.returncode != 0

    missing = await runner.run(("/nonexistent/binary-for-test",), timeout=5)
    assert missing.returncode == 127 and missing.timed_out is False


@pytest.mark.asyncio
async def test_runner_reads_every_chunk_to_eof_not_just_the_first():
    runner = SubprocessRunner()
    code = (
        "import sys,time\n"
        "sys.stdout.write('first\\n'); sys.stdout.flush(); time.sleep(0.4)\n"
        "sys.stdout.write('second\\n'); sys.stderr.write('e1\\n'); sys.stderr.flush()\n"
    )
    result = await runner.run((sys.executable, "-c", code), timeout=10)
    assert result.stdout == b"first\nsecond\n" and result.stderr == b"e1\n"
    assert result.returncode == 0 and not result.truncated and not result.timed_out


@pytest.mark.asyncio
async def test_runner_returns_large_output_in_full_without_hanging():
    runner = SubprocessRunner(max_output_bytes=1024 * 1024)
    result = await runner.run(
        (sys.executable, "-c", "import sys; sys.stdout.write('x' * 300000)"), timeout=10
    )
    assert len(result.stdout) == 300000 and not result.truncated and not result.timed_out


@pytest.mark.asyncio
async def test_runner_over_limit_is_truncated_and_killed_promptly():
    runner = SubprocessRunner(max_output_bytes=2048)
    started = asyncio.get_running_loop().time()
    result = await runner.run(
        (sys.executable, "-c", "import sys,time\nsys.stdout.write('y'*10**6)\ntime.sleep(30)"),
        timeout=20,
    )
    assert result.truncated is True and len(result.stdout) <= 2048
    assert asyncio.get_running_loop().time() - started < 10


@pytest.mark.asyncio
async def test_runner_cancellation_kills_the_child(tmp_path):
    pid_file = tmp_path / "pid"
    code = f"import os,time,pathlib; pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)"
    task = asyncio.ensure_future(SubprocessRunner().run((sys.executable, "-c", code), timeout=60))
    for _ in range(100):
        if pid_file.exists() and pid_file.read_text():
            break
        await asyncio.sleep(0.05)
    pid = int(pid_file.read_text())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    import os

    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.05)
    else:
        pytest.fail("child process survived cancellation")


@pytest.mark.asyncio
async def test_runner_kills_forked_grandchildren_on_timeout_and_on_overflow(tmp_path):
    import os

    async def gone(pid_file):
        pid = int(pid_file.read_text())
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            await asyncio.sleep(0.05)
        return False

    grandchild_src = tmp_path / "grandchild.py"
    grandchild_src.write_text(
        "import os, sys, time, pathlib\n"
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    parent_src = tmp_path / "parent.py"
    parent_src.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
        "time.sleep(0.5)\n"
        "if sys.argv[3] == 'spam':\n"
        "    sys.stdout.write('z' * 10**6)\n"
        "    sys.stdout.flush()\n"
        "time.sleep(60)\n"
    )
    for label, timeout, mode in (("timeout", 1.5, "quiet"), ("overflow", 20.0, "spam")):
        pid_file = tmp_path / f"grandchild-{label}"
        result = await SubprocessRunner(max_output_bytes=1024).run(
            (sys.executable, str(parent_src), str(grandchild_src), str(pid_file), mode),
            timeout=timeout,
        )
        assert result.timed_out or result.truncated, (label, result)
        assert await gone(pid_file), f"grandchild survived ({label})"


@pytest.mark.asyncio
async def test_runner_tolerates_killing_an_already_exited_child(monkeypatch):
    real_kill = asyncio.subprocess.Process.kill

    def kill_twice(self):
        real_kill(self)
        raise ProcessLookupError

    monkeypatch.setattr(asyncio.subprocess.Process, "kill", kill_twice)
    result = await SubprocessRunner(max_output_bytes=64).run(
        (sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"), timeout=10
    )
    assert result.truncated is True


@pytest.mark.asyncio
async def test_runner_passes_a_scrubbed_environment(monkeypatch):
    monkeypatch.setenv("SOM_TEST_AMBIENT_SECRET", "leak")
    monkeypatch.setenv("LIMA_HOME", "/tmp/lima-home-for-test")
    code = "import os,json; print(json.dumps(sorted(os.environ)))"
    result = await SubprocessRunner().run((sys.executable, "-c", code), timeout=10)
    names = set(__import__("json").loads(result.stdout))
    assert "SOM_TEST_AMBIENT_SECRET" not in names
    assert {"PATH"} <= names and "LIMA_HOME" in names


@pytest.mark.asyncio
async def test_tcp_probe_distinguishes_listening_refused_and_unknown(monkeypatch):
    probe = TcpPortProbe(timeout=1.0)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert await probe.is_listening("127.0.0.1", port) is True
    finally:
        server.close()
    assert await probe.is_listening("127.0.0.1", port) is False  # refused

    async def hangs(*args, **kwargs):
        await asyncio.sleep(30)

    monkeypatch.setattr(asyncio, "open_connection", hangs)
    with pytest.raises(OSError):  # a timeout proves nothing: unknown, not "closed"
        await TcpPortProbe(timeout=0.1).is_listening("127.0.0.1", port)

    async def unreachable(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(asyncio, "open_connection", unreachable)
    with pytest.raises(OSError):
        await probe.is_listening("127.0.0.1", port)
