"""Synthetic control-plane adapter evidence, never deployment authorization."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import asyncssh
import pytest

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.approvals.authorization import AuditOnlyExecutionAuthorizer
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.host_agent.visibility_snapshot_v5 import sign_snapshot
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.policy.models import Effect, PolicyDocument, PolicyRule, RoleSpec
from ssh_over_mcp.ssh.errors import (
    SSHAuditPersistenceError,
    SSHPolicyDenied,
    SSHRemoteResponseError,
)
from ssh_over_mcp.ssh.filesystem import SSHFilesystemClient
from ssh_over_mcp.ssh.protocol_v2 import decode_request_v2
from ssh_over_mcp.ssh.transport import SSHExecutionResult


class Authority:
    def __init__(self, engine):
        self.engine = engine
        self.active = True
        self.signed = []

    def current_epoch(self, *, host, policy_sha256):
        return 7

    def sign(self, snapshot):
        self.signed.append(snapshot)
        return sign_snapshot(snapshot, key=b"t" * 32)

    def is_active(self, snapshot):
        return self.active


class Ledger:
    def __init__(self):
        self.events = []
        self.fail = None
        self.hook = lambda event: None

    async def append_audit(self, event):
        self.hook(event)
        if event.event_type == self.fail:
            raise RuntimeError("private ledger failure")
        self.events.append(event)
        return "evt_" + "f" * 32


@pytest.fixture
def setup():
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    inventory = Inventory(
        hosts={
            "node": Host(
                address="127.0.0.1",
                ssh_user="fs",
                credential_ref="test",
                host_key=key,
                allowed_roles=frozenset({"operator"}),
            )
        }
    )
    engine = PolicyEngine(
        inventory=inventory,
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
                PolicyRule(
                    id="deny",
                    effect=Effect.DENY,
                    roles=("operator",),
                    tools=("fs_list",),
                    paths=("/srv/data/private/**",),
                ),
            ),
        ),
    )
    authority = Authority(engine)
    ledger = Ledger()
    context = OperationContext(
        request_id="req_" + "a" * 32,
        principal=PrincipalContext(principal_id="trusted:alice", profile="operator"),
        received_at=datetime.now(UTC),
    )
    state = SimpleNamespace(
        authority=authority,
        ledger=ledger,
        context=context,
        mutate=lambda body: body,
        raw=None,
        calls=[],
        error=None,
    )

    async def run_v2(**kwargs):
        state.calls.append(kwargs)
        if state.error:
            raise state.error
        request = decode_request_v2(kwargs["payload"])
        snap = request.signed_snapshot.payload
        body = {
            "request_id": context.request_id,
            "host": "node",
            "root": "/srv/data",
            "policy_epoch": 7,
            "snapshot_id": snap.snapshot_id,
            "entries": [
                {
                    "path": "/srv/data/a",
                    "kind": "regular",
                    "size": 1,
                    "mode": 0o640,
                    "uid": 1000,
                    "gid": 1000,
                    "mtime_ns": 123,
                }
            ],
        }
        body = state.mutate(body)
        return SSHExecutionResult(
            request_id=context.request_id,
            host="node",
            exit_status=0,
            duration_ms=1,
            stdout=state.raw if state.raw is not None else json.dumps(body).encode(),
        )

    state.transport = SimpleNamespace(
        run_v2=run_v2, connections=SimpleNamespace(inventory=inventory)
    )
    state.client = SSHFilesystemClient(
        authorizer=AuditOnlyExecutionAuthorizer(policy=engine, ledger=ledger),
        audit=AuditRecorder(ledger),
        transport=state.transport,
    )
    return state


async def invoke(s, **kwargs):
    return await s.client.list(
        host="node", path="/srv/data", context=s.context, max_entries=kwargs.get("max_entries", 8)
    )


def enable(s):
    s.client.visibility_authority = s.authority


@pytest.mark.asyncio
async def test_opt_in_and_trusted_identity_binding(setup):
    s = setup
    with pytest.raises(SSHRemoteResponseError):
        await invoke(s)
    assert not s.calls
    enable(s)
    result = await invoke(s)
    snap = s.authority.signed[0]
    assert (snap.principal, snap.profile, snap.request_id) == (
        "trusted:alice",
        "operator",
        s.context.request_id,
    )
    assert snap.central_policy_sha256 == s.authority.engine.policy_version[7:]
    assert snap.policy_epoch == 7 and snap.max_entries == 8
    public = asyncssh.import_public_key(s.transport.connections.inventory.hosts["node"].host_key)
    assert snap.host_key_sha256 == hashlib.sha256(public.public_data).hexdigest()
    assert result.entries[0].path == "/srv/data/a"
    assert [e.event_type for e in s.ledger.events][-2:] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_COMPLETED,
    ]
    assert s.ledger.events[-1].safe_summary.stdin_fingerprint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("size", "1"),
        ("size", -1),
        ("mode", 65536),
        ("uid", 1.5),
        ("gid", None),
        ("mtime_ns", "3"),
        ("kind", "symlink"),
        ("kind", "fifo"),
        ("extra", 1),
        ("path", "/srv/data/private"),
        ("path", "/srv/data/a/b"),
        ("path", "/srv/data/../a"),
    ],
)
async def test_bad_child_rejects_entire_response(setup, field, value):
    s = setup
    enable(s)

    def mutate(body):
        body["entries"].append({**body["entries"][0], "path": "/srv/data/z", field: value})
        return body

    s.mutate = mutate
    with pytest.raises(SSHRemoteResponseError):
        await invoke(s)
    assert s.ledger.events[-1].event_type == AuditEventType.EXECUTION_FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"\xff",
        b"[]",
        b'{"entries":[],"entries":[]}',
        b"[" * 3000 + b"]" * 3000,
        b" " * 65537,
        b'{"x":NaN}',
    ],
    ids=["empty", "encoding", "array", "duplicate", "deep", "oversize", "nan"],
)
async def test_malformed_bounded_response(setup, raw):
    enable(setup)
    setup.raw = raw
    with pytest.raises(SSHRemoteResponseError):
        await invoke(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "wrong"),
        ("host", "other"),
        ("root", "/other"),
        ("policy_epoch", 8),
        ("policy_epoch", True),
        ("snapshot_id", "0" * 32),
    ],
)
async def test_response_binding(setup, field, value):
    enable(setup)
    setup.mutate = lambda body: {**body, field: value}
    with pytest.raises(SSHRemoteResponseError):
        await invoke(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [True, 0, 65, "8"])
async def test_invalid_limit_before_network(setup, limit):
    enable(setup)
    with pytest.raises(ValueError):
        await invoke(setup, max_entries=limit)
    assert not setup.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ["before", "response", "completion"])
async def test_revocation(setup, when):
    s = setup
    enable(s)
    if when == "before":
        s.authority.active = False
    elif when == "response":

        def mutate(body):
            s.authority.active = False
            return body

        s.mutate = mutate
    else:

        def hook(event):
            if event.event_type == AuditEventType.EXECUTION_COMPLETED:
                s.authority.active = False

        s.ledger.hook = hook
    with pytest.raises(SSHRemoteResponseError):
        await invoke(s)
    if when == "before":
        assert not s.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event",
    [
        AuditEventType.POLICY_ALLOWED,
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_COMPLETED,
    ],
)
async def test_audit_failure_never_returns_data(setup, event):
    enable(setup)
    setup.ledger.fail = event
    with pytest.raises(SSHAuditPersistenceError):
        await invoke(setup)
    if event != AuditEventType.EXECUTION_COMPLETED:
        assert not setup.calls


@pytest.mark.asyncio
async def test_cancellation_audited_without_retry(setup):
    enable(setup)
    setup.error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await invoke(setup)
    assert len(setup.calls) == 1
    assert setup.ledger.events[-1].event_type == AuditEventType.EXECUTION_CANCELLED


@pytest.mark.asyncio
async def test_denied_root_before_signing(setup):
    enable(setup)
    with pytest.raises(SSHPolicyDenied):
        await setup.client.list(host="node", path="/etc", context=setup.context, max_entries=8)
    assert not setup.calls and not setup.authority.signed


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["duplicate", "unsorted", "overflow", "missing", "extra"])
async def test_response_collection_contract(setup, case):
    enable(setup)

    def mutate(body):
        entry = body["entries"][0]
        if case == "duplicate":
            body["entries"].append(entry)
        elif case == "unsorted":
            body["entries"] = [{**entry, "path": "/srv/data/z"}, entry]
        elif case == "overflow":
            body["entries"] = [{**entry, "path": f"/srv/data/{i:02}"} for i in range(9)]
        elif case == "missing":
            del entry["uid"]
        else:
            body["cursor"] = "unsupported"
        return body

    setup.mutate = mutate
    with pytest.raises(SSHRemoteResponseError):
        await invoke(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ["start", "response", "completion"])
async def test_policy_change_across_awaits(setup, when):
    s = setup
    enable(s)

    def change():
        s.authority.engine = PolicyEngine(
            inventory=s.authority.engine.inventory,
            policy=PolicyDocument(roles={"operator": RoleSpec()}, rules=()),
        )

    if when == "response":

        def mutate(body):
            change()
            return body

        s.mutate = mutate
    else:
        target = (
            AuditEventType.EXECUTION_STARTED
            if when == "start"
            else AuditEventType.EXECUTION_COMPLETED
        )

        def hook(event):
            if event.event_type == target:
                change()

        s.ledger.hook = hook
    with pytest.raises(SSHRemoteResponseError):
        await invoke(s)
    if when == "start":
        assert not s.calls


@pytest.mark.asyncio
async def test_approval_required_never_signs_or_executes(setup):
    from ssh_over_mcp.policy.models import RiskLevel, RiskPolicy
    from ssh_over_mcp.ssh.errors import SSHApprovalRequired

    s = setup
    enable(s)
    old = s.authority.engine
    engine = PolicyEngine(
        inventory=old.inventory,
        policy=old.policy.model_copy(
            update={"risk": RiskPolicy(approval_required=frozenset({RiskLevel.LOW}))}
        ),
    )
    s.authority.engine = engine
    s.client.authorizer = AuditOnlyExecutionAuthorizer(policy=engine, ledger=s.ledger)
    with pytest.raises(SSHApprovalRequired):
        await invoke(s)
    assert not s.calls and not s.authority.signed


@pytest.mark.asyncio
async def test_approval_required_creates_no_unusable_ledger_approval(setup):
    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer
    from ssh_over_mcp.policy.models import RiskLevel, RiskPolicy
    from ssh_over_mcp.ssh.errors import SSHApprovalRequired

    s = setup
    enable(s)
    old = s.authority.engine
    engine = PolicyEngine(
        inventory=old.inventory,
        policy=old.policy.model_copy(
            update={"risk": RiskPolicy(approval_required=frozenset({RiskLevel.LOW}))}
        ),
    )
    s.authority.engine = engine
    ensured: list[object] = []

    class ApprovalLedger(Ledger):
        async def ensure_approval(self, **kwargs):
            ensured.append(kwargs)
            raise AssertionError("fs_list cannot use an approval")

        async def consume_approval(self, **kwargs):
            raise AssertionError("fs_list cannot use an approval")

    ledger = ApprovalLedger()
    s.client.authorizer = ExecutionAuthorizer(policy=engine, ledger=ledger)
    s.client.audit = AuditRecorder(ledger)
    with pytest.raises(SSHApprovalRequired) as raised:
        await invoke(s)
    assert raised.value.approval_status is None
    assert ensured == [] and not s.calls and not s.authority.signed
    assert [e.event_type for e in ledger.events] == [AuditEventType.APPROVAL_REQUIRED]


@pytest.mark.asyncio
@pytest.mark.parametrize("epoch", [True, 0, -1, "7"])
async def test_invalid_trusted_epoch_cannot_sign(setup, epoch):
    enable(setup)
    setup.authority.current_epoch = lambda **kwargs: epoch
    with pytest.raises(SSHRemoteResponseError):
        await invoke(setup)
    assert not setup.calls and not setup.authority.signed


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["pin", "inventory", "signer", "guard"])
async def test_broken_authority_fails_closed(setup, kind):
    enable(setup)
    if kind == "pin":
        setup.authority.engine.inventory.hosts["node"] = setup.authority.engine.inventory.hosts[
            "node"
        ].model_copy(update={"host_key": "bad"})
    elif kind == "inventory":
        setup.transport.connections.inventory = setup.authority.engine.inventory.model_copy()
    elif kind == "signer":

        def sign(snapshot):
            return sign_snapshot(snapshot.model_copy(update={"principal": "other"}), key=b"t" * 32)

        setup.authority.sign = sign
    else:
        setup.authority.is_active = lambda snapshot: 1
    with pytest.raises(SSHRemoteResponseError):
        await invoke(setup)
    assert not setup.calls


@pytest.mark.asyncio
async def test_constructor_opt_in_empty_result_and_budget_fingerprint(setup):
    s = setup
    s.client = SSHFilesystemClient(
        authorizer=s.client.authorizer,
        audit=s.client.audit,
        transport=s.transport,
        visibility_authority=s.authority,
    )
    s.mutate = lambda body: {**body, "entries": []}
    assert not (await invoke(s, max_entries=1)).entries
    first = s.ledger.events[-1].safe_summary.stdin_fingerprint
    await invoke(s, max_entries=2)
    assert s.ledger.events[-1].safe_summary.stdin_fingerprint != first


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["epoch", "policy"])
async def test_authority_state_changed_without_replacing_engine(setup, change):
    enable(setup)

    def mutate(body):
        if change == "epoch":
            setup.authority.current_epoch = lambda **kwargs: 8
        else:
            old = setup.authority.engine.policy
            setup.authority.engine.policy = old.model_copy(update={"rules": old.rules[:1]})
        return body

    setup.mutate = mutate
    with pytest.raises(SSHRemoteResponseError):
        await invoke(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes,error_name,event",
    [
        ({"exit_status": 77}, "SSHRemotePolicyDenied", AuditEventType.REMOTE_POLICY_DENIED),
        ({"exit_status": 69}, "SSHRemoteOperationError", AuditEventType.EXECUTION_FAILED),
        ({"timed_out": True}, "SSHRequestTimeout", AuditEventType.EXECUTION_FAILED),
        ({"truncated": True}, "SSHOutputLimitExceeded", AuditEventType.EXECUTION_FAILED),
        ({"stderr": b"private"}, "SSHRemoteResponseError", AuditEventType.EXECUTION_FAILED),
        ({"request_id": "foreign"}, "SSHRemoteResponseError", AuditEventType.EXECUTION_FAILED),
    ],
)
async def test_transport_failures_audited_without_fallback(setup, changes, error_name, event):
    from ssh_over_mcp.ssh import errors

    enable(setup)
    original = setup.transport.run_v2

    async def run(**kwargs):
        return (await original(**kwargs)).model_copy(update=changes)

    setup.transport.run_v2 = run
    with pytest.raises(getattr(errors, error_name)):
        await invoke(setup)
    assert len(setup.calls) == 1
    assert setup.ledger.events[-1].event_type == event


@pytest.mark.asyncio
async def test_failure_audit_unavailable_still_returns_no_data(setup):
    enable(setup)
    setup.raw = b"{}"
    setup.ledger.fail = AuditEventType.EXECUTION_FAILED
    with pytest.raises(SSHAuditPersistenceError):
        await invoke(setup)


@pytest.mark.asyncio
async def test_unrepresentable_central_rule_is_audited_as_policy_denial(setup):
    s = setup
    enable(s)
    old = s.authority.engine
    rules = (
        *old.policy.rules,
        PolicyRule(
            id="glob-deny",
            effect=Effect.DENY,
            roles=("operator",),
            tools=("fs_list",),
            paths=("/srv/data/*.key",),
        ),
    )
    engine = PolicyEngine(
        inventory=old.inventory, policy=old.policy.model_copy(update={"rules": rules})
    )
    s.authority.engine = engine
    s.client.authorizer = AuditOnlyExecutionAuthorizer(policy=engine, ledger=s.ledger)
    with pytest.raises(SSHPolicyDenied):
        await invoke(s)
    types = [e.event_type for e in s.ledger.events]
    assert types[-1] == AuditEventType.POLICY_DENIED
    assert AuditEventType.EXECUTION_STARTED not in types
    assert AuditEventType.EXECUTION_FAILED not in types
    assert not s.calls and not s.authority.signed


@pytest.mark.asyncio
async def test_unavailable_authority_before_authorization_is_audited(setup):
    s = setup
    enable(s)

    def broken(**kwargs):
        raise RuntimeError("signer store offline")

    s.authority.current_epoch = broken
    with pytest.raises(SSHRemoteResponseError):
        await invoke(s)
    assert [e.event_type for e in s.ledger.events] == [AuditEventType.EXECUTION_FAILED]
    assert s.ledger.events[0].host == "node" and s.ledger.events[0].tool == "fs_list"
    assert not s.calls


@pytest.mark.asyncio
async def test_unauditable_authority_failure_fails_closed(setup):
    s = setup
    enable(s)
    s.authority.current_epoch = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("x"))
    s.ledger.fail = AuditEventType.EXECUTION_FAILED
    with pytest.raises(SSHAuditPersistenceError):
        await invoke(s)
    assert not s.calls


@pytest.mark.asyncio
async def test_snapshot_tolerates_small_host_clock_lag_within_fixed_ttl(setup, monkeypatch):
    import ssh_over_mcp.ssh.filesystem as module
    from ssh_over_mcp.host_agent.visibility_snapshot_v5 import MAX_SNAPSHOT_TTL_SECONDS

    s = setup
    enable(s)
    monkeypatch.setattr(module.time, "time", lambda: 1_800_000_000.5)
    await invoke(s)
    snap = s.authority.signed[0]
    assert snap.issued_at == 1_800_000_000 - module.SNAPSHOT_CLOCK_SKEW_SECONDS
    assert 1 <= module.SNAPSHOT_CLOCK_SKEW_SECONDS <= 10
    assert snap.expires_at - snap.issued_at <= MAX_SNAPSHOT_TTL_SECONDS
    assert snap.expires_at > 1_800_000_000 + 30
