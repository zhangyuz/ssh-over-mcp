from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures/staging-envelope-v1"


@pytest.fixture
def codec(monkeypatch):
    path = ROOT / "ops/live-e2e"
    assert (path / "staging_envelope.py").is_file(), "dormant envelope is not implemented"
    monkeypatch.syspath_prepend(str(path))
    return importlib.import_module("staging_envelope")


@pytest.fixture
def wire(monkeypatch):
    path = ROOT / "ops/live-e2e"
    assert (path / "staging_wire.py").is_file(), "bounded wire codec is not implemented"
    monkeypatch.syspath_prepend(str(path))
    return importlib.import_module("staging_wire")


def fixture_inputs():
    envelope = json.loads((FIXTURE / "envelope.json").read_bytes())
    return envelope["inventory"], envelope["inspection"]


def test_complete_literal_golden_envelope(codec):
    inventory, inspection = fixture_inputs()
    expected = json.loads((FIXTURE / "expected.json").read_bytes())
    raw = (FIXTURE / "envelope.json").read_bytes()
    assert len(inventory["entries"]) == 13
    assert codec.encode_envelope(inventory, inspection) == raw
    assert codec.validate_envelope(raw) is None
    assert len(raw) == expected["envelope_bytes"] == 3253
    assert hashlib.sha256(raw).hexdigest() == expected["envelope_sha256"]
    inv = (FIXTURE / "inventory.json").read_bytes()
    assert len(inv) == expected["inventory_bytes"] == 3023
    assert hashlib.sha256(inv).hexdigest() == expected["inventory_sha256"]


@pytest.mark.parametrize("digits", [4299, 4300, 4301, 5001, 10000])
@pytest.mark.parametrize("negative", [False, True])
def test_local_decimal_conversion_preserves_guard(wire, monkeypatch, digits, negative):
    guard = sys.get_int_max_str_digits()

    def forbidden(*args):
        pytest.fail("codec changed the process-wide integer guard")

    monkeypatch.setattr(sys, "set_int_max_str_digits", forbidden)
    value = 10 ** (digits - 1)
    token = b"1" + b"0" * (digits - 1)
    if negative:
        value, token = -value, b"-" + token
    assert wire.encode_integer(value, max_bytes=len(token)) == token
    assert wire.decode_integer(token, max_bytes=len(token)) == value
    for call, argument in [(wire.encode_integer, value), (wire.decode_integer, token)]:
        with pytest.raises(wire.EnvelopeError, match="^staging envelope rejected$"):
            call(argument, max_bytes=len(token) - 1)
    assert sys.get_int_max_str_digits() == guard


@pytest.mark.parametrize(
    "field,negative", [("size", False), ("mtime_ns", False), ("ctime_ns", True)]
)
def test_large_metadata_integer_agrees_on_encode_validate(codec, field, negative):
    inventory, inspection = fixture_inputs()
    value = 10**5000
    inventory["entries"][2][field] = -value if negative else value
    raw = codec.encode_envelope(inventory, inspection)
    token = (b"-" if negative else b"") + b"1" + b"0" * 5000
    assert b'"' + field.encode() + b'":' + token in raw
    assert codec.validate_envelope(raw) is None


def test_provenance_separated_and_encoded_bytes_detached(codec):
    inventory, inspection = fixture_inputs()
    before = codec.encode_envelope(inventory, inspection)
    after_inspection = copy.deepcopy(inspection)
    after_inspection["attempt"] = "2"
    after = codec.encode_envelope(inventory, after_inspection)
    first, second = json.loads(before), json.loads(after)
    assert first["inventory"] == second["inventory"]
    assert first["inventory_sha256"] == second["inventory_sha256"]
    assert before != after
    inventory["marker"]["inode"] += 1
    assert (
        json.loads(codec.encode_envelope(inventory, inspection))["inventory_sha256"]
        != first["inventory_sha256"]
    )
    assert before == (FIXTURE / "envelope.json").read_bytes()


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def unchecked_envelope(inventory, inspection):
    return canonical(
        {
            "schema_version": 1,
            "inventory": inventory,
            "inspection": inspection,
            "inventory_sha256": hashlib.sha256(canonical(inventory)).hexdigest(),
        }
    )


def populated_inventory(count):
    inventory, inspection = fixture_inputs()
    for index in range(count - len(inventory["entries"])):
        entry = dict(inventory["entries"][2], path=f"wheels/{index:04d}", inode=100000 + index)
        inventory["entries"].append(entry)
    inventory["entries"].sort(key=lambda entry: entry["path"].encode("utf-8", "surrogateescape"))
    return inventory, inspection


def byte_boundary(target):
    inventory, inspection = populated_inventory(4096)
    remaining = target - len(unchecked_envelope(inventory, inspection))
    # All added names remain siblings under wheels. ASCII padding adds exactly one byte.
    for entry in inventory["entries"]:
        if entry["path"].startswith("wheels/"):
            padding = min(remaining, 4096 - len(entry["path"]))
            entry["path"] += "x" * padding
            remaining -= padding
    assert remaining == 0
    inventory["entries"].sort(key=lambda entry: entry["path"].encode())
    assert len(unchecked_envelope(inventory, inspection)) == target
    return inventory, inspection


def test_complete_envelope_exact_budget_and_one_byte_overflow(codec):
    inventory, inspection = byte_boundary(2097152)
    raw = unchecked_envelope(inventory, inspection)
    assert codec.encode_envelope(inventory, inspection) == raw
    assert codec.validate_envelope(raw) is None
    oversized, inspection = byte_boundary(2097153)
    for fn, args in [
        (codec.encode_envelope, (oversized, inspection)),
        (codec.validate_envelope, (unchecked_envelope(oversized, inspection),)),
    ]:
        with pytest.raises(codec.EnvelopeError, match="^staging envelope rejected$"):
            fn(*args)


def test_entry_count_boundary(codec):
    inventory, inspection = populated_inventory(4096)
    assert codec.validate_envelope(codec.encode_envelope(inventory, inspection)) is None
    inventory, inspection = populated_inventory(4097)
    with pytest.raises(codec.EnvelopeError):
        codec.encode_envelope(inventory, inspection)


def leaves(value, prefix=()):
    if type(value) is dict:
        for key, item in value.items():
            yield from leaves(item, (*prefix, key))
    elif type(value) is list:
        for key, item in enumerate(value):
            yield from leaves(item, (*prefix, key))
    else:
        yield prefix, value


LEAVES = list(leaves(json.loads((FIXTURE / "envelope.json").read_bytes())))


@pytest.mark.parametrize("path,original", LEAVES, ids=["/".join(map(str, p)) for p, _ in LEAVES])
def test_every_scalar_rejects_wrong_exact_type(codec, path, original):
    for replacement in [None, True, 1.0, [], {}, "1" if type(original) is int else 1]:
        envelope = json.loads((FIXTURE / "envelope.json").read_bytes())
        parent = envelope
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = replacement
        # Fix hashes to ensure the domain/type violation itself is rejected.
        if path[0] == "inventory":
            envelope["inventory_sha256"] = hashlib.sha256(
                canonical(envelope["inventory"])
            ).hexdigest()
        with pytest.raises(codec.EnvelopeError):
            codec.validate_envelope(canonical(envelope))
        if path[0] in {"inventory", "inspection"}:
            with pytest.raises(codec.EnvelopeError):
                codec.encode_envelope(envelope["inventory"], envelope["inspection"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "0"),
        ("run_id", "01"),
        ("run_id", "+1"),
        ("run_id", "١"),
        ("attempt", "9223372036854775808"),
        ("attempt", "1" * 20),
        ("authority_sha", "A" * 40),
        ("authority_sha", "sha1:" + "a" * 40),
    ],
)
def test_invalid_trusted_provenance(codec, field, value):
    inventory, inspection = fixture_inputs()
    inspection[field] = value
    with pytest.raises(codec.EnvelopeError):
        codec.encode_envelope(inventory, inspection)


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "catalog",
        "root",
        "marker",
        "layout",
        "order",
        "hardlink",
        "writable",
        "device",
        "identity",
        "parent",
        "expected-size",
        "content-field",
    ],
)
def test_hash_consistent_bad_binding_and_topology(codec, change):
    inventory, inspection = fixture_inputs()
    if change == "unknown":
        inventory["incident"] = "recover.cc8Del"
    elif change == "catalog":
        inventory["staging"]["expected_commit"] = "b" * 40
    elif change == "root":
        inventory["entries"][0]["inode"] += 1
    elif change == "marker":
        inventory["marker"]["owner_pid"] += 1
    elif change == "layout":
        inventory["entries"].pop(1)
    elif change == "order":
        inventory["entries"].reverse()
    elif change == "hardlink":
        inventory["entries"][2]["nlink"] = 2
    elif change == "writable":
        inventory["entries"][2]["mode"] = 0o666
    elif change == "device":
        inventory["entries"][2]["device"] += 1
    elif change == "identity":
        inventory["entries"][2]["inode"] = inventory["entries"][1]["inode"]
    elif change == "parent":
        inventory["parent"]["ancestors"][5]["uid"] = 0
    elif change == "expected-size":
        inventory["entries"][5]["size"] = 40
    elif change == "content-field":
        inventory["entries"][5]["content"] = inventory["staging"]["expected_commit"]
    with pytest.raises(codec.EnvelopeError):
        codec.validate_envelope(unchecked_envelope(inventory, inspection))


def test_older_catalog_and_safe_escaped_names(codec):
    inventory, inspection = fixture_inputs()
    inventory["incident"] = "older-target"
    inventory["staging"].update(
        basename="ssh-over-mcp-e2e-w_kn4rus",
        inode=186877220,
        expected_commit="bf84c7aafa5c79d629fc04488b5e0bda1cd98cef",
    )
    inventory["entries"][0]["inode"] = 186877220
    entry = dict(inventory["entries"][2], inode=99999, path='wheels/quote"\n\udcff')
    inventory["entries"].append(entry)
    raw = codec.encode_envelope(inventory, inspection)
    assert b'quote\\"\\n\\udcff' in raw
    assert codec.validate_envelope(raw) is None


@pytest.mark.parametrize(
    "raw",
    [
        b"[" * 10000 + b"0" + b"]" * 10000,
        b"[" + b"0," * 99999 + b"0]",
        b'{"a":' + b"0," * 100000 + b'"z":0}',
        b'{"' + b"k" * 20000 + b'":0}',
        b'{"inspection":{"attempt":"' + b"1" * 10000,
        b'{"inspection":{"attempt":"1","attempt":"1"}}',
    ],
)
def test_hostile_shape_refuses_before_materialization(wire, monkeypatch, raw):
    assert len(raw) <= 2097152
    calls = []
    original = wire._materialize_wire

    def spy(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(wire, "_materialize_wire", spy)
    with pytest.raises(wire.EnvelopeError, match="^staging envelope rejected$"):
        wire.parse_wire(raw, kind="envelope")
    assert calls == []


@pytest.mark.parametrize("raw", [b"true", b"null", b"01", b"-0", b"1e2", b"+1", b" 1", b"1.0"])
def test_integer_tokens_are_canonical(wire, raw):
    with pytest.raises(wire.EnvelopeError):
        wire.decode_integer(raw, max_bytes=100)


def test_supplementary_literal_scalar_vectors(wire):
    value = {"incident": "stale-target", "run_id": "37563415169", "schema_version": 1}
    raw = wire._encode(
        value, {"incident": "incident", "run_id": "provenance", "schema_version": "version"}, 100
    )
    assert raw == b'{"incident":"stale-target","run_id":"37563415169","schema_version":1}'
    assert len(raw) == 69
    assert (
        hashlib.sha256(raw).hexdigest()
        == "54213dd999af295227f6d96133908796a0586cd6ff4b5d4d3a44d66766804d5e"
    )
    assert (
        base64.b64encode(raw)
        == b"eyJpbmNpZGVudCI6InN0YWxlLXRhcmdldCIsInJ1bl9pZCI6IjM3NTYzNDE1MTY5Iiwic2NoZW1hX3ZlcnNpb24iOjF9"
    )
    inspection = {"attempt": "1", "authority_sha": "a" * 40, "run_id": "37563415169"}
    raw = wire._encode(
        inspection, {"attempt": "provenance", "authority_sha": "sha40", "run_id": "provenance"}, 100
    )
    assert (
        raw
        == b'{"attempt":"1","authority_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_id":"37563415169"}'
    )
    assert len(raw) == 97
    assert (
        hashlib.sha256(raw).hexdigest()
        == "81e5746c2b075dadcbe423f9953bc705d47da0209c210b8913b9dd85ba56e6a8"
    )


def test_excess_entry_and_ancestor_counts_refuse_before_materialization(wire, monkeypatch):
    inventory, inspection = populated_inventory(4097)
    raw = unchecked_envelope(inventory, inspection)
    calls = []
    original = wire._materialize_wire

    def spy(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(wire, "_materialize_wire", spy)
    with pytest.raises(wire.EnvelopeError):
        wire.parse_wire(raw, kind="envelope")
    inventory, inspection = fixture_inputs()
    inventory["parent"]["ancestors"].append(copy.deepcopy(inventory["parent"]["ancestors"][-1]))
    with pytest.raises(wire.EnvelopeError):
        wire.parse_wire(unchecked_envelope(inventory, inspection), kind="envelope")
    assert calls == []


def test_subclasses_and_unknown_fields_cannot_enter_encoded_schema(codec):
    class FakeInt(int):
        pass

    class FakeStr(str):
        pass

    class FakeDict(dict):
        pass

    for value in [FakeInt(17), FakeStr("17")]:
        inventory, inspection = fixture_inputs()
        inventory["entries"][2]["size"] = value
        with pytest.raises(codec.EnvelopeError):
            codec.encode_envelope(inventory, inspection)
    inventory, inspection = fixture_inputs()
    with pytest.raises(codec.EnvelopeError):
        codec.encode_envelope(FakeDict(inventory), inspection)
    inventory["unexpected"] = "secret-canary"
    with pytest.raises(codec.EnvelopeError, match="^staging envelope rejected$"):
        codec.encode_envelope(inventory, inspection)


@pytest.mark.parametrize(
    "path,allowed",
    [
        ("wheels/" + "x" * 4089, True),
        ("wheels/" + "x" * 4090, False),
        ("wheels/../escape", False),
        ("wheels/" + "/".join(["d"] * 11), True),
        ("wheels/" + "/".join(["d"] * 12), False),
    ],
)
def test_path_and_depth_boundaries(codec, path, allowed):
    inventory, inspection = fixture_inputs()
    parts = path.split("/")
    for depth in range(2, len(parts)):
        inventory["entries"].append(
            dict(inventory["entries"][1], path="/".join(parts[:depth]), inode=30000 + depth)
        )
    inventory["entries"].append(dict(inventory["entries"][2], path=path, inode=40000))
    inventory["entries"].sort(key=lambda e: e["path"].encode())
    if allowed:
        assert codec.validate_envelope(codec.encode_envelope(inventory, inspection)) is None
    else:
        with pytest.raises(codec.EnvelopeError):
            codec.encode_envelope(inventory, inspection)


@pytest.mark.parametrize(
    "mutation",
    [
        "digest-upper",
        "digest-prefix",
        "digest-mismatch",
        "whitespace",
        "negative-zero",
        "alternate-escape",
        "extra-key",
    ],
)
def test_noncanonical_or_inconsistent_raw_envelope(codec, mutation):
    raw = (FIXTURE / "envelope.json").read_bytes()
    if mutation == "digest-upper":
        raw = raw.replace(
            b"b8553ab4e4499fe5acf144a890efc43f0414d7c888cb19dc4e64533bf2384c49",
            b"B8553AB4E4499FE5ACF144A890EFC43F0414D7C888CB19DC4E64533BF2384C49",
        )
    elif mutation == "digest-prefix":
        raw = raw.replace(b'"inventory_sha256":"', b'"inventory_sha256":"sha256:')
    elif mutation == "digest-mismatch":
        raw = raw.replace(b"b8553ab4", b"00000000")
    elif mutation == "whitespace":
        raw = b" " + raw
    elif mutation == "negative-zero":
        raw = raw.replace(b'"mtime_ns":1', b'"mtime_ns":-0')
    elif mutation == "alternate-escape":
        raw = raw.replace(b"stale-target", b"stale\\u002dtarget")
    elif mutation == "extra-key":
        raw = raw[:-1] + b',"zz":"secret-canary"}'
    with pytest.raises(codec.EnvelopeError, match="^staging envelope rejected$"):
        codec.validate_envelope(raw)


def test_del_escape_budget_checked_before_encoded_allocation(wire, monkeypatch):
    original = json.dumps
    calls = []

    def spy(value, **kwargs):
        calls.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(json, "dumps", spy)
    with pytest.raises(wire.EnvelopeError):
        wire._string_bytes("\x7f", "absolute", 7)
    assert calls == []
    assert wire._string_bytes("\x7f", "absolute", 8) == b'"\\u007f"'
