from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/native_inputs.py"
SIGNED = datetime(2026, 10, 4, 13, 26, 37, tzinfo=UTC)
NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
INDEX_HASH = "a" * 64
INDEX_PATH = "main/binary-amd64/Packages.xz"


def _load_module() -> ModuleType:
    assert MODULE.is_file(), "bounded native Release parser is missing"
    name = "ssh_over_mcp_native_inputs"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _contract(module: ModuleType, **changes):
    values = {
        "suite": "resolute-updates",
        "codename": "resolute",
        "signed_date": SIGNED,
        "valid_until": None,
        "architecture": "amd64",
        "component": "main",
    }
    values.update(changes)
    return module.ReleaseContract(**values)


def _payload(
    *,
    suite: str = "resolute-updates",
    codename: str = "resolute",
    date: str = "Sun, 04 Oct 2026 13:26:37 +0000",
    valid_until: str | None = None,
    architectures: str = "amd64 arm64",
    components: str = "main universe",
    sha256_lines: tuple[str, ...] = (f" {INDEX_HASH} 1024 {INDEX_PATH}",),
    extra: tuple[str, ...] = (),
) -> bytes:
    lines = [
        "Origin: Ubuntu",
        "Label: Ubuntu",
        f"Suite: {suite}",
        f"Codename: {codename}",
        f"Date: {date}",
    ]
    if valid_until is not None:
        lines.append(f"Valid-Until: {valid_until}")
    lines.extend(
        [
            f"Architectures: {architectures}",
            f"Components: {components}",
            *extra,
            "SHA256:",
            *sha256_lines,
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def test_parses_frozen_release_payload_without_claiming_signature_verification() -> None:
    module = _load_module()

    metadata = module.parse_release_payload(
        _payload(), contract=_contract(module), now=NOW
    )

    assert metadata.suite == "resolute-updates"
    assert metadata.codename == "resolute"
    assert metadata.signed_date == SIGNED
    assert metadata.valid_until is None
    assert metadata.architectures == ("amd64", "arm64")
    assert metadata.components == ("main", "universe")
    assert metadata.sha256 == (
        module.DigestRecord(path=INDEX_PATH, size=1024, sha256=INDEX_HASH),
    )
    assert not hasattr(metadata, "signature_verified")
    with pytest.raises((AttributeError, TypeError)):
        metadata.suite = "attacker"


def test_accepts_other_bounded_deb822_multiline_fields_around_sha256() -> None:
    module = _load_module()
    payload = _payload(
        extra=(
            "MD5Sum:",
            " 11111111111111111111111111111111 512 main/binary-amd64/Packages.gz",
            "SHA1:",
            " 2222222222222222222222222222222222222222 768 main/binary-amd64/Packages.gz",
        ),
        sha256_lines=(
            f" {INDEX_HASH} 1024 {INDEX_PATH}",
            "SHA512:",
            " " + "3" * 128 + " 1024 main/binary-amd64/Packages.xz",
        ),
    )

    metadata = module.parse_release_payload(payload, contract=_contract(module), now=NOW)

    assert metadata.sha256 == (
        module.DigestRecord(path=INDEX_PATH, size=1024, sha256=INDEX_HASH),
    )


@pytest.mark.parametrize(
    "contract_change,payload_change",
    [
        ({"suite": "resolute"}, {}),
        ({"codename": "other"}, {}),
        ({"signed_date": datetime(2026, 10, 4, 13, 26, 38, tzinfo=UTC)}, {}),
        ({}, {"architectures": "arm64"}),
        ({}, {"components": "universe"}),
    ],
)
def test_rejects_wrong_frozen_suite_codename_date_architecture_or_component(
    contract_change: dict[str, object], payload_change: dict[str, object]
) -> None:
    module = _load_module()

    with pytest.raises(module.NativeInputError, match="^native input validation failed$"):
        module.parse_release_payload(
            _payload(**payload_change),
            contract=_contract(module, **contract_change),
            now=NOW,
        )


def test_rejects_future_date_and_unexpected_or_expired_valid_until() -> None:
    module = _load_module()
    future = "Wed, 07 Oct 2026 13:26:37 +0000"
    with pytest.raises(module.NativeInputError):
        module.parse_release_payload(
            _payload(date=future),
            contract=_contract(
                module,
                signed_date=datetime(2026, 10, 7, 13, 26, 37, tzinfo=UTC),
            ),
            now=NOW,
        )

    valid_until = "Mon, 05 Oct 2026 13:26:37 +0000"
    with pytest.raises(module.NativeInputError):
        module.parse_release_payload(
            _payload(valid_until=valid_until), contract=_contract(module), now=NOW
        )

    with pytest.raises(module.NativeInputError):
        module.parse_release_payload(
            _payload(valid_until=valid_until),
            contract=_contract(
                module,
                valid_until=datetime(2026, 10, 5, 13, 26, 37, tzinfo=UTC),
            ),
            now=NOW,
        )


def test_accepts_exact_nonexpired_valid_until_when_contract_requires_it() -> None:
    module = _load_module()
    valid_until = datetime(2026, 10, 8, 13, 26, 37, tzinfo=UTC)

    metadata = module.parse_release_payload(
        _payload(valid_until="Thu, 08 Oct 2026 13:26:37 +0000"),
        contract=_contract(module, valid_until=valid_until),
        now=NOW,
    )

    assert metadata.valid_until == valid_until


@pytest.mark.parametrize(
    "raw",
    [
        b"not-a-release\n",
        _payload(extra=("Suite: duplicate",)),
        _payload(sha256_lines=()),
        _payload(sha256_lines=(f" {'g' * 64} 1024 {INDEX_PATH}",)),
        _payload(sha256_lines=(f" {INDEX_HASH} nope {INDEX_PATH}",)),
        _payload(sha256_lines=(f" {INDEX_HASH} 1024 /absolute",)),
        _payload(sha256_lines=(f" {INDEX_HASH} 1024 ../escape",)),
        _payload(
            sha256_lines=(
                f" {INDEX_HASH} 1024 {INDEX_PATH}",
                f" {'b' * 64} 1024 {INDEX_PATH}",
            )
        ),
    ],
)
def test_rejects_malformed_duplicate_or_conflicting_release_records(raw: bytes) -> None:
    module = _load_module()

    with pytest.raises(module.NativeInputError, match="^native input validation failed$"):
        module.parse_release_payload(raw, contract=_contract(module), now=NOW)


def test_rejects_oversize_payload_or_line_before_unbounded_use() -> None:
    module = _load_module()

    oversize = b"X" * (module.MAX_INRELEASE_BYTES + 1)
    with pytest.raises(module.NativeInputError):
        module.parse_release_payload(oversize, contract=_contract(module), now=NOW)

    long_line = _payload(extra=("Description: " + "x" * module.MAX_RELEASE_LINE_BYTES,))
    assert len(long_line) < module.MAX_INRELEASE_BYTES
    with pytest.raises(module.NativeInputError):
        module.parse_release_payload(long_line, contract=_contract(module), now=NOW)


def test_rejects_pgp_envelope_in_parser_that_requires_verified_payload() -> None:
    module = _load_module()
    wrapped = b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + _payload()

    with pytest.raises(module.NativeInputError):
        module.parse_release_payload(wrapped, contract=_contract(module), now=NOW)


def test_index_lookup_requires_exact_path_digest_and_compressed_size_bound() -> None:
    module = _load_module()
    metadata = module.parse_release_payload(
        _payload(), contract=_contract(module), now=NOW
    )

    assert module.require_index_record(metadata, INDEX_PATH) == module.DigestRecord(
        path=INDEX_PATH, size=1024, sha256=INDEX_HASH
    )
    with pytest.raises(module.NativeInputError):
        module.require_index_record(metadata, "main/binary-amd64/Packages.zst")

    too_large = module.parse_release_payload(
        _payload(
            sha256_lines=(
                f" {INDEX_HASH} {module.MAX_COMPRESSED_INDEX_BYTES + 1} {INDEX_PATH}",
            )
        ),
        contract=_contract(module),
        now=NOW,
    )
    with pytest.raises(module.NativeInputError):
        module.require_index_record(too_large, INDEX_PATH)


def test_parser_remains_dormant_and_unreferenced_by_live_e2e() -> None:
    for relative in (
        ".github/workflows/live-local-e2e.yml",
        "scripts/run-live-local-e2e-orchestrator.py",
        "ops/live-e2e/ssh-over-mcp-live-e2e-gate",
    ):
        assert "native_inputs.py" not in (ROOT / relative).read_text(encoding="utf-8")
