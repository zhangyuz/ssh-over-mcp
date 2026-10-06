from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

_PUBLIC_ERROR = "native input validation failed"
MAX_INRELEASE_BYTES = 512 * 1024
MAX_RELEASE_LINE_BYTES = 64 * 1024
MAX_COMPRESSED_INDEX_BYTES = 32 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_SCALARS = ("Origin", "Label", "Suite", "Codename", "Date", "Architectures", "Components")


class NativeInputError(RuntimeError):
    """Raised when frozen native-source metadata violates its reviewed contract."""


@dataclass(frozen=True, slots=True)
class ReleaseContract:
    suite: str
    codename: str
    signed_date: datetime
    valid_until: datetime | None
    architecture: str
    component: str


@dataclass(frozen=True, slots=True)
class DigestRecord:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedMetadata:
    suite: str
    codename: str
    signed_date: datetime
    valid_until: datetime | None
    architectures: tuple[str, ...]
    components: tuple[str, ...]
    sha256: tuple[DigestRecord, ...]


def _fail() -> NativeInputError:
    return NativeInputError(_PUBLIC_ERROR)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _fail()
    return value.astimezone(UTC)


def _parse_date(raw: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        raise _fail() from None
    if parsed is None or parsed.tzinfo is None:
        raise _fail()
    return parsed.astimezone(UTC)


def _validate_relative_path(path: str) -> None:
    if not path or path.startswith("/") or "\x00" in path:
        raise _fail()
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _fail()


def _parse_sha256(lines: list[str]) -> tuple[DigestRecord, ...]:
    if not lines:
        raise _fail()
    records: list[DigestRecord] = []
    seen: set[str] = set()
    for line in lines:
        parts = line.split()
        if len(parts) != 3:
            raise _fail()
        digest, size_raw, path = parts
        if _SHA256_RE.fullmatch(digest) is None:
            raise _fail()
        try:
            size = int(size_raw, 10)
        except ValueError:
            raise _fail() from None
        if size < 0 or str(size) != size_raw:
            raise _fail()
        _validate_relative_path(path)
        if path in seen:
            raise _fail()
        seen.add(path)
        records.append(DigestRecord(path=path, size=size, sha256=digest))
    return tuple(records)


def parse_release_payload(
    raw: bytes, *, contract: ReleaseContract, now: datetime
) -> VerifiedMetadata:
    """Parse already-signature-verified frozen Ubuntu Release payload bytes.

    This parser intentionally performs no OpenPGP verification. A later N1 slice
    must authenticate the exact InRelease bytes and pass only verified payload
    bytes here.
    """

    try:
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INRELEASE_BYTES:
            raise _fail()
        raw_lines = raw.splitlines()
        if any(len(line) > MAX_RELEASE_LINE_BYTES for line in raw_lines):
            raise _fail()
        text_lines = [line.decode("utf-8", errors="strict") for line in raw_lines]
        if any("\x00" in line for line in text_lines):
            raise _fail()
        if text_lines and text_lines[0].startswith("-----BEGIN PGP"):
            raise _fail()

        fields: dict[str, str] = {}
        sha_lines: list[str] = []
        in_sha256 = False
        for line in text_lines:
            if in_sha256:
                if line.startswith((" ", "\t")):
                    sha_lines.append(line)
                    continue
                in_sha256 = False
            if not line:
                raise _fail()
            if ":" not in line:
                raise _fail()
            name, value = line.split(":", 1)
            if not name or value.startswith(("\n", "\r")):
                raise _fail()
            value = value.strip()
            if name == "SHA256":
                if value or sha_lines:
                    raise _fail()
                in_sha256 = True
                continue
            if name in fields:
                raise _fail()
            fields[name] = value

        if in_sha256 and not sha_lines:
            raise _fail()
        if any(name not in fields for name in _REQUIRED_SCALARS):
            raise _fail()
        if fields["Origin"] != "Ubuntu" or fields["Label"] != "Ubuntu":
            raise _fail()

        signed_date = _parse_date(fields["Date"])
        contract_signed_date = _utc(contract.signed_date)
        current = _utc(now)
        if signed_date != contract_signed_date or signed_date > current:
            raise _fail()
        if fields["Suite"] != contract.suite or fields["Codename"] != contract.codename:
            raise _fail()

        architectures = tuple(fields["Architectures"].split())
        components = tuple(fields["Components"].split())
        if not architectures or contract.architecture not in architectures:
            raise _fail()
        if not components or contract.component not in components:
            raise _fail()

        raw_valid_until = fields.get("Valid-Until")
        if contract.valid_until is None:
            if raw_valid_until is not None:
                raise _fail()
            valid_until = None
        else:
            expected_valid_until = _utc(contract.valid_until)
            if raw_valid_until is None:
                raise _fail()
            valid_until = _parse_date(raw_valid_until)
            if valid_until != expected_valid_until or valid_until <= current:
                raise _fail()

        records = _parse_sha256(sha_lines)
        return VerifiedMetadata(
            suite=fields["Suite"],
            codename=fields["Codename"],
            signed_date=signed_date,
            valid_until=valid_until,
            architectures=architectures,
            components=components,
            sha256=records,
        )
    except NativeInputError:
        raise
    except (UnicodeError, OverflowError, TypeError, ValueError):
        raise _fail() from None


def require_index_record(metadata: VerifiedMetadata, path: str) -> DigestRecord:
    """Return one exact signed index record within the reviewed compressed bound."""

    try:
        _validate_relative_path(path)
        matches = [record for record in metadata.sha256 if record.path == path]
        if len(matches) != 1:
            raise _fail()
        record = matches[0]
        if record.size > MAX_COMPRESSED_INDEX_BYTES:
            raise _fail()
        return record
    except NativeInputError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise _fail() from None
