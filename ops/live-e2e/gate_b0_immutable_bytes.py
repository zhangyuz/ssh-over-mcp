"""Linux-only, synthetic B0a sealed-byte measurement; no source-trust authority.

The caller must be a trusted fixed-fixture harness with exclusive ownership of
an immutable built-in bytes object. Pathnames, file objects, mutable buffers
and untrusted operating-system descriptors are not accepted. This module
cannot authenticate a caller, Sigstore signer, trust root or target host.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import threading
from dataclasses import dataclass, field

_MAX_BYTES = 4 * 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_AUTH_PROOF = object()
_REQUIRED_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)


class B0aInputRefused(ValueError):
    """Non-authorizing fail-closed signal; never include attacker bytes."""


@dataclass(frozen=True, slots=True)
class FixedFixture:
    payload: bytes
    fixture_id: str
    _source_identity: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedFixtureAuthority:
    _source_identity: object = field(repr=False)
    _proof: object = field(repr=False)
    writer_excluded: bool


@dataclass(frozen=True, slots=True)
class SealedMeasurement:
    fd: int
    sha256: str
    length: int
    witness_ref: str


# Retain the exact issued object until authenticated one-time close.
# Matching public fields do not prove possession of this descriptor.
_LIVE_LOCK = threading.Lock()
_LIVE_MEASUREMENTS: dict[int, tuple[SealedMeasurement, int, int, int, int, str, int, str]] = {}


def fixture_from_trusted_bytes(
    payload: bytes, *, fixture_id: str
) -> tuple[FixedFixture, VerifiedFixtureAuthority]:
    """Trusted-harness-only inlet for immutable, exclusively owned synthetic bytes.

    These objects are NOT cryptographically authenticated sources; a caller
    cannot upgrade an untrusted path or blob to an accepted real package.
    """
    if type(payload) is not bytes or not payload or len(payload) > _MAX_BYTES:
        raise B0aInputRefused("SYNTHETIC_BYTES_INVALID")
    if type(fixture_id) is not str or _ID.fullmatch(fixture_id) is None:
        raise B0aInputRefused("SYNTHETIC_ID_INVALID")
    token = object()
    return (
        FixedFixture(payload, fixture_id, token),
        VerifiedFixtureAuthority(token, _AUTH_PROOF, True),
    )


def ingest_fixed_fixture(
    fixture: FixedFixture, authority: VerifiedFixtureAuthority, *, max_bytes: int = _MAX_BYTES
) -> SealedMeasurement:
    """Seal before hashing and return a live, caller-owned FD. No path reads."""
    if (
        type(fixture) is not FixedFixture
        or type(authority) is not VerifiedFixtureAuthority
        or authority._proof is not _AUTH_PROOF
        or authority.writer_excluded is not True
        or authority._source_identity is not fixture._source_identity
        or type(fixture.payload) is not bytes
        or type(fixture.fixture_id) is not str
        or _ID.fullmatch(fixture.fixture_id) is None
        or type(max_bytes) is not int
        or not (0 < max_bytes <= _MAX_BYTES)
        or not (0 < len(fixture.payload) <= max_bytes)
    ):
        raise B0aInputRefused("SYNTHETIC_SOURCE_NOT_EXCLUSIVE")
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise B0aInputRefused("SEALED_SNAPSHOT_UNAVAILABLE")

    fd = -1
    transferred = False
    try:
        fd = os.memfd_create(
            "som-b0a-synthetic", flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        )
        position = 0
        while position < len(fixture.payload):
            n = os.write(fd, fixture.payload[position:])
            if n <= 0:
                raise B0aInputRefused("SEALED_SNAPSHOT_SHORT_WRITE")
            position += n
        original = os.fstat(fd)
        if not stat.S_ISREG(original.st_mode) or original.st_size != len(fixture.payload):
            raise B0aInputRefused("SEALED_SNAPSHOT_SIZE_MISMATCH")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _REQUIRED_SEALS)
        if (fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _REQUIRED_SEALS) != _REQUIRED_SEALS:
            raise B0aInputRefused("SEALED_SNAPSHOT_UNVERIFIED")
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(fd, min(65536, len(fixture.payload) - count + 1))
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
            if count > len(fixture.payload):
                raise B0aInputRefused("SEALED_SNAPSHOT_SIZE_MISMATCH")
        final = os.fstat(fd)
        if (
            count != len(fixture.payload)
            or final.st_dev != original.st_dev
            or final.st_ino != original.st_ino
            or final.st_size != count
            or (fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _REQUIRED_SEALS) != _REQUIRED_SEALS
        ):
            raise B0aInputRefused("SEALED_SNAPSHOT_DRIFT")
        os.lseek(fd, 0, os.SEEK_SET)
        result = SealedMeasurement(
            fd=fd,
            sha256=digest.hexdigest(),
            length=count,
            witness_ref=f"synthetic-memfd:{final.st_dev}:{final.st_ino}",
        )
        with _LIVE_LOCK:
            _LIVE_MEASUREMENTS[id(result)] = (
                result, fd, final.st_dev, final.st_ino, final.st_size,
                result.sha256, result.length, result.witness_ref
            )
        transferred = True
        return result
    except (OSError, ValueError) as exc:
        if isinstance(exc, B0aInputRefused):
            raise
        raise B0aInputRefused("SEALED_SNAPSHOT_REFUSED") from None
    finally:
        if fd >= 0 and not transferred:
            os.close(fd)



def authenticated_measurement_for_handoff(
    measurement: SealedMeasurement,
) -> tuple[int, str, int]:
    """Return only registered and kernel-checked sealed bytes identity.

    Intended for the future approved T5 adapter; this is not trust-policy
    approval or a proof against hostile concurrent same-process FD changes.
    Never use public measurement.sha256 as an independently trusted hash.
    """
    if type(measurement) is not SealedMeasurement:
        raise B0aInputRefused("SEALED_MEASUREMENT_INVALID")
    with _LIVE_LOCK:
        owned = _LIVE_MEASUREMENTS.get(id(measurement))
        if owned is None or owned[0] is not measurement:
            raise B0aInputRefused("SEALED_MEASUREMENT_NOT_OWNED")
        _, fd, dev, ino, size, digest, length, witness = owned
        if (
            measurement.fd != fd
            or measurement.sha256 != digest
            or measurement.length != length
            or measurement.witness_ref != witness
        ):
            raise B0aInputRefused("SEALED_MEASUREMENT_SUBSTITUTED")
        try:
            actual = os.fstat(fd)
            seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        except OSError:
            raise B0aInputRefused("SEALED_MEASUREMENT_STALE") from None
        if (
            actual.st_dev != dev
            or actual.st_ino != ino
            or actual.st_size != size
            or size != length
            or (seals & _REQUIRED_SEALS) != _REQUIRED_SEALS
        ):
            raise B0aInputRefused("SEALED_MEASUREMENT_SUBSTITUTED")
        return fd, digest, size

def close_measurement(measurement: SealedMeasurement) -> None:
    """Close one still-owned sealed FD, never an arbitrary reused integer.

    Borrowers must not close or replace this FD externally. The registry
    serializes its own closes, not hostile same-process descriptor mutations.
    """
    if type(measurement) is not SealedMeasurement or type(measurement.fd) is not int:
        raise B0aInputRefused("SEALED_MEASUREMENT_INVALID")
    with _LIVE_LOCK:
        owned = _LIVE_MEASUREMENTS.get(id(measurement))
        if owned is None or owned[0] is not measurement or measurement.fd != owned[1]:
            raise B0aInputRefused("SEALED_MEASUREMENT_NOT_OWNED")
        _, fd, original_dev, original_ino, original_size, _, _, _ = owned
        try:
            current = os.fstat(fd)
            seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        except OSError:
            del _LIVE_MEASUREMENTS[id(measurement)]
            raise B0aInputRefused("SEALED_MEASUREMENT_STALE") from None
        if (
            current.st_dev != original_dev
            or current.st_ino != original_ino
            or current.st_size != original_size
            or (seals & _REQUIRED_SEALS) != _REQUIRED_SEALS
        ):
            del _LIVE_MEASUREMENTS[id(measurement)]
            raise B0aInputRefused("SEALED_MEASUREMENT_SUBSTITUTED")
        del _LIVE_MEASUREMENTS[id(measurement)]
        try:
            os.close(fd)
        except OSError:
            raise B0aInputRefused("SEALED_MEASUREMENT_STALE") from None
