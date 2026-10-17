"""B0a synthetic developer inspection; no authenticated Sigstore authority.

The offline "inspect-synthetic" operation checks only pinned candidate file
bytes, a Linux sealed-memory digest and a syntactic bundle digest match.
It NEVER attests a signature, signer, root, log, timestamp, or real package.
The original "verify-synthetic" command still fails closed pending T5B.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from gate_b0_evidence import format_refusal

_HELP = (
    "Usage: gate_b0_source_verification.py "
    "{verify-synthetic|inspect-synthetic} --fixture signed-test-key-1 --format json\n"
    "Inspection is untrusted and non-authorizing; real T5 policy is not approved.\n"
)
_ARTIFACT_SHA256 = "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
_BUNDLE_SHA256 = "3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd"
_FIXTURE_FILES = (
    ("sigstore-conformance-a.txt", 109, _ARTIFACT_SHA256),
    ("sigstore-conformance-rekor2-bundle.sigstore.json", 10123, _BUNDLE_SHA256),
)


class CandidateInspectionRefused(ValueError):
    """Candidate bytes or sealed/bundle consistency did not match."""


def _read_fixed_candidate(name: str, size: int, expected_sha256: str) -> bytes:
    """Read one code-selected candidate with a bounded, no-follow FD.

    This is a pin against accidental/replaced *test data*, not an independent
    trust source. The repository and parent path remain untrusted.
    """
    path = (
        Path(__file__).resolve().parents[2]
        / "tests" / "ops" / "fixtures" / "b0a_synthetic" / name
    )
    # O_NONBLOCK prevents a substituted FIFO from waiting forever for a writer.
    # fstat rejects non-regular descriptors before any read (including devices).
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        raise CandidateInspectionRefused("CANDIDATE_BYTES_CHANGED") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            raise CandidateInspectionRefused("CANDIDATE_BYTES_CHANGED")
        data = os.read(fd, size + 1)
        after = os.fstat(fd)
        if (
            len(data) != size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or hashlib.sha256(data).hexdigest() != expected_sha256
        ):
            raise CandidateInspectionRefused("CANDIDATE_BYTES_CHANGED")
        return data
    except OSError:
        raise CandidateInspectionRefused("CANDIDATE_BYTES_CHANGED") from None
    finally:
        os.close(fd)


def _inspect_candidate(payload: bytes, bundle: bytes) -> bytes:
    """Developer-only inspection: do not return any source-verification status."""
    if (
        type(payload) is not bytes or len(payload) != 109
        or hashlib.sha256(payload).hexdigest() != _ARTIFACT_SHA256
        or type(bundle) is not bytes or len(bundle) != 10123
        or hashlib.sha256(bundle).hexdigest() != _BUNDLE_SHA256
    ):
        raise CandidateInspectionRefused("CANDIDATE_BYTES_CHANGED")

    # Refuse cleanly on macOS and platforms lacking Linux anonymous sealing.
    # Do not import Linux-only fcntl seal constants before this guard.
    if (
        sys.platform != "linux"
        or not hasattr(os, "memfd_create")
        or not hasattr(os, "MFD_ALLOW_SEALING")
    ):
        raise CandidateInspectionRefused("SEALED_SNAPSHOT_REFUSED")

    # Lazy Linux-only imports keep the original refusal command portable.
    from gate_b0_immutable_bytes import (
        B0aInputRefused,
        authenticated_measurement_for_handoff,
        close_measurement,
        fixture_from_trusted_bytes,
        ingest_fixed_fixture,
    )
    from gate_b0_sigstore_adapter import check_bundle_digest_consistency

    measurement = None
    try:
        # "Trusted" here means exclusively owned immutable *in-process bytes*,
        # not authenticated external file origin, publisher or signer.
        fixture, witness = fixture_from_trusted_bytes(payload, fixture_id="signed-test-key-1")
        measurement = ingest_fixed_fixture(fixture, witness)
        check_bundle_digest_consistency(measurement, bundle)
        _, measured_sha256, measured_length = authenticated_measurement_for_handoff(measurement)
        record = {
            "schema": "som.b0a.inspect.v1",
            "status": "B0A_INSPECTED_UNTRUSTED",
            "evidence_class": "NON_AUTHORIZING_SYNTHETIC",
            "fixture": "signed-test-key-1",
            "measured_sha256": measured_sha256,
            "measured_length": measured_length,
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
            "signature_verified": False,
            "source_approved": False,
        }
        output = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        assert len(output) < 16384
        return output
    except (B0aInputRefused, OSError):
        raise CandidateInspectionRefused("CANDIDATE_STRUCTURE_REFUSED") from None
    finally:
        if measurement is not None:
            try:
                close_measurement(measurement)
            except (B0aInputRefused, OSError):
                # A swapped/stale descriptor may never yield inspection success.
                raise CandidateInspectionRefused("CANDIDATE_STRUCTURE_REFUSED") from None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if type(args) is not list or any(type(x) is not str for x in args):
        sys.stdout.buffer.write(format_refusal("CLI_ARGS_REJECTED"))
        return 2
    if args == ["--help"]:
        sys.stdout.write(_HELP)
        return 0
    if (
        len(args) != 5
        or args[0] not in ("verify-synthetic", "inspect-synthetic")
        or args[1] != "--fixture"
        or args[3:] != ["--format", "json"]
    ):
        sys.stdout.buffer.write(format_refusal("CLI_ARGS_REJECTED"))
        return 2
    if args[2] != "signed-test-key-1":
        sys.stdout.buffer.write(format_refusal("FIXTURE_NOT_APPROVED"))
        return 2
    if args[0] == "verify-synthetic":
        sys.stdout.buffer.write(format_refusal("T5_POLICY_UNAPPROVED"))
        return 2

    try:
        payload, bundle = (
            _read_fixed_candidate(name, size, digest)
            for name, size, digest in _FIXTURE_FILES
        )
        sys.stdout.buffer.write(_inspect_candidate(payload, bundle))
        return 0
    except CandidateInspectionRefused as exc:
        # No untrusted detail, path, signer or root enters the bounded response.
        reason = str(exc)
        if reason not in (
            "CANDIDATE_BYTES_CHANGED", "CANDIDATE_STRUCTURE_REFUSED",
            "SEALED_SNAPSHOT_REFUSED",
        ):
            reason = "CANDIDATE_STRUCTURE_REFUSED"
        sys.stdout.buffer.write(format_refusal(reason))
        return 2
    except (ImportError, OSError):
        sys.stdout.buffer.write(format_refusal("SEALED_SNAPSHOT_REFUSED"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
