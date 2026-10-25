"""Read-only C5 Ubuntu archive signer/index/package-metadata preflight.

Consumes only caller-supplied signed text and index bytes. No network,
package download, apt/dpkg, guest, key generation, or image execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
POCKETS = frozenset(("resolute", "resolute-updates", "resolute-security"))
PACKAGES = frozenset(
    (
        "openssh-server",
        "openssh-client",
        "sudo",
        "python3",
        "python3-minimal",
        "ca-certificates",
        "libc6",
        "libssl3t64",
        "libpam0g",
        "openssl",
    )
)
_INRELEASE_MAX = 256_000
_PACKAGES_XZ_MAX = 4_000_000
_PACKAGES_PLAIN_MAX = 25_000_000
_KEYRING_MAX = 128_000
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_VERSION = re.compile(r"(?:[0-9]+:)?[0-9A-Za-z.+~:-]{1,120}\Z", re.ASCII)
_PATH = re.compile(r"pool/main/[A-Za-z0-9_.+~/%-]{1,295}\Z", re.ASCII)
_STATUS = re.compile(r"^\[GNUPG:\] VALIDSIG ([A-F0-9]{40})(?:\s|$)", re.MULTILINE)


class Refused(ValueError):
    """A narrow offline verification precondition failed."""


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read one regular file once, refusing leaf symlinks and special files."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise Refused("UNSUPPORTED_OS")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Refused("NOT_REGULAR")
        if not 0 < before.st_size <= limit:
            raise Refused("BOUNDED_INPUT_REQUIRED")
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        attrs = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(
            getattr(before, name) != getattr(after, name) for name in attrs
        ):
            raise Refused("INPUT_CHANGED")
        return raw
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    finally:
        os.close(fd)


def _fingerprint_verified(status: str) -> str:
    matches = _STATUS.findall(status)
    if matches != [FINGERPRINT]:
        raise Refused("UNTRUSTED_SIGNING_KEY")
    return FINGERPRINT


def _verify_gpgv(inrelease: bytes, keyring: bytes) -> str:
    """Verify captured bytes using a system-location verifier, never PATH."""
    binary = None
    for location in ("/usr/bin/gpgv", "/usr/local/bin/gpgv", "/opt/homebrew/bin/gpgv"):
        try:
            mode = Path(location).resolve(strict=True).stat().st_mode
        except (OSError, RuntimeError):
            continue
        if stat.S_ISREG(mode) and not mode & 0o022 and os.access(location, os.X_OK):
            binary = location
            break
    if binary is None:
        raise Refused("GPGV_UNAVAILABLE")
    try:
        with tempfile.TemporaryDirectory(prefix="som-c5-verify-") as directory:
            area = Path(directory)
            text_path, key_path = area / "InRelease", area / "ubuntu-archive-keyring.gpg"
            text_path.write_bytes(inrelease)
            key_path.write_bytes(keyring)
            result = subprocess.run(
                [binary, "--status-fd", "1", "--keyring", str(key_path), str(text_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
                env={"HOME": directory, "GNUPGHOME": directory, "LC_ALL": "C"},
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("SIGNATURE_VERIFICATION_UNAVAILABLE") from exc
    if result.returncode != 0:
        raise Refused("BAD_RELEASE_SIGNATURE")
    return _fingerprint_verified(result.stdout)


def _release_package_ref(inrelease: bytes, pocket: str) -> tuple[str, int]:
    """Parse a signed Release packet; this function alone does NOT verify PGP."""
    if pocket not in POCKETS:
        raise Refused("UNAPPROVED_POCKET")
    if not 0 < len(inrelease) <= _INRELEASE_MAX:
        raise Refused("BOUNDED_INPUT_REQUIRED")
    try:
        text = inrelease.decode("utf-8")
    except UnicodeError as exc:
        raise Refused("INVALID_RELEASE") from exc
    if (
        not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n")
        or text.count("-----BEGIN PGP SIGNATURE-----") != 1
    ):
        raise Refused("MISSING_RELEASE_SIGNATURE")
    signed = text.split("-----BEGIN PGP SIGNATURE-----", 1)[0]
    signed = signed.split("\n\n", 1)
    if len(signed) != 2:
        raise Refused("INVALID_RELEASE")
    payload = signed[1]
    metadata: dict[str, str] = {}
    for line in payload.splitlines():
        if not line or line[0] in (" ", "-"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k in ("Origin", "Label", "Suite", "Codename", "Architectures", "Components"):
            if k in metadata:
                raise Refused("DUPLICATE_RELEASE_FIELD")
            metadata[k] = v.strip()
    if (
        metadata.get("Origin") != "Ubuntu"
        or metadata.get("Label") != "Ubuntu"
        or metadata.get("Suite") != pocket
        or metadata.get("Codename") != "resolute"
        or "amd64" not in metadata.get("Architectures", "").split()
        or "main" not in metadata.get("Components", "").split()
    ):
        raise Refused("WRONG_UBUNTU_RELEASE")
    if payload.count("\nSHA256:\n") != 1:
        raise Refused("NO_UNIQUE_SHA256_TABLE")
    section = payload.split("\nSHA256:\n", 1)[1]
    target = "main/binary-amd64/Packages.xz"
    rows: list[tuple[str, int]] = []
    for line in section.splitlines():
        if not line.startswith(" "):
            break
        fields = line.split()
        if len(fields) != 3:
            raise Refused("MALFORMED_RELEASE_HASH")
        sha, length, filename = fields
        if filename == target:
            if _HEX.fullmatch(sha) is None or not length.isascii() or not length.isdigit():
                raise Refused("BAD_RELEASE_HASH")
            value = int(length)
            if not 0 < value <= _PACKAGES_XZ_MAX:
                raise Refused("INVALID_PACKAGES_SIZE")
            rows.append((sha, value))
    if len(rows) != 1:
        raise Refused("UNIQUE_PACKAGES_INDEX_REQUIRED")
    return rows[0]


def _selected_packages(packages_xz: bytes) -> dict[str, dict[str, object]]:
    """Select a bounded subset of metadata; never resolve dependency closure."""
    if not 0 < len(packages_xz) <= _PACKAGES_XZ_MAX:
        raise Refused("BOUNDED_INPUT_REQUIRED")
    try:
        decoder = lzma.LZMADecompressor()
        plain = decoder.decompress(packages_xz, max_length=_PACKAGES_PLAIN_MAX + 1)
        if len(plain) > _PACKAGES_PLAIN_MAX or not decoder.eof or decoder.unused_data:
            raise Refused("PACKAGES_DECOMPRESS_BOUNDS")
        text = plain.decode("utf-8")
    except Refused:
        raise
    except (lzma.LZMAError, EOFError, UnicodeError, ValueError) as exc:
        raise Refused("INVALID_PACKAGES_COMPRESSION") from exc
    chosen: dict[str, dict[str, object]] = {}
    for stanza in text.split("\n\n"):
        if len(stanza) > 30_000:
            raise Refused("UNBOUNDED_STANZA")
        rows: dict[str, str] = {}
        for line in stanza.splitlines():
            if not line or line.startswith(" "):
                continue
            if ": " not in line:
                raise Refused("INVALID_PACKAGE_FIELD")
            key, value = line.split(": ", 1)
            if key in rows:
                raise Refused("DUPLICATE_PACKAGE_FIELD")
            rows[key] = value
        package = rows.get("Package")
        if package not in PACKAGES:
            continue
        if package in chosen:
            raise Refused("DUPLICATE_SELECTED_PACKAGE")
        version = rows.get("Version", "")
        arch = rows.get("Architecture", "")
        path = rows.get("Filename", "")
        digest = rows.get("SHA256", "")
        length = rows.get("Size", "")
        if (
            _VERSION.fullmatch(version) is None
            or arch not in ("amd64", "all")
            or _PATH.fullmatch(path) is None
            or ".." in path.split("/")
            or "." in path.split("/")
            or _HEX.fullmatch(digest) is None
            or not length.isascii()
            or not length.isdigit()
            or not 0 < int(length) <= 1024 * 1024 * 1024
        ):
            raise Refused("INVALID_SELECTED_PACKAGE")
        chosen[package] = {
            "version": version,
            "architecture": arch,
            "filename": path,
            "deb_sha256": digest,
            "deb_size": int(length),
        }
    if not chosen:
        raise Refused("NO_RELEVANT_PACKAGES")
    return dict(sorted(chosen.items()))


def check_metadata(
    inrelease: bytes,
    packages_xz: bytes,
    keyring: bytes,
    pocket: str,
) -> dict[str, object]:
    """One candidate signed-pocket receipt; no local/remote installation rights."""
    if pocket not in POCKETS:
        raise Refused("UNAPPROVED_POCKET")
    fingerprint = _verify_gpgv(inrelease, keyring)
    sha, size = _release_package_ref(inrelease, pocket)
    if hashlib.sha256(packages_xz).hexdigest() != sha or len(packages_xz) != size:
        raise Refused("SIGNED_INDEX_HASH_MISMATCH")
    packages = _selected_packages(packages_xz)
    return {
        "schema": "som-ubuntu-2604-offline-index-preview-v1",
        "pocket": pocket,
        "platform": "linux/amd64",
        "trusted_key_fingerprint": fingerprint,
        "inrelease_sha256": hashlib.sha256(inrelease).hexdigest(),
        "packages_xz_sha256": sha,
        "packages_xz_size": size,
        "signed_release_verified": True,
        "index_hash_verified": True,
        "packages": packages,
        "package_archive_bytes_verified": False,
        "dependency_closure_verified": False,
        "image_build_authorized": False,
        "guest_execution_authorized": False,
        "deployment_ready": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OFFLINE signed Ubuntu index preview")
    parser.add_argument("--pocket", choices=sorted(POCKETS), required=True)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-xz", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = check_metadata(
            _read_bounded(args.inrelease, _INRELEASE_MAX),
            _read_bounded(args.packages_xz, _PACKAGES_XZ_MAX),
            _read_bounded(args.keyring, _KEYRING_MAX),
            args.pocket,
        )
    except Refused as exc:
        print(f"REFUSED:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
