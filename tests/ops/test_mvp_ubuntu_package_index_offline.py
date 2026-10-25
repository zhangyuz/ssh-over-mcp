"""C5 signed Ubuntu Release -> Packages digest candidate; no package download."""

from __future__ import annotations

import hashlib
import lzma
from pathlib import Path
from unittest.mock import patch

import pytest

from ops.mvp.ubuntu_package_index_offline import (
    Refused,
    _fingerprint_verified,
    _read_bounded,
    _release_package_ref,
    _selected_packages,
    _verify_gpgv,
    check_metadata,
    main,
)

FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"


def fixture():
    content = (
        "Package: openssh-server\nVersion: 1:10.2p1-2ubuntu3.8\n"
        "Architecture: amd64\nFilename: pool/main/o/openssh/openssh-server_10.deb\n"
        "SHA256: " + "a" * 64 + "\nSize: 1024\n"
        "Depends: openssh-client, libc6\n\n"
        "Package: ca-certificates\nVersion: 20260816ubuntu0.26.04.1\n"
        "Architecture: all\nFilename: pool/main/c/ca-certificates/ca.deb\n"
        "SHA256: " + "b" * 64 + "\nSize: 640\n"
    ).encode()
    compressed = lzma.compress(content)
    sha = hashlib.sha256(compressed).hexdigest()
    release = (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        "Origin: Ubuntu\nLabel: Ubuntu\nSuite: resolute-updates\n"
        "Codename: resolute\nArchitectures: amd64 arm64\nComponents: main universe\n"
        "SHA256:\n " + sha + " " + str(len(compressed)) + " main/binary-amd64/Packages.xz\n"
        "-----BEGIN PGP SIGNATURE-----\n"
    ).encode()
    return release, compressed


def test_signed_release_hash_chain_exposes_package_proposals_not_permissions():
    release, packages = fixture()
    expected = _release_package_ref(release, "resolute-updates")
    assert expected == (hashlib.sha256(packages).hexdigest(), len(packages))
    chosen = _selected_packages(packages)
    assert chosen["openssh-server"]["version"] == "1:10.2p1-2ubuntu3.8"
    assert chosen["ca-certificates"]["architecture"] == "all"
    with patch("ops.mvp.ubuntu_package_index_offline._verify_gpgv", return_value=FINGERPRINT):
        result = check_metadata(release, packages, b"dummy-key", "resolute-updates")
    assert result["signed_release_verified"] is True
    assert result["trusted_key_fingerprint"] == FINGERPRINT
    assert result["index_hash_verified"] is True
    assert result["package_archive_bytes_verified"] is False
    assert result["dependency_closure_verified"] is False
    assert result["image_build_authorized"] is False
    assert result["packages"]["openssh-server"]["deb_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "case",
    [
        "hash",
        "length",
        "release",
        "no_header",
        "duplicated",
        "duplicate_sha",
        "missing_index",
        "invalid_arch",
        "bad_origin",
        "missing_signature",
    ],
)
def test_release_refuses_inconsistent_metadata(case):
    release, packages = fixture()
    raw = release.decode()
    digest = hashlib.sha256(packages).hexdigest()
    if case == "hash":
        raw = raw.replace(digest, "0" * 64)
    elif case == "length":
        raw = raw.replace(str(len(packages)) + " main/", "0 main/")
    elif case == "release":
        raw = raw.replace("Suite: resolute-updates", "Suite: noble")
    elif case == "no_header":
        raw = raw.replace("SHA256:\n", "SHA1:\n")
    elif case == "duplicated":
        raw = raw.replace(
            "Suite: resolute-updates", "Suite: resolute-updates\nSuite: resolute-updates"
        )
    elif case == "duplicate_sha":
        raw = raw.replace(
            "SHA256:\n",
            "SHA256:\n " + digest + " " + str(len(packages)) + " main/binary-amd64/Packages.xz\n",
        )
    elif case == "missing_index":
        raw = raw.replace("main/binary-amd64/Packages.xz", "universe/binary-amd64/Packages.xz")
    elif case == "invalid_arch":
        raw = raw.replace("Architectures: amd64 arm64", "Architectures: arm64")
    elif case == "bad_origin":
        raw = raw.replace("Origin: Ubuntu", "Origin: Attack")
    elif case == "missing_signature":
        raw = raw.replace("-----BEGIN PGP SIGNATURE-----", "")
    with pytest.raises(Refused):
        if case in ("hash", "length"):
            with patch(
                "ops.mvp.ubuntu_package_index_offline._verify_gpgv", return_value=FINGERPRINT
            ):
                check_metadata(raw.encode(), packages, b"dummy", "resolute-updates")
        else:
            _release_package_ref(raw.encode(), "resolute-updates")


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_digest",
        "path_traversal",
        "missing_version",
        "duplicate_pkg",
        "broken_size",
        "bad_arch",
        "duplicate_fields",
        "no_digest",
    ],
)
def test_packages_reject_untrusted_stanzas(mutation):
    _, body = fixture()
    plain = lzma.decompress(body).decode()
    if mutation == "wrong_digest":
        plain = plain.replace("a" * 64, "a" * 63)
    elif mutation == "path_traversal":
        plain = plain.replace("pool/main/o/openssh/", "pool/main/../")
    elif mutation == "missing_version":
        plain = plain.replace("Version: 1:10.2p1-2ubuntu3.8\n", "")
    elif mutation == "duplicate_pkg":
        plain += "\n\n" + plain.split("\n\n")[0]
    elif mutation == "broken_size":
        plain = plain.replace("Size: 1024", "Size: abc")
    elif mutation == "bad_arch":
        plain = plain.replace("Architecture: amd64", "Architecture: arm64")
    elif mutation == "duplicate_fields":
        plain = plain.replace("Size: 1024", "Size: 1024\nSize: 1024")
    elif mutation == "no_digest":
        plain = plain.replace("SHA256: " + "a" * 64 + "\n", "")
    with pytest.raises(Refused):
        _selected_packages(lzma.compress(plain.encode()))


def test_gpgv_status_must_pin_the_documented_ubuntu_archive_fingerprint():
    assert _fingerprint_verified("[GNUPG:] VALIDSIG " + FINGERPRINT + " rest\n") == FINGERPRINT
    for status in ("", "[GNUPG:] GOODSIG fake", "[GNUPG:] VALIDSIG " + "0" * 40 + " rest"):
        with pytest.raises(Refused):
            _fingerprint_verified(status)


def test_input_refuses_symlink_directory_and_excess(tmp_path):
    file = tmp_path / "InRelease"
    file.write_bytes(b"VALID")
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(Refused):
        _read_bounded(link, 2000)
    with pytest.raises(Refused):
        _read_bounded(tmp_path, 2000)
    file.write_bytes(b"a" * 2001)
    with pytest.raises(Refused):
        _read_bounded(file, 2000)


def test_cli_refuses_invalid_gpg_inputs_and_never_leaks_paths(tmp_path, capsys):
    release, packages = fixture()
    paths = [tmp_path / "InRelease", tmp_path / "Packages.xz", tmp_path / "keyring"]
    for path, data in zip(paths, (release, packages, b"not-a-real-keyring")):
        path.write_bytes(data)
    args = [
        "--pocket",
        "resolute-updates",
        "--inrelease",
        str(paths[0]),
        "--packages-xz",
        str(paths[1]),
        "--keyring",
        str(paths[2]),
    ]
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("REFUSED:")
    assert str(tmp_path) not in captured.err


def test_no_package_fetch_or_docker_in_read_only_tool():
    source = (
        Path(__file__).resolve().parents[2] / "ops/mvp/ubuntu_package_index_offline.py"
    ).read_text()
    assert "urllib" not in source and "requests" not in source
    assert "apt-get" not in source and "docker" not in source


def test_ambient_path_cannot_inject_fake_gpgv(tmp_path, monkeypatch):
    fake = tmp_path / "gpgv"
    fake.write_text("#!/bin/sh\nprintf '[GNUPG:] VALIDSIG " + FINGERPRINT + " fake\\n'\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(Refused):
        _verify_gpgv(b"not-signed-release", b"untrusted-keyring")


def test_gpgv_non_utf8_release_refuses_before_subprocess(monkeypatch):
    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("invalid UTF-8 must not reach gpgv")

    monkeypatch.setattr("ops.mvp.ubuntu_package_index_offline.subprocess.run", unexpected_run)
    with pytest.raises(Refused, match="INVALID_RELEASE"):
        _verify_gpgv(b"-----BEGIN PGP SIGNED MESSAGE-----\n\xff\n", b"not-secret")


def test_gpgv_undecodable_child_output_refuses_without_traceback(monkeypatch):
    def undecodable_run(*_args, **_kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr("ops.mvp.ubuntu_package_index_offline.subprocess.run", undecodable_run)
    with pytest.raises(Refused, match="SIGNATURE_VERIFICATION_UNAVAILABLE"):
        _verify_gpgv(b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n", b"not-secret")
