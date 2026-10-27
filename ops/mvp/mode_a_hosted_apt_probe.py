"""Read-only Ubuntu 26.04 hosted APT preflight evidence; never authorizes media."""

from __future__ import annotations

import os
import platform
from pathlib import Path

_RELEASE = Path("/etc/os-release")
_SOURCE = Path("/etc/apt/sources.list.d/ubuntu.sources")
_KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
_SIGNER = "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"


def _bounded_lines(path: Path) -> list[str]:
    if path.is_symlink() or not path.is_file():
        return []
    if path.stat().st_size > 65536:
        return []
    return path.read_text(encoding="utf-8").splitlines()


def checks(
    release_lines: list[str],
    source_lines: list[str],
    keyring_available: bool,
    *,
    machine: str,
    uid: int,
) -> dict[str, bool]:
    release = {}
    for line in release_lines:
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    return {
        "UBUNTU_2604": release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "26.04",
        "X86_64": machine == "x86_64",
        "NON_ROOT": uid != 0,
        "ARCHIVE_KEYRING": keyring_available,
        "UBUNTU_REPOSITORY": any(
            line.startswith("URIs: ") and "ubuntu.com/ubuntu" in line for line in source_lines
        ),
        "KEYRING_SIGNER": _SIGNER in source_lines,
    }


def main() -> None:
    # Print only fixed keys and boolean values. Never print repository content.
    status = checks(
        _bounded_lines(_RELEASE),
        _bounded_lines(_SOURCE),
        _KEYRING.is_file() and not _KEYRING.is_symlink() and os.access(_KEYRING, os.R_OK),
        machine=platform.machine(),
        uid=os.getuid(),
    )
    for key, matched in status.items():
        print(f"ENGINE_APT_PREFLIGHT_{key}={'true' if matched else 'false'}")
    print("ENGINE_APT_PREFLIGHT_MATCHES_OLD_GUARD=" + str(all(status.values())).lower())
    print("OFFLINE_ENGINE_MEDIA_BUILD_AUTHORIZED=false")


if __name__ == "__main__":
    main()
