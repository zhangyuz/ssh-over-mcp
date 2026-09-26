from __future__ import annotations

import base64
import binascii
import re

from .errors import SSHHostKeyVerificationError

_KEY_TYPE_RE = re.compile(r"^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$")


def build_pinned_known_hosts(host_alias: str, host_key: str) -> bytes:
    """Build a one-host known_hosts payload using the server-owned alias."""

    if any(ch in host_alias for ch in "*?!,[]\\\r\n"):
        raise SSHHostKeyVerificationError(
            "host alias contains known_hosts pattern metacharacters"
        )

    if "\n" in host_key or "\r" in host_key:
        raise SSHHostKeyVerificationError(
            "host key must be a single OpenSSH public-key line"
        )

    parts = host_key.strip().split()
    if len(parts) < 2:
        raise SSHHostKeyVerificationError(
            "host key must contain key type and base64 data"
        )

    key_type, key_data = parts[0], parts[1]
    if not _KEY_TYPE_RE.fullmatch(key_type):
        raise SSHHostKeyVerificationError(
            "unsupported or malformed host key type"
        )

    try:
        base64.b64decode(key_data.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise SSHHostKeyVerificationError("malformed base64 host key") from exc

    return f"{host_alias} {key_type} {key_data}\n".encode("ascii")
