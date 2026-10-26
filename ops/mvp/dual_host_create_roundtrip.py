#!/usr/bin/env python3
"""Explicit create-only MCP write/read smoke for two distinct SSH targets."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import posixpath
import re
import stat
import sys
from pathlib import Path

from dual_host_read_smoke import (
    MCPHTTPClient,
    SmokeRefused,
    _read_token,
    validate_endpoint,
    verify_two_nodes,
)

_ALIASES = ("node01", "node02")
_MAX_PROBE = 4096
_MAX_MANIFEST = 16 * 1024
_APPROVAL = re.compile(r"apr_[0-9a-f]{32}\Z", re.ASCII)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SmokeRefused("INVALID_MANIFEST")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict:
    """Load a local owner-private, regular, bounded file without leaf symlinks."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > _MAX_MANIFEST
            ):
                raise SmokeRefused("INVALID_MANIFEST")
            raw = os.read(fd, _MAX_MANIFEST + 1)
        finally:
            os.close(fd)
        if not raw or len(raw) > _MAX_MANIFEST:
            raise SmokeRefused("INVALID_MANIFEST")
        document = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise SmokeRefused("INVALID_MANIFEST") from None
    return document


def _prepared(
    document: dict,
) -> tuple[str, dict[str, bytes], dict[str, str], dict[str, str]]:
    required = {"path", *_ALIASES}
    if type(document) is not dict or set(document) not in (required, required | {"mkdir"}):
        raise SmokeRefused("INVALID_MANIFEST")
    path = document["path"]
    if (
        type(path) is not str
        or not path.startswith("/")
        or path.startswith("//")
        or "\x00" in path
        or path != posixpath.normpath(path)
        or len(path.encode("utf-8")) > 4096
    ):
        raise SmokeRefused("INVALID_MANIFEST")

    payloads = {}
    approvals = {}
    for alias in _ALIASES:
        node = document[alias]
        if type(node) is not dict or set(node) != {"data_base64", "approval_id"}:
            raise SmokeRefused("INVALID_MANIFEST")
        encoded = node["data_base64"]
        approval = node["approval_id"]
        if type(encoded) is not str or type(approval) is not str:
            raise SmokeRefused("INVALID_MANIFEST")
        if _APPROVAL.fullmatch(approval) is None:
            raise SmokeRefused("INVALID_MANIFEST")
        if len(encoded) > 4 * ((_MAX_PROBE + 2) // 3):
            raise SmokeRefused("INVALID_MANIFEST")
        try:
            content = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeError, ValueError, binascii.Error):
            raise SmokeRefused("INVALID_MANIFEST") from None
        if (
            not content
            or len(content) > _MAX_PROBE
            or base64.b64encode(content).decode() != encoded
        ):
            raise SmokeRefused("INVALID_MANIFEST")
        payloads[alias] = content
        approvals[alias] = approval
    if payloads["node01"] == payloads["node02"] or approvals["node01"] == approvals["node02"]:
        raise SmokeRefused("INVALID_MANIFEST")

    mkdir_grants: dict[str, str] = {}
    if "mkdir" in document:
        provided = document["mkdir"]
        if (
            posixpath.dirname(path) == "/"
            or type(provided) is not dict
            or set(provided) != set(_ALIASES)
        ):
            raise SmokeRefused("INVALID_MANIFEST")
        for alias in _ALIASES:
            grant = provided[alias]
            if type(grant) is not str or _APPROVAL.fullmatch(grant) is None:
                raise SmokeRefused("INVALID_MANIFEST")
            mkdir_grants[alias] = grant
        if len(set(mkdir_grants.values()) | set(approvals.values())) != 4:
            raise SmokeRefused("INVALID_MANIFEST")
    return path, payloads, approvals, mkdir_grants


def create_and_verify(rpc, document: dict) -> dict[str, str]:
    """One call per host for create; NEVER retry a possibly committed write."""
    path, payloads, approvals, mkdir_grants = _prepared(document)
    visible = rpc("hosts_list", {})
    try:
        hosts = {item["alias"] for item in visible["hosts"]}
    except (TypeError, ValueError, KeyError):
        raise SmokeRefused("INVALID_RESULT") from None
    if not set(_ALIASES) <= hosts:
        raise SmokeRefused("HOST_NOT_VISIBLE")

    if mkdir_grants:
        parent = posixpath.dirname(path)
        for alias in _ALIASES:
            # Create only the immediate parent; the host refuses if it exists.
            try:
                result = rpc(
                    "fs_mkdir",
                    {"host": alias, "path": parent, "approval_id": mkdir_grants[alias]},
                )
            except SmokeRefused:
                raise SmokeRefused("CREATE_OUTCOME_UNCERTAIN") from None
            if (
                type(result) is not dict
                or result.get("host") != alias
                or result.get("path") != parent
                or type(result.get("request_id")) is not str
                or not result["request_id"]
            ):
                raise SmokeRefused("CREATE_OUTCOME_UNCERTAIN")
        # Prove both directory operations were effective before writing files.
        for alias in _ALIASES:
            metadata = rpc("fs_stat", {"host": alias, "path": parent})
            if (
                type(metadata) is not dict
                or metadata.get("host") != alias
                or metadata.get("path") != parent
                or metadata.get("kind") != "directory"
            ):
                raise SmokeRefused("CREATE_OUTCOME_UNCERTAIN")

    for alias in _ALIASES:
        # Exact approval is minted by the existing ledger for THIS host,
        # path and content; old/replayed grants are rejected by MCP itself.
        try:
            result = rpc(
                "fs_write",
                {
                    "host": alias,
                    "path": path,
                    "data_base64": base64.b64encode(payloads[alias]).decode("ascii"),
                    "approval_id": approvals[alias],
                },
            )
        except SmokeRefused:
            raise SmokeRefused("CREATE_OUTCOME_UNCERTAIN") from None
        if (
            type(result) is not dict
            or result.get("host") != alias
            or result.get("path") != path
            or type(result.get("content_length")) is not int
            or result["content_length"] != len(payloads[alias])
            or type(result.get("request_id")) is not str
            or not result["request_id"]
        ):
            raise SmokeRefused("CREATE_OUTCOME_UNCERTAIN")
    expected = {alias: hashlib.sha256(payloads[alias]).hexdigest() for alias in _ALIASES}
    # A successful acknowledgement is insufficient: read bytes back over MCP.
    # Refusal here still means one or both creates may have committed.
    return verify_two_nodes(rpc, path=path, expected=expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--execute-create-once", action="store_true")
    parser.add_argument("--allow-loopback-http", action="store_true")
    args = parser.parse_args()
    try:
        if not args.execute_create_once:
            raise SmokeRefused("WRITE_OPTIN_REQUIRED")
        endpoint = validate_endpoint(args.endpoint, allow_loopback=args.allow_loopback_http)
        document = read_manifest(args.manifest)
        _prepared(document)  # refuse bad inputs before a network connection
        client = MCPHTTPClient(endpoint, _read_token(args.token_file))
        client.initialize()
        digests = create_and_verify(client.call, document)
    except SmokeRefused as exc:
        print(json.dumps({"status": "REFUSED", "code": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "status": "PASS",
                "verified_hosts": list(digests),
                "content_sha256": digests,
                "create_only": True,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
