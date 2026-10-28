"""Offline consistency of two local OCI metadata documents; never grants image use."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

_INPUT_MAX = 256 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


class Refused(ValueError):
    """Invalid, unverified or untrusted input."""


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in items:
        if key in obj:
            raise Refused("DUPLICATE_FIELD")
        obj[key] = value
    return obj


def _bad_constant(_value: str) -> None:
    raise Refused("INVALID_JSON")


def _decode(raw: bytes) -> dict:
    if not raw or len(raw) > _INPUT_MAX:
        raise Refused("INVALID_SIZE")
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_bad_constant
        )
    except Refused:
        raise
    except Exception as exc:
        raise Refused("INVALID_JSON") from exc
    if type(data) is not dict:
        raise Refused("INVALID_SHAPE")
    return data


def read_regular_bytes(path: Path) -> bytes:
    """Read one bounded ordinary file once without following the final symlink."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise Refused("UNSUPPORTED_PLATFORM")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Refused("NOT_REGULAR")
        if not 0 < before.st_size <= _INPUT_MAX:
            raise Refused("INVALID_SIZE")
        raw = os.read(fd, _INPUT_MAX + 1)
        after = os.fstat(fd)
        attrs = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(
            getattr(before, x) != getattr(after, x) for x in attrs
        ):
            raise Refused("INPUT_CHANGED")
        return raw
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    finally:
        os.close(fd)


def _check_digest(raw: bytes, expected: str) -> None:
    if type(expected) is not str or _DIGEST.fullmatch(expected) is None:
        raise Refused("INVALID_DIGEST")
    real = "sha256:" + hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(real, expected):
        raise Refused("DIGEST_MISMATCH")


def _allowed(value: object, options: set[str]) -> bool:
    return type(value) is str and value in options


def _size(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise Refused("INVALID_SIZE")
    return value


def _sha(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise Refused("INVALID_DIGEST")
    return value


def inspect(
    index_bytes: bytes,
    platform_bytes: bytes,
    expected_index: str,
    expected_platform: str,
) -> dict[str, object]:
    """Prove local byte/hash/platform consistency only, never publisher trust."""
    _check_digest(index_bytes, expected_index)
    _check_digest(platform_bytes, expected_platform)
    index = _decode(index_bytes)
    child = _decode(platform_bytes)
    if (
        type(index.get("schemaVersion")) is not int
        or index["schemaVersion"] != 2
        or not _allowed(index.get("mediaType"), _INDEX_TYPES)
    ):
        raise Refused("INVALID_INDEX")
    items = index.get("manifests")
    if type(items) is not list or not 1 <= len(items) <= 64:
        raise Refused("INVALID_INDEX")
    selected = []
    for desc in items:
        if type(desc) is not dict:
            raise Refused("INVALID_INDEX")
        platform = desc.get("platform")
        if type(platform) is not dict:
            raise Refused("INVALID_INDEX")
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            selected.append(desc)
    if len(selected) != 1:
        raise Refused("INVALID_PLATFORM")
    desc = selected[0]
    if (
        not _allowed(desc.get("mediaType"), _MANIFEST_TYPES)
        or _sha(desc.get("digest")) != expected_platform
        or _size(desc.get("size"), _INPUT_MAX) != len(platform_bytes)
    ):
        raise Refused("INVALID_DESCRIPTOR")
    if (
        type(child.get("schemaVersion")) is not int
        or child["schemaVersion"] != 2
        or not _allowed(child.get("mediaType"), _MANIFEST_TYPES)
        or child["mediaType"] != desc["mediaType"]
    ):
        raise Refused("INVALID_MANIFEST")

    config = child.get("config")
    if type(config) is not dict or not _allowed(config.get("mediaType"), _CONFIG_TYPES):
        raise Refused("INVALID_CONFIG")
    config_digest = _sha(config.get("digest"))
    _size(config.get("size"), 1024 * 1024 * 1024)
    layers = child.get("layers")
    if type(layers) is not list or not 1 <= len(layers) <= 64:
        raise Refused("INVALID_LAYERS")
    for layer in layers:
        if type(layer) is not dict or not _allowed(layer.get("mediaType"), _LAYER_TYPES):
            raise Refused("INVALID_LAYERS")
        _sha(layer.get("digest"))
        _size(layer.get("size"), 1024 * 1024 * 1024)
    return {
        "schema": "som-offline-oci-manifest-preflight-v1",
        # Local bytes/digests cannot establish which registry supplied them.
        "repository_provenance_verified": False,
        "platform": "linux/amd64",
        "index_digest": expected_index,
        "amd64_manifest_digest": expected_platform,
        "config_digest": config_digest,
        "layer_descriptors": len(layers),
        "metadata_consistent": True,
        "publisher_signature_verified": False,
        "image_layers_downloaded": False,
        "image_use_authorized": False,
        "deployment_ready": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline OCI manifest verification only")
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--platform-manifest", type=Path, required=True)
    parser.add_argument("--expected-index", required=True)
    parser.add_argument("--expected-platform", required=True)
    args = parser.parse_args(argv)
    try:
        result = inspect(
            read_regular_bytes(args.index),
            read_regular_bytes(args.platform_manifest),
            args.expected_index,
            args.expected_platform,
        )
    except Refused as exc:
        print(f"REFUSED:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
