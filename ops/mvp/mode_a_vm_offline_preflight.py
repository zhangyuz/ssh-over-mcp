"""Read-only Mode A VM proposal shape check. Never authorizes boot."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

import yaml

_MAX_BYTES = 16 * 1024
_SOURCE = (
    "https://cloud-images.ubuntu.com/releases/resolute/release/"
    "ubuntu-26.04-server-cloudimg-amd64.img"
)
_DIGEST = "sha256:5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5"
_FIELDS = frozenset(
    {
        "minimumLimaVersion",
        "images",
        "param",
        "mounts",
        "cpus",
        "memory",
        "vmType",
        "arch",
        "containerd",
        "disk",
        "plain",
    }
)


class Refused(ValueError):
    """A proposal was rejected without exposing its contents."""


class _UniqueKeysLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise Refused("INVALID_YAML")
        pairs = super().construct_pairs(node, deep=deep)
        result = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise Refused("INVALID_YAML")
            result[key] = value
        return result


def read_yaml(path: Path) -> object:
    """Read a bounded ordinary file; do not follow a leaf symlink."""
    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW"):
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
        if before.st_size > _MAX_BYTES:
            raise Refused("INPUT_TOO_LARGE")
        data = os.read(fd, _MAX_BYTES + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != before.st_size or any(
            getattr(before, item) != getattr(after, item) for item in fields
        ):
            raise Refused("INPUT_CHANGED")
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    finally:
        os.close(fd)
    try:
        return yaml.load(data.decode("utf-8"), Loader=_UniqueKeysLoader)
    except Refused:
        raise
    except Exception as exc:
        # PyYAML safe scalar constructors may raise KeyError, IndexError or
        # AttributeError on malformed explicit tags, not only YAMLError.
        # The public CLI must refuse untrusted YAML without a traceback.
        raise Refused("INVALID_YAML") from exc


def check_document(document: object) -> dict[str, object]:
    """Allow only the reviewed declaration; never infer runtime isolation."""
    if type(document) is not dict or set(document) != _FIELDS:
        raise Refused("INVALID_VM_SHAPE")
    image_list = document["images"]
    if type(image_list) is not list or len(image_list) != 1:
        raise Refused("UNREVIEWED_IMAGE_SOURCE")
    image = image_list[0]
    if type(image) is not dict or image != {
        "location": _SOURCE,
        "arch": "x86_64",
        "variant": "server",
        "digest": _DIGEST,
    }:
        raise Refused("UNREVIEWED_IMAGE_SOURCE")
    exact = {
        "minimumLimaVersion": "2.0.0",
        "param": {"internal_netplanOptional": "true"},
        "mounts": None,
        "cpus": 2,
        "memory": "4GiB",
        "vmType": "vz",
        "arch": "x86_64",
        "containerd": {"user": False, "system": False},
        "disk": "16GiB",
        "plain": True,
    }
    for field, expected in exact.items():
        actual = document[field]
        if type(actual) is not type(expected) or actual != expected:
            raise Refused("UNREVIEWED_VM_SETTING")
    if any(type(document["containerd"][name]) is not bool for name in ("user", "system")):
        raise Refused("UNREVIEWED_VM_SETTING")
    return {
        "schema": "som-mode-a-vm-offline-preflight-v1",
        "static_vm_shape_valid": True,
        "host_lan_isolation_verified": False,
        "docker_runtime_verified": False,
        "vm_execution_authorized": False,
        "deployment_ready": False,
        "network_gate": "UNVERIFIED_DEFAULT_USERMODE_EGRESS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OFFLINE ONLY: never authorizes VM boot")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = check_document(read_yaml(args.config))
    except Refused as exc:
        print(f"REFUSED:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
