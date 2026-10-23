"""Bounded read-once, no-network, non-authorizing MVP Compose topology shape check.

This check accepts *untrusted descriptions*, not live Engine attestations or trusted
image/key evidence. Success is never permission to provision or release anything.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

_INPUT_LIMIT = 16 * 1024
_SCHEMA = "som-mvp-compose-topology-v1"
_REPORT = "som-mvp-compose-topology-preflight-v1"
_ENGINE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z", re.ASCII)
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}@sha256:[0-9a-f]{64}\Z", re.ASCII)
_ALIAS = frozenset({"node01", "node02"})


class Refused(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in values:
        if name in result:
            raise Refused("DUPLICATE_FIELD")
        result[name] = value
    return result


def _bad_constant(_value: str) -> None:
    raise Refused("INVALID_JSON")


def _read_one_regular_file(path: Path) -> object:
    # Do not silently remove safe file-open guarantees on other platforms.
    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW"):
        raise Refused("UNSUPPORTED_PLATFORM")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    # Nonblocking open rejects FIFOs before their writers exist; NOFOLLOW
    # rejects leaf symlinks, even during replacement races.
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("NOT_REGULAR_FILE")
        if info.st_size > _INPUT_LIMIT:
            raise Refused("INPUT_TOO_LARGE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(_INPUT_LIMIT + 1)
        if len(data) > _INPUT_LIMIT:
            raise Refused("INPUT_TOO_LARGE")
    except OSError as exc:
        raise Refused("INPUT_UNAVAILABLE") from exc
    finally:
        os.close(fd)
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_bad_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, Refused):
            raise
        raise Refused("INVALID_JSON") from exc


def _object(value: object, required: frozenset[str]) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != required:
        raise Refused("INVALID_SHAPE")
    return value


def _engine(value: object) -> str:
    if type(value) is not str or _ENGINE.fullmatch(value) is None:
        raise Refused("INVALID_ENGINE")
    return value


def _image(value: object) -> None:
    if type(value) is not str or _IMAGE.fullmatch(value) is None:
        raise Refused("IMAGE_DIGEST_REQUIRED")


def _pin(value: object) -> str:
    if type(value) is not str or not value.startswith("SHA256:"):
        raise Refused("HOST_KEY_PIN_REQUIRED")
    token = value[7:]
    if len(token) != 43 or re.fullmatch(r"[A-Za-z0-9+/]{43}", token, re.ASCII) is None:
        raise Refused("HOST_KEY_PIN_REQUIRED")
    try:
        digest = base64.b64decode(token + "=", validate=True)
    except binascii.Error as exc:
        raise Refused("HOST_KEY_PIN_REQUIRED") from exc
    if len(digest) != 32 or base64.b64encode(digest).decode().rstrip("=") != token:
        raise Refused("HOST_KEY_PIN_REQUIRED")
    return value


def check_topology(document: object) -> dict[str, object]:
    root = _object(document, frozenset({"schema", "mode", "control", "targets"}))
    if root["schema"] != _SCHEMA:
        raise Refused("UNSUPPORTED_SCHEMA")
    mode = root["mode"]
    if mode not in ("dev-e2e", "multi-host") or type(mode) is not str:
        raise Refused("UNSUPPORTED_MODE")
    control = _object(root["control"], frozenset({"engine", "image"}))
    control_engine = _engine(control["engine"])
    _image(control["image"])
    nodes = root["targets"]
    if type(nodes) is not list or len(nodes) != 2:
        raise Refused("INVALID_TARGET_COUNT")
    aliases: set[str] = set()
    engines: set[str] = set()
    pins: set[str] = set()
    for raw in nodes:
        node = _object(raw, frozenset({"alias", "engine", "image", "host_key_pin"}))
        alias = node["alias"]
        if type(alias) is not str or alias not in _ALIAS or alias in aliases:
            raise Refused("INVALID_TARGET_ALIAS")
        aliases.add(alias)
        engines.add(_engine(node["engine"]))
        _image(node["image"])
        pin = _pin(node["host_key_pin"])
        if pin in pins:
            raise Refused("DUPLICATE_HOST_KEY_PIN")
        pins.add(pin)
    if aliases != _ALIAS:
        raise Refused("INVALID_TARGET_ALIAS")
    if mode == "dev-e2e" and (engines != {control_engine}):
        raise Refused("SINGLE_ENGINE_REQUIRED")
    if mode == "multi-host" and (len(engines) != 2 or control_engine in engines):
        raise Refused("THREE_DISTINCT_ENGINES_REQUIRED")
    return {
        "schema": _REPORT,
        "mode": mode,
        "target_count": 2,
        "target_aliases": sorted(aliases),
        "static_structure_valid": True,
        "deployment_ready": False,
        "network_verified": False,
        "runtime_verified": False,
        "trust_verified": False,
        "live_e2e_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline topology-shape check only; no runtime or trust authority."
    )
    parser.add_argument("--topology-json", required=True, type=Path)
    options = parser.parse_args()
    try:
        result = check_topology(_read_one_regular_file(options.topology_json))
    except Refused as exc:
        parser.error("preflight refused: " + exc.code)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
