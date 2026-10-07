"""Dormant pure metadata predicates; supplied observations grant no authority."""

from __future__ import annotations

import re
from dataclasses import dataclass


class ProcessMetadataError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("staging process metadata rejected")


@dataclass(frozen=True, slots=True)
class TempParent:
    native_path: str
    canonical_path: str


@dataclass(frozen=True, slots=True)
class ProcessRow:
    pid: int
    command: str


def _require(condition: bool) -> None:
    if not condition:
        raise ProcessMetadataError() from None


def _parse_temp_parent(stdout: bytes) -> TempParent:
    _require(type(stdout) is bytes)
    _require(len(stdout) <= 1024)
    _require(re.fullmatch(rb"/var/folders/[a-z0-9]{2}/[a-z0-9_]+/T/\n", stdout) is not None)
    native = stdout[:-1].decode("ascii")
    return TempParent(native, "/private" + native)


def _parse_process_rows(stdout: bytes) -> tuple[ProcessRow, ...]:
    _require(type(stdout) is bytes)
    _require(len(stdout) <= 65536)
    if not stdout:
        return ()
    _require(stdout.endswith(b"\n"))
    lines = tuple(line for line in stdout.split(b"\n")[:-1] if line)
    _require(len(lines) <= 256 and all(len(line) <= 4096 for line in lines))
    rows = []
    seen = set()
    for line in lines:
        # Only PID-left padding is discarded. Exactly one post-PID byte separates fields.
        pid_text, separator, command = line.lstrip(b" ").partition(b" ")
        _require(1 <= len(pid_text) <= 10 and pid_text.isdigit() and pid_text[:1] != b"0")
        _require(separator == b" " and bool(command))
        _require(command[:1] != b" " and command[-1:] != b" ")
        _require(all(32 <= byte <= 126 for byte in command))
        pid = int(pid_text)
        _require(pid <= 2147483647 and pid not in seen)
        seen.add(pid)
        rows.append(ProcessRow(pid, command.decode("ascii")))
    return tuple(rows)
