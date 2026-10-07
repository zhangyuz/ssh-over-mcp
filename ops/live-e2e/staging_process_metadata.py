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


def _require_snapshot(rows: tuple[ProcessRow, ...], *, inspection_pid: int, own_ps_pid: int) -> None:
    _require(type(inspection_pid) is int and 1 <= inspection_pid <= 2147483647)
    _require(type(own_ps_pid) is int and 1 <= own_ps_pid <= 2147483647)
    _require(inspection_pid != own_ps_pid)
    _require(type(rows) is tuple and len(rows) <= 256)
    seen = set()
    validated = []
    total = 0
    for row in rows:
        _require(type(row) is ProcessRow)
        pid, command = row.pid, row.command
        _require(type(pid) is int and 1 <= pid <= 2147483647 and pid not in seen)
        _require(type(command) is str and 1 <= len(command) <= 4096)
        _require(command[0] != " " and command[-1] != " " and not command.endswith("/"))
        line_size = len(str(pid)) + 1 + len(command)
        total += line_size + 1  # Every record requires its own LF.
        _require(line_size <= 4096 and total <= 65536)
        _require(all(32 <= ord(character) <= 126 for character in command))
        seen.add(pid)
        validated.append((pid, command))
    _require(inspection_pid in seen and own_ps_pid in seen)
    # Classify only after every supplied record meets the representation bounds.
    for pid, command in validated:
        basename = command.rsplit("/", 1)[-1].lower()
        interpreter = basename.startswith(("python", "pypy"))
        _require(interpreter == (pid == inspection_pid))
        _require((basename == "ps") == (pid == own_ps_pid))
        _require(not basename.startswith("qemu-system-"))
        _require(basename not in (
            "getconf", "qemu-img", "run-live-local-e2e-orchestrator.py",
            "ssh-over-mcp-live-e2e-gate", "recover_provider.py",
        ))
