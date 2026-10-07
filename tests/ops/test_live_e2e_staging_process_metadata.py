from __future__ import annotations

import builtins
import importlib.util
import os
import socket
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_process_metadata.py"


def _load_module():
    assert MODULE.is_file(), "dormant process metadata module is not implemented"
    name = "ssh_over_mcp_staging_process_metadata"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def metadata():
    return _load_module()


def test_temp_parent_literal_alias_and_shape():
    metadata = _load_module()
    value = metadata._parse_temp_parent(b"/var/folders/ab/token_123/T/\n")
    assert type(value) is metadata.TempParent
    assert value.native_path == "/var/folders/ab/token_123/T/"
    assert value.canonical_path == "/private/var/folders/ab/token_123/T/"


@pytest.mark.parametrize("raw", [
    b"", b"/var/folders/ab/token_123/T/", b"/var/folders/ab/token/T/\n\n",
    b"/var/folders/ab/token/T/\r\n", b"/var/folders/ab/token\x00/T/\n",
    b"/var/folders/ab/to\tken/T/\n", b" /var/folders/ab/token/T/\n",
    b"/var/folders/ab/token/T/ \n", b"/private/var/folders/ab/token/T/\n",
    b"/var/folders/AB/token/T/\n", b"/var/folders/a/token/T/\n",
    b"/var/folders/abc/token/T/\n", b"/var/folders/ab//T/\n",
    b"/var/folders/ab/../T/\n", b"/var/folders/ab/to-ken/T/\n",
    b"/var/folders/ab/Token/T/\n", b"/var/folders/ab/tok\xffen/T/\n",
    b"/var//folders/ab/token/T/\n", b"/tmp/selected-by-environment/\n",
    b"${TMPDIR}/\n", b"/var/folders/ab/token/T/\n/other/\n",
])
def test_temp_parent_refuses_controls_extra_lines_and_environment_style_paths(metadata, raw):
    with pytest.raises(metadata.ProcessMetadataError, match="^staging process metadata rejected$"):
        metadata._parse_temp_parent(raw)


def test_temp_parent_byte_equality_and_overflow(metadata):
    # 16 prefix bytes + 1004 token bytes + 4 suffix bytes, independently pinned.
    exact = b"/var/folders/ab/" + b"a" * 1004 + b"/T/\n"
    overflow = b"/var/folders/ab/" + b"a" * 1005 + b"/T/\n"
    assert len(exact) == 1024 and len(overflow) == 1025
    result = metadata._parse_temp_parent(exact)
    assert result.native_path == exact[:-1].decode("ascii")
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_temp_parent(overflow)


def test_process_rows_preserve_command_spaces(metadata):
    rows = metadata._parse_process_rows(b"\n  411 /dir with space/Python\n512 ps  inner\n\n")
    assert type(rows) is tuple
    assert [(row.pid, row.command) for row in rows] == [
        (411, "/dir with space/Python"), (512, "ps  inner"),
    ]
    assert all(type(row) is metadata.ProcessRow for row in rows)
    assert metadata._parse_process_rows(b"") == ()
    assert metadata._parse_process_rows(b"\n\n") == ()


@pytest.mark.parametrize("raw", [
    b"411  ps\n", b"  411  ps\n", b"411   ps\n", b"411 \n", b"411 ps \n",
    b"411\tps\n", b"411 ps\t\n", b"411 ps\r\n", b"411 \x00ps\n",
    b"411 p\x7fs\n", b"411 p\xffs\n", b"411 ps", b"411 ps\n \n",
])
def test_single_post_pid_separator_does_not_swallow_command_spaces(metadata, raw):
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_process_rows(raw)
    row, = metadata._parse_process_rows(b"  411 ps\n")
    assert (row.pid, row.command) == (411, "ps")


@pytest.mark.parametrize("raw", [
    b"0 ps\n", b"00 ps\n", b"01 ps\n", b"+1 ps\n", b"-1 ps\n",
    b"1.0 ps\n", b"1e1 ps\n", b"2147483648 ps\n", b"9999999999 ps\n",
    b"10000000000 ps\n", b"9" * 4000 + b" ps\n", b"1 ps\n1 other\n",
])
def test_duplicate_noncanonical_pid_and_wrong_types_refuse(metadata, raw):
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_process_rows(raw)


class _BytesSubclass(bytes):
    pass


class _NoCoercion:
    def __bytes__(self):
        raise AssertionError("must not coerce")

    def __len__(self):
        raise AssertionError("must not inspect unsupported shape")


@pytest.mark.parametrize("raw", [
    None, "411 ps\n", 1, True, bytearray(b"411 ps\n"), memoryview(b"411 ps\n"),
    _BytesSubclass(b"411 ps\n"), _NoCoercion(),
])
def test_exact_byte_types_refuse_without_coercion(metadata, raw):
    for parser in (metadata._parse_temp_parent, metadata._parse_process_rows):
        with pytest.raises(metadata.ProcessMetadataError,
                           match="^staging process metadata rejected$"):
            parser(raw)


def test_bytes_rows_line_pid_bounds(metadata):
    smallest, largest = metadata._parse_process_rows(b"1 ps\n2147483647 Python\n")
    assert (smallest.pid, largest.pid) == (1, 2147483647)
    exact_line = b"1 " + b"z" * 4094 + b"\n"
    overflow_line = b"1 " + b"z" * 4095 + b"\n"
    assert len(exact_line[:-1]) == 4096 and len(overflow_line[:-1]) == 4097
    assert metadata._parse_process_rows(exact_line)[0].command == "z" * 4094
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_process_rows(overflow_line)
    exact_rows = b"".join(f"{pid} x\n".encode("ascii") for pid in range(1, 257))
    assert len(exact_rows.splitlines()) == 256 and len(exact_rows) < 65536
    assert len(metadata._parse_process_rows(exact_rows)) == 256
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_process_rows(exact_rows + b"257 x\n")


def test_process_total_bytes_equality_is_not_masked_by_other_bounds(metadata):
    exact = (b"411 Python\n512 ps\n"
             + b"".join(str(pid).encode("ascii") + b" " + b"z" * 4091 + b"\n"
                        for pid in range(1000, 1015))
             + b"1015 " + b"z" * 4057 + b"\n")
    overflow = exact[:-1] + b"z\n"
    assert len(exact) == 65536 and len(overflow) == 65537
    assert len(exact.splitlines()) == 18
    assert all(len(line) <= 4096 for line in overflow.splitlines())
    rows = metadata._parse_process_rows(exact)
    assert len(rows) == 18 and rows[-1].command == "z" * 4057
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_process_rows(overflow)
    assert metadata._parse_process_rows(b"\n" * 65536) == ()
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._parse_process_rows(b"\n" * 65537)


def test_records_are_immutable_and_failure_has_no_partial_output(metadata, capsys):
    parent = metadata._parse_temp_parent(b"/var/folders/a0/token_123/T/\n")
    row, = metadata._parse_process_rows(b"411 Python\n")
    with pytest.raises(FrozenInstanceError):
        row.pid = 999
    with pytest.raises(FrozenInstanceError):
        parent.native_path = "/changed/"
    assert not hasattr(parent, "__dict__") and not hasattr(row, "__dict__")
    with pytest.raises(metadata.ProcessMetadataError,
                       match="^staging process metadata rejected$") as error:
        metadata._parse_process_rows(b"411 Python\nSECRET_CANARY\n")
    assert error.value.args == ("staging process metadata rejected",)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("inspection,own_ps", [
    (411, 411), (True, 512), (411, False), (0, 512), (-1, 512),
    (2147483648, 512), (411, 2147483648), ("411", 512), (411, 512.0), (None, 512),
])
def test_exact_distinct_own_identities_required(metadata, inspection, own_ps):
    rows = metadata._parse_process_rows(b"411 Python\n512 ps\n")
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(rows, inspection_pid=inspection, own_ps_pid=own_ps)


@pytest.mark.parametrize("wire", [
    b"", b"512 ps\n", b"411 Python\n", b"411 bash\n512 ps\n",
    b"411 Python\n512 ordinary\n", b"411 Python\n513 ps\n",
    b"411 Python\n512 Python\n", b"411 Python\n512 ps\n613 Ps\n",
])
def test_missing_mismatched_and_extra_own_rows_refuse(metadata, wire):
    rows = metadata._parse_process_rows(wire)
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=512)


@pytest.mark.parametrize("candidate", [
    "Python", "python3.13td", "python3.7dm", "pypy3.10dm", "python3..13",
    "python3.13tdx", "python-tools", "PyThOn3.13TD", "PYPY3.10DM",
])
def test_interpreter_prefix_vectors_and_case_fold(metadata, candidate):
    own = (metadata.ProcessRow(411, "/framework/" + candidate),
           metadata.ProcessRow(512, "/bin/Ps"), metadata.ProcessRow(700, "ordinary"))
    assert metadata._require_snapshot(own, inspection_pid=411, own_ps_pid=512) is None
    extra = own + (metadata.ProcessRow(613, "/framework/" + candidate),)
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(extra, inspection_pid=411, own_ps_pid=512)


@pytest.mark.parametrize("candidate", [
    "getconf", "GeTcOnF", "ps", "PS", "qemu-system-x86_64", "QEMU-SYSTEM-aarch64",
    "qemu-system-", "qemu-img", "QEMU-IMG", "run-live-local-e2e-orchestrator.py",
    "RUN-LIVE-LOCAL-E2E-ORCHESTRATOR.PY", "ssh-over-mcp-live-e2e-gate",
    "SSH-OVER-MCP-LIVE-E2E-GATE", "recover_provider.py", "RECOVER_PROVIDER.PY",
])
def test_fixed_qemu_authority_and_leftover_names_refuse(metadata, candidate):
    rows = (metadata.ProcessRow(411, "/framework/Python"),
            metadata.ProcessRow(512, "/bin/ps"), metadata.ProcessRow(613, "/bin/"+candidate))
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=512)


@pytest.mark.parametrize("stage", ["before", "after"])
@pytest.mark.parametrize("orphan", ["getconf", "PS", "Python3.13td"])
def test_both_snapshot_stage_vectors_reject_orphans(metadata, stage, orphan):
    # Pure vectors only; the different ps IDs do not claim real snapshot wiring.
    for label, own_ps in (("before", 512), ("after", 513)):
        rows = (metadata.ProcessRow(411, "Python"), metadata.ProcessRow(own_ps, "ps"))
        if label == stage:
            rows += (metadata.ProcessRow(613, orphan),)
            with pytest.raises(metadata.ProcessMetadataError):
                metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=own_ps)
        else:
            assert metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=own_ps) is None


class _TupleSubclass(tuple):
    pass


class _StrSubclass(str):
    pass


@pytest.mark.parametrize("shape", ["list", "dict", "none", "tuple-subclass", "record-subclass"])
def test_forged_container_and_record_shapes_refuse(metadata, shape):
    own = (metadata.ProcessRow(411, "Python"), metadata.ProcessRow(512, "ps"))
    class DerivedRow(metadata.ProcessRow):
        pass
    choices = {
        "list": list(own), "dict": {411: "Python", 512: "ps"}, "none": None,
        "tuple-subclass": _TupleSubclass(own),
        "record-subclass": own + (DerivedRow(613, "ordinary"),),
    }
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(choices[shape], inspection_pid=411, own_ps_pid=512)


@pytest.mark.parametrize("pid,command", [
    (True, "ordinary"), (0, "ordinary"), (-1, "ordinary"), (2147483648, "ordinary"),
    (613.0, "ordinary"), ("613", "ordinary"), (613, None), (613, b"ordinary"),
    (613, ""), (613, " ordinary"), (613, "ordinary "), (613, "ordi\tnary"),
    (613, "ordi\nnary"), (613, "ordi\x00nary"), (613, "ordi\x7fnary"),
    (613, "ordiénaire"), (613, "/path/"), (613, _StrSubclass("ordinary")),
    (411, "Python"), (613, "z" * 4093),
])
def test_forged_intermediate_records_refuse(metadata, pid, command):
    rows = (metadata.ProcessRow(411, "Python"), metadata.ProcessRow(512, "ps"),
            metadata.ProcessRow(pid, command))
    with pytest.raises(metadata.ProcessMetadataError,
                       match="^staging process metadata rejected$"):
        metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=512)


def test_forged_snapshot_line_and_row_equality_and_overflow(metadata):
    own = (metadata.ProcessRow(411, "Python"), metadata.ProcessRow(512, "ps"))
    # 10 PID digits + one space + 4085 command bytes = 4096, excluding LF.
    row = metadata.ProcessRow(2147483647, "z" * 4085)
    assert metadata._require_snapshot(own + (row,), inspection_pid=411, own_ps_pid=512) is None
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(own + (metadata.ProcessRow(2147483647, "z" * 4086),),
                                   inspection_pid=411, own_ps_pid=512)
    exact_rows = own + tuple(metadata.ProcessRow(pid, "ordinary") for pid in range(1000, 1254))
    assert len(exact_rows) == 256
    assert metadata._require_snapshot(exact_rows, inspection_pid=411, own_ps_pid=512) is None
    with pytest.raises(metadata.ProcessMetadataError):
        metadata._require_snapshot(exact_rows + (metadata.ProcessRow(1254, "ordinary"),),
                                   inspection_pid=411, own_ps_pid=512)


def test_forged_snapshot_aggregate_equality_and_overflow(metadata):
    own = (metadata.ProcessRow(411, "Python"), metadata.ProcessRow(512, "ps"))
    prefix = tuple(metadata.ProcessRow(pid, "z" * 4091) for pid in range(1000, 1015))
    exact = own + prefix + (metadata.ProcessRow(1015, "z" * 4057),)
    overflow = own + prefix + (metadata.ProcessRow(1015, "z" * 4058),)
    forged = own + tuple(metadata.ProcessRow(pid, "z" * 4000) for pid in range(1000, 1018))
    assert sum(len(f"{row.pid} {row.command}\n") for row in exact) == 65536
    assert sum(len(f"{row.pid} {row.command}\n") for row in overflow) == 65537
    assert sum(len(f"{row.pid} {row.command}\n") for row in forged) == 72126
    assert all(len(f"{row.pid} {row.command}") <= 4096 for row in overflow + forged)
    assert metadata._require_snapshot(exact, inspection_pid=411, own_ps_pid=512) is None
    for rows in (overflow, forged):
        with pytest.raises(metadata.ProcessMetadataError):
            metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=512)


def test_import_and_validation_perform_no_host_action_or_output(monkeypatch, capsys):
    # Read/compile and import stdlib outside the guarded module execution boundary.
    code = compile(MODULE.read_bytes(), str(MODULE), "exec")
    name = "ssh_over_mcp_process_metadata_no_host_action"
    module = ModuleType(name)
    module.__file__ = str(MODULE)
    attempted = []
    original_import = builtins.__import__
    def forbidden(*args, **kwargs):
        attempted.append("host action")
        raise AssertionError("pure metadata attempted host action")
    def guarded_import(target, *args, **kwargs):
        if target in {"staging_diagnostics", "staging_inventory", "recover_provider"}:
            attempted.append("capability import")
            raise AssertionError("pure metadata imported a host helper")
        return original_import(target, *args, **kwargs)
    with monkeypatch.context() as guard:
        for target, attributes in (
            (os, ("open", "stat", "lstat", "scandir", "read", "write", "getpid", "getenv",
                  "posix_spawn", "kill", "waitpid")),
            (subprocess, ("Popen", "run")), (socket, ("socket", "create_connection")),
            (builtins, ("open",)), (Path, ("open", "resolve", "read_bytes", "read_text")),
        ):
            for attribute in attributes:
                guard.setattr(target, attribute, forbidden)
        guard.setattr(builtins, "__import__", guarded_import)
        guard.setitem(sys.modules, name, module)
        # Fixed repo-module bytecode only; separate loader I/O from the guarded module boundary.
        exec(code, module.__dict__)  # noqa: S102
        parent = module._parse_temp_parent(b"/var/folders/ab/token_123/T/\n")
        assert parent.canonical_path == "/private/var/folders/ab/token_123/T/"
        rows = module._parse_process_rows(b"411 Python\n512 ps\n613 /with space/ordinary\n")
        assert module._require_snapshot(rows, inspection_pid=411, own_ps_pid=512) is None
        with pytest.raises(module.ProcessMetadataError,
                           match="^staging process metadata rejected$"):
            module._require_snapshot(rows + (module.ProcessRow(614, "SECRET_CANARY Python/"),),
                                     inspection_pid=411, own_ps_pid=512)
    assert attempted == []
    assert capsys.readouterr() == ("", "")
