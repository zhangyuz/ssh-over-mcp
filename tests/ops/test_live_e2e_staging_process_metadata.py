from __future__ import annotations

import importlib.util
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

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
