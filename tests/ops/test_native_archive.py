from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/native_archive.py"


def _load_module() -> ModuleType:
    assert MODULE.is_file(), "bounded native package-data reader is missing"
    name = "ssh_over_mcp_native_archive"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _tar_bytes(
    members: list[tuple[str, bytes | None, int, bytes, str]],
    *,
    format: int = tarfile.GNU_FORMAT,
    pax_headers: dict[str, str] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=format) as archive:
        for name, data, mode, kind, linkname in members:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.type = kind
            info.linkname = linkname
            if pax_headers:
                info.pax_headers = dict(pax_headers)
            if data is not None:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)
    return output.getvalue()


def _limits(module: ModuleType, **changes: int):
    values = {
        "max_entries": 32,
        "max_expanded_bytes": 4096,
        "max_path_bytes": 256,
        "max_file_bytes": 2048,
        "max_link_hops": 8,
    }
    values.update(changes)
    return module.ArchiveLimits(**values)


def test_reads_data_tar_into_immutable_metadata_only_recipe() -> None:
    module = _load_module()
    payload = b"int main(void) { return 0; }\n"
    archive = _tar_bytes(
        [
            ("./usr/", None, 0o755, tarfile.DIRTYPE, ""),
            ("./usr/bin/cc", payload, 0o755, tarfile.REGTYPE, ""),
            ("./usr/bin/gcc", None, 0o777, tarfile.SYMTYPE, "cc"),
        ]
    )

    entries = module.read_data_tar(io.BytesIO(archive), limits=_limits(module))

    assert tuple(entry.path for entry in entries) == ("/usr", "/usr/bin/cc", "/usr/bin/gcc")
    assert entries[0].kind == "directory"
    assert entries[1].kind == "file"
    assert entries[1].mode == 0o755
    assert entries[1].size == len(payload)
    assert entries[1].sha256 == hashlib.sha256(payload).hexdigest()
    assert entries[1].link_target is None
    assert entries[2].kind == "symlink"
    assert entries[2].link_target == "cc"
    assert entries[2].sha256 is None
    assert entries[2].size == 0
    assert all(entry.uid == 0 and entry.gid == 0 for entry in entries)
    assert not hasattr(entries[1], "content")
    with pytest.raises((AttributeError, TypeError)):
        entries[1].mode = 0o777


@pytest.mark.parametrize(
    "name",
    ["/etc/passwd", "../etc/passwd", "usr/../../etc/passwd", ".", "", "usr/./bin/cc"],
)
def test_rejects_noncanonical_or_escaping_member_paths(name: str) -> None:
    module = _load_module()
    archive = _tar_bytes([(name, b"x", 0o644, tarfile.REGTYPE, "")])

    with pytest.raises(module.NativeArchiveError, match="^native archive validation failed$"):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


def test_rejects_duplicate_paths_after_leading_dot_normalization() -> None:
    module = _load_module()
    archive = _tar_bytes(
        [
            ("./usr/bin/cc", b"one", 0o755, tarfile.REGTYPE, ""),
            ("usr/bin/cc", b"two", 0o755, tarfile.REGTYPE, ""),
        ]
    )

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


def test_rejects_regular_file_trailing_slash() -> None:
    module = _load_module()
    archive = _tar_bytes([("usr/bin/cc/", b"x", 0o755, tarfile.REGTYPE, "")])

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


def test_rejects_duplicate_directory_after_tar_normalization() -> None:
    module = _load_module()
    archive = _tar_bytes(
        [
            ("usr///", None, 0o755, tarfile.DIRTYPE, ""),
            ("usr/", None, 0o755, tarfile.DIRTYPE, ""),
        ]
    )

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


@pytest.mark.parametrize(
    "kind",
    [tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE],
)
def test_rejects_hardlinks_and_special_files(kind: bytes) -> None:
    module = _load_module()
    archive = _tar_bytes([("usr/bin/cc", None, 0o755, kind, "usr/bin/other")])

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o6755])
def test_rejects_setid_metadata(mode: int) -> None:
    module = _load_module()
    archive = _tar_bytes([("usr/bin/cc", b"x", mode, tarfile.REGTYPE, "")])

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


def test_rejects_extended_metadata_in_n1a() -> None:
    module = _load_module()
    archive = _tar_bytes(
        [("usr/bin/cc", b"x", 0o755, tarfile.REGTYPE, "")],
        format=tarfile.PAX_FORMAT,
        pax_headers={"SCHILY.xattr.security.capability": "sensitive"},
    )

    with pytest.raises(module.NativeArchiveError, match="^native archive validation failed$"):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


@pytest.mark.parametrize(
    "linkname",
    ["/etc/passwd", "../../../etc/passwd", "../../../../tmp/escape"],
)
def test_rejects_absolute_or_root_escaping_symlinks(linkname: str) -> None:
    module = _load_module()
    archive = _tar_bytes([("usr/bin/cc", None, 0o777, tarfile.SYMTYPE, linkname)])

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(archive), limits=_limits(module))


def test_rejects_symlink_cycles_and_excessive_link_chains() -> None:
    module = _load_module()
    cycle = _tar_bytes(
        [
            ("usr/bin/a", None, 0o777, tarfile.SYMTYPE, "b"),
            ("usr/bin/b", None, 0o777, tarfile.SYMTYPE, "a"),
        ]
    )
    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(cycle), limits=_limits(module))

    component_cycle = _tar_bytes(
        [
            ("a", None, 0o777, tarfile.SYMTYPE, "dir/x"),
            ("dir", None, 0o777, tarfile.SYMTYPE, "a"),
        ]
    )
    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(component_cycle), limits=_limits(module))

    chain = _tar_bytes(
        [
            ("usr/bin/a", None, 0o777, tarfile.SYMTYPE, "b"),
            ("usr/bin/b", None, 0o777, tarfile.SYMTYPE, "c"),
            ("usr/bin/c", None, 0o777, tarfile.SYMTYPE, "d"),
            ("usr/bin/d", b"x", 0o755, tarfile.REGTYPE, ""),
        ]
    )
    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(
            io.BytesIO(chain), limits=_limits(module, max_link_hops=2)
        )


@pytest.mark.parametrize(
    "limit_name,limit_value,members",
    [
        (
            "max_entries",
            1,
            [
                ("usr/a", b"a", 0o644, tarfile.REGTYPE, ""),
                ("usr/b", b"b", 0o644, tarfile.REGTYPE, ""),
            ],
        ),
        ("max_expanded_bytes", 3, [("usr/a", b"abcd", 0o644, tarfile.REGTYPE, "")]),
        ("max_file_bytes", 3, [("usr/a", b"abcd", 0o644, tarfile.REGTYPE, "")]),
        ("max_path_bytes", 5, [("usr/abcdef", b"x", 0o644, tarfile.REGTYPE, "")]),
    ],
)
def test_enforces_entry_expansion_file_and_path_limits(
    limit_name: str,
    limit_value: int,
    members: list[tuple[str, bytes | None, int, bytes, str]],
) -> None:
    module = _load_module()
    archive = _tar_bytes(members)

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(
            io.BytesIO(archive), limits=_limits(module, **{limit_name: limit_value})
        )


def test_path_limit_counts_utf8_bytes_not_codepoints() -> None:
    module = _load_module()
    archive = _tar_bytes([("ééé", b"x", 0o644, tarfile.REGTYPE, "")])

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(
            io.BytesIO(archive), limits=_limits(module, max_path_bytes=5)
        )


def test_truncated_or_non_tar_input_fails_with_fixed_public_error() -> None:
    module = _load_module()

    for archive in (b"not-a-tar", b"secret-path-or-payload" * 32):
        with pytest.raises(
            module.NativeArchiveError, match="^native archive validation failed$"
        ) as error:
            module.read_data_tar(io.BytesIO(archive), limits=_limits(module))
        assert "secret" not in str(error.value)


def test_rejects_compressed_tar_input() -> None:
    module = _load_module()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("usr/bin/cc")
        info.mode = 0o755
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    with pytest.raises(module.NativeArchiveError):
        module.read_data_tar(io.BytesIO(output.getvalue()), limits=_limits(module))


def test_defaults_match_reviewed_n1_package_data_limits() -> None:
    module = _load_module()

    assert module.DEFAULT_LIMITS == module.ArchiveLimits(
        max_entries=32_768,
        max_expanded_bytes=768 * 1024 * 1024,
        max_path_bytes=4_096,
        max_file_bytes=128 * 1024 * 1024,
        max_link_hops=40,
    )


def test_n1a_reader_is_not_activated_by_current_live_e2e() -> None:
    for relative in (
        ".github/workflows/live-local-e2e.yml",
        "scripts/run-live-local-e2e-orchestrator.py",
        "ops/live-e2e/ssh-over-mcp-live-e2e-gate",
    ):
        assert "native_archive.py" not in (ROOT / relative).read_text(encoding="utf-8")
