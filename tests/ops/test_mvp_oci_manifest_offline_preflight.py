"""Offline OCI index->platform manifest evidence, not an image authorization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ops.mvp.oci_manifest_offline_preflight import Refused, inspect, main, read_regular_bytes


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fixture():
    child = _encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + "a" * 64,
                "size": 88,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "b" * 64,
                    "size": 129,
                }
            ],
        }
    )
    index = _encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": _pin(child),
                    "size": len(child),
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ],
        }
    )
    return index, child


def test_matching_manifest_bytes_and_platform_pin_are_metadata_only():
    index, child = _fixture()
    result = inspect(index, child, _pin(index), _pin(child))
    assert result["index_digest"] == _pin(index)
    assert result["amd64_manifest_digest"] == _pin(child)
    assert result["platform"] == "linux/amd64"
    assert result["metadata_consistent"] is True
    assert result["publisher_signature_verified"] is False
    assert result["image_layers_downloaded"] is False
    assert result["image_use_authorized"] is False
    assert result["deployment_ready"] is False


@pytest.mark.parametrize(
    "variant",
    [
        "bad_index_pin",
        "bad_manifest_pin",
        "tampered_index",
        "tampered_manifest",
        "duplicate_amd64",
        "wrong_arch",
        "wrong_size",
        "bad_config_digest",
        "empty_layers",
        "duplicate_json_keys",
        "wrong_schema",
        "non_json",
    ],
)
def test_bad_provenance_or_malformed_manifest_refused(variant):
    index, child = _fixture()
    index_pin, child_pin = _pin(index), _pin(child)
    i, c = json.loads(index), json.loads(child)
    if variant == "bad_index_pin":
        index_pin = "sha256:" + "0" * 64
    elif variant == "bad_manifest_pin":
        child_pin = "sha256:" + "0" * 64
    elif variant == "tampered_index":
        index += b" "
    elif variant == "tampered_manifest":
        child += b" "
    elif variant == "duplicate_amd64":
        i["manifests"].append(dict(i["manifests"][0]))
        index = _encoded(i)
        index_pin = _pin(index)
    elif variant == "wrong_arch":
        i["manifests"][0]["platform"]["architecture"] = "arm64"
        index = _encoded(i)
        index_pin = _pin(index)
    elif variant == "wrong_size":
        i["manifests"][0]["size"] += 1
        index = _encoded(i)
        index_pin = _pin(index)
    elif variant == "bad_config_digest":
        c["config"]["digest"] = "sha256:invalid"
        child = _encoded(c)
        child_pin = _pin(child)
        i["manifests"][0]["digest"] = child_pin
        i["manifests"][0]["size"] = len(child)
        index = _encoded(i)
        index_pin = _pin(index)
    elif variant == "empty_layers":
        c["layers"] = []
        child = _encoded(c)
        child_pin = _pin(child)
        i["manifests"][0]["digest"] = child_pin
        i["manifests"][0]["size"] = len(child)
        index = _encoded(i)
        index_pin = _pin(index)
    elif variant == "duplicate_json_keys":
        index = b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}'
        index_pin = _pin(index)
    elif variant == "wrong_schema":
        i["schemaVersion"] = 1
        index = _encoded(i)
        index_pin = _pin(index)
    elif variant == "non_json":
        index = b"{secret-not-json}"
        index_pin = _pin(index)
    with pytest.raises(Refused):
        inspect(index, child, index_pin, child_pin)


def test_cli_reads_only_local_metadata_and_outputs_bounded_json(tmp_path, capsys):
    index, child = _fixture()
    ipath = tmp_path / "index.json"
    cpath = tmp_path / "manifest.json"
    ipath.write_bytes(index)
    cpath.write_bytes(child)
    args = [
        "--index",
        str(ipath),
        "--platform-manifest",
        str(cpath),
        "--expected-index",
        _pin(index),
        "--expected-platform",
        _pin(child),
    ]
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["metadata_consistent"] is True
    assert report["image_use_authorized"] is False
    ipath.write_bytes(index + b" ")
    assert main(args) == 2
    error = capsys.readouterr()
    assert error.out == ""
    assert "REFUSED:" in error.err
    assert str(ipath) not in error.err


def test_input_rejects_symlinks_special_files_and_size(tmp_path):
    f = tmp_path / "manifest.json"
    f.write_bytes(b"{}")
    symlink = tmp_path / "link"
    symlink.symlink_to(f)
    with pytest.raises(Refused):
        read_regular_bytes(symlink)
    with pytest.raises(Refused):
        read_regular_bytes(tmp_path)
    f.write_bytes(b"x" * 262145)
    with pytest.raises(Refused):
        read_regular_bytes(f)


def test_no_registry_or_layer_network_calls_in_offline_module():
    source = (
        Path(__file__).resolve().parents[2] / "ops/mvp/oci_manifest_offline_preflight.py"
    ).read_text()
    assert "urllib" not in source
    assert "requests" not in source
    assert "import docker" not in source.lower()
    assert "subprocess" not in source


@pytest.mark.parametrize(
    "where",
    ["index", "descriptor", "manifest", "config", "layer"],
)
def test_unhashable_untrusted_media_types_are_refused_not_tracebacks(where):
    original_index, original_child = _fixture()
    index, child = json.loads(original_index), json.loads(original_child)
    if where == "index":
        index["mediaType"] = []
    elif where == "descriptor":
        index["manifests"][0]["mediaType"] = []
    elif where == "manifest":
        child["mediaType"] = []
    elif where == "config":
        child["config"]["mediaType"] = []
    else:
        child["layers"][0]["mediaType"] = []
    child_bytes = _encoded(child)
    index["manifests"][0]["digest"] = _pin(child_bytes)
    index["manifests"][0]["size"] = len(child_bytes)
    index_bytes = _encoded(index)
    with pytest.raises(Refused):
        inspect(index_bytes, child_bytes, _pin(index_bytes), _pin(child_bytes))
