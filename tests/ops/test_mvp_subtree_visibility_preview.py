"""Non-authorizing, offline operator preview: positive and hostile cases."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "ops" / "mvp" / "subtree_visibility_preview.py"


def rules() -> dict:
    return {
        "schema": "som-mvp-subtree-rules-preview-v1",
        "host": "node01",
        "profile": "rw-operator",
        "operations": {
            "fs_list": {
                "allow_roots": ["/srv/mcp-data"],
                "deny_subtrees": ["/srv/mcp-data/secrets"],
            },
            "fs_search": {
                "allow_roots": ["/srv/mcp-data"],
                "deny_subtrees": ["/srv/mcp-data/secrets"],
            },
        },
    }


def queries(paths: list[str], *, operation: str = "fs_list") -> dict:
    return {
        "schema": "som-mvp-subtree-queries-preview-v1",
        "host": "node01",
        "profile": "rw-operator",
        "queries": [{"operation": operation, "path": path} for path in paths],
    }


def invoke(tmp_path: Path, policy: object, request: object) -> subprocess.CompletedProcess[str]:
    rules_path = tmp_path / "rules.json"
    queries_path = tmp_path / "queries.json"
    rules_path.write_text(json.dumps(policy), encoding="utf-8")
    queries_path.write_text(json.dumps(request), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--rules-json",
            str(rules_path),
            "--queries-json",
            str(queries_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


def assert_refused(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert result.stdout == ""
    assert result.stderr.startswith("refused:")
    assert "secrets" not in result.stderr
    assert "node01" not in result.stderr


def test_preview_exact_component_subtree_entry_and_descendants(tmp_path):
    result = invoke(
        tmp_path,
        rules(),
        queries(
            [
                "/srv/mcp-data",
                "/srv/mcp-data/readme.txt",
                "/srv/mcp-data/secrets",
                "/srv/mcp-data/secrets/keys",
                "/srv/mcp-data/secrets2",
                "/srv/mcp-data-old",
            ]
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "schema": "som-mvp-subtree-report-preview-v1",
        "results": [
            {"index": 0, "visible": True},
            {"index": 1, "visible": True},
            {"index": 2, "visible": False},
            {"index": 3, "visible": False},
            {"index": 4, "visible": True},
            {"index": 5, "visible": False},
        ],
        "authoritative": False,
        "deployment_ready": False,
        "host_accessed": False,
    }
    assert "secrets" not in result.stdout
    assert "/srv" not in result.stdout


@pytest.mark.parametrize("operation", ["fs_list", "fs_search"])
def test_applies_each_operation_independently(tmp_path, operation):
    policy = rules()
    if operation == "fs_search":
        policy["operations"]["fs_search"]["allow_roots"] = ["/srv/mcp-data/public"]
        policy["operations"]["fs_search"]["deny_subtrees"] = []
    result = invoke(
        tmp_path,
        policy,
        queries(
            [
                "/srv/mcp-data/public",
                "/srv/mcp-data/secrets",
                "/srv/mcp-data/misc",
            ],
            operation=operation,
        ),
    )
    assert result.returncode == 0, result.stderr
    expected = [True, False, operation == "fs_list"]
    assert [item["visible"] for item in json.loads(result.stdout)["results"]] == expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p, q: p.update(schema="v5"),
        lambda p, q: q.update(schema="v5"),
        lambda p, q: p.update(secret="SECRET_SENTINEL"),
        lambda p, q: p.update(host="node02"),
        lambda p, q: p.update(host=["node01"]),
        lambda p, q: p.update(host={"value": "node01"}),
        lambda p, q: p.update(host=True),
        lambda p, q: q.update(profile="admin"),
        lambda p, q: p["operations"].update(fs_delete=p["operations"]["fs_list"]),
        lambda p, q: q["queries"][0].update(operation="fs_write"),
        lambda p, q: q["queries"].append({"path": "/srv/mcp-data"}),
        lambda p, q: p["operations"]["fs_list"]["allow_roots"].append("/srv/mcp-data"),
        lambda p, q: p["operations"]["fs_list"]["deny_subtrees"].append("/srv/mcp-data"),
        lambda p, q: p["operations"]["fs_list"]["deny_subtrees"].append(
            "/srv/mcp-data/secrets/nested"
        ),
        lambda p, q: p["operations"]["fs_list"]["deny_subtrees"].append("/etc"),
        lambda p, q: p["operations"]["fs_list"]["deny_subtrees"].append("/srv/mcp-data/secrets/**"),
        lambda p, q: q["queries"][0].update(path="/srv/mcp-data/../etc"),
        lambda p, q: q["queries"][0].update(path="/srv/mcp-data//secret"),
        lambda p, q: q["queries"][0].update(path="/srv/mcp-data/."),
        lambda p, q: q["queries"][0].update(path="/srv/mcp-data/"),
        lambda p, q: q["queries"][0].update(path="/srv/mcp-data/\x00x"),
        lambda p, q: q["queries"][0].update(path="/srv/mcp-data/" + "a" * 4096),
        lambda p, q: q.update(queries=q["queries"] * 65),
        lambda p, q: q.update(queries=[]),
        lambda p, q: p["operations"]["fs_list"].update(allow_roots=[]),
    ],
)
def test_invalid_shapes_conflicts_paths_are_refused(tmp_path, mutate):
    policy, query = rules(), queries(["/srv/mcp-data/readme"])
    mutate(policy, query)
    result = invoke(tmp_path, policy, query)
    assert_refused(result)
    assert "SECRET_SENTINEL" not in result.stderr


def test_duplicate_fields_invalid_constant_and_trailing_payload_refused(tmp_path):
    q = queries(["/srv/mcp-data"])
    rp, qp = tmp_path / "r.json", tmp_path / "q.json"
    qp.write_text(json.dumps(q), encoding="utf-8")
    for content in ('{"schema":"a","schema":"b"}', '{"x":NaN}', "{}garbage"):
        rp.write_text(content, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(CLI), "--rules-json", str(rp), "--queries-json", str(qp)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        assert_refused(result)


def test_oversize_rules_refused_without_echo(tmp_path):
    p = rules()
    p["secret"] = "SECRET_SENTINEL" * 4000
    assert_refused(invoke(tmp_path, p, queries(["/srv/mcp-data"])))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no fifo")
def test_fifo_refused_without_blocking(tmp_path):
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    qp = tmp_path / "q.json"
    qp.write_text(json.dumps(queries(["/srv/mcp-data"])))
    result = subprocess.run(
        [sys.executable, str(CLI), "--rules-json", str(pipe), "--queries-json", str(qp)],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert_refused(result)


def test_symlink_file_refused_without_reading_target(tmp_path):
    secret = tmp_path / "source"
    secret.write_text(json.dumps(rules()))
    link = tmp_path / "link"
    link.symlink_to(secret)
    qp = tmp_path / "q.json"
    qp.write_text(json.dumps(queries(["/srv/mcp-data"])))
    result = subprocess.run(
        [sys.executable, str(CLI), "--rules-json", str(link), "--queries-json", str(qp)],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert_refused(result)
