"""Informational-only CLI: no native launch or commit-status output."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/pr_ci_shadow.py"
SHA = "a" * 40


def _module():
    sys.path.insert(0, str(MODULE.parent))
    spec = importlib.util.spec_from_file_location("pr_ci_shadow", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _event_file(tmp_path):
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps(
            {
                "action": "completed",
                "repository": {"full_name": "zhangyuz/ssh-over-mcp", "id": 42},
                "workflow_run": {"id": 123, "run_attempt": 1, "head_sha": SHA},
            }
        )
    )
    return event_file


def test_shadow_cli_emits_informational_verdict(tmp_path, monkeypatch, capsys) -> None:
    m = _module()

    class FakeAPI:
        def __init__(self, token):
            assert token == "test-only"

        def load(self, event):
            assert event["workflow_run"]["id"] == 123
            return ("repository", "workflow", "run", "pulls", "jobs")

    monkeypatch.setattr(m, "GitHubReadAPI", FakeAPI)
    monkeypatch.setattr(
        m,
        "decide",
        lambda *_: m.ShadowObservation(
            repo_id=42,
            pr_number=40,
            head_sha=SHA,
            ci_run_id=123,
            ci_attempt=1,
        ),
    )
    assert m.main(_event_file(tmp_path), token="test-only") == 0
    lines = capsys.readouterr()
    result = json.loads(lines.out)
    assert result == {
        "verdict": "METADATA_MATCH_SHADOW",
        "reason_code": "CI_METADATA_MATCHED_NO_AUTHORITY",
        "ci_run_id": 123,
        "ci_attempt": 1,
        "pr_number": 40,
        "head_sha": SHA,
        "base_freshness_proven": False,
        "trusted_suite_proven": False,
        "dispatch_authorized": False,
    }
    assert lines.err == ""


def test_cli_redacts_exception_details(tmp_path, monkeypatch, capsys) -> None:
    m = _module()

    class Broken:
        def __init__(self, _token):
            pass

        def load(self, _event):
            raise RuntimeError("nonpublic transport response")

    monkeypatch.setattr(m, "GitHubReadAPI", Broken)
    assert m.main(_event_file(tmp_path), token="local-token-value") == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "verdict": "ERROR",
        "reason_code": "API_UNEXPECTED_ERROR",
    }
    assert "nonpublic" not in output.out + output.err
    assert "local-token-value" not in output.out + output.err


def test_malformed_or_oversize_event_errors(tmp_path, capsys) -> None:
    m = _module()
    for content, code in [
        (b"{", "EVENT_JSON_INVALID"),
        (b"[]", "EVENT_SHAPE_INVALID"),
        (b"X" * (256 * 1024 + 1), "EVENT_TOO_LARGE"),
    ]:
        f = tmp_path / "event.json"
        f.write_bytes(content)
        assert m.main(f, token="test") == 1
        assert json.loads(capsys.readouterr().out) == {
            "verdict": "ERROR",
            "reason_code": code,
        }


def test_fork_refusal_is_not_success_or_sha_status(tmp_path, monkeypatch, capsys) -> None:
    m = _module()

    class Fake:
        def __init__(self, _token):
            pass

        def load(self, _event):
            return (None, None, None, None, None)

    def refuse(*_):
        raise m.Refused("PR_NOT_UNIQUE_OR_CURRENT")

    monkeypatch.setattr(m, "GitHubReadAPI", Fake)
    monkeypatch.setattr(m, "decide", refuse)
    assert m.main(_event_file(tmp_path), token="test") == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"verdict": "REFUSED", "reason_code": "PR_NOT_UNIQUE_OR_CURRENT"}
    assert "sha" not in out
    assert "pr_number" not in out


def test_cli_does_not_write_github_output_or_status(tmp_path, monkeypatch, capsys) -> None:
    m = _module()
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary"))

    class NoAPI:
        def __init__(self, _token):
            pass

        def load(self, _event):
            raise m.Refused("API_UNAVAILABLE")

    monkeypatch.setattr(m, "GitHubReadAPI", NoAPI)
    assert m.main(_event_file(tmp_path), token="test") == 1
    result = json.loads(capsys.readouterr().out)
    assert result == {"verdict": "ERROR", "reason_code": "API_UNAVAILABLE"}
    assert not output.exists()
    assert not (tmp_path / "summary").exists()


def test_event_missing_never_prints_path(tmp_path, capsys) -> None:
    m = _module()
    assert m.main(tmp_path / "unavailable-path", token="test") == 1
    assert json.loads(capsys.readouterr().out) == {
        "verdict": "ERROR",
        "reason_code": "EVENT_UNAVAILABLE",
    }
