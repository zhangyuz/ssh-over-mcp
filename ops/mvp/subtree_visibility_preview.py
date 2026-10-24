"""Offline-only synthetic operator preview of future per-node subtree visibility.

Never used by the MCP runtime, host agent, authorization or approval path. No
filesystem traversal of queried paths: this CLI only compares supplied strings.
No statement from it is a policy grant, host attestation or deployment evidence.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import sys
from pathlib import Path

from topology_preflight import Refused as InputRefused
from topology_preflight import _read_one_regular_file

RULES_SCHEMA = "som-mvp-subtree-rules-preview-v1"
QUERIES_SCHEMA = "som-mvp-subtree-queries-preview-v1"
REPORT_SCHEMA = "som-mvp-subtree-report-preview-v1"
OPS = frozenset({"fs_list", "fs_search"})
HOSTS = frozenset({"node01", "node02"})
DATA_ROOT = "/srv/mcp-data"


class Refused(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _shape(value: object, fields: frozenset[str]) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise Refused("INVALID_SHAPE")
    return value


def _path(value: object) -> str:
    if type(value) is not str or not value.startswith("/"):
        raise Refused("INVALID_PATH")
    try:
        length = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise Refused("INVALID_PATH") from exc
    if not 1 <= length <= 4096 or "\x00" in value:
        raise Refused("INVALID_PATH")
    # Reject canonicalization tricks rather than quietly normalizing a rule or query.
    if posixpath.normpath(value) != value or "//" in value or "\\" in value:
        raise Refused("INVALID_PATH")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise Refused("INVALID_PATH")
    if any(part in {".", ".."} or any(c in part for c in "*?[]") for part in value.split("/")):
        raise Refused("INVALID_PATH")
    return value


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _roots(value: object, *, allow: bool) -> tuple[str, ...]:
    if type(value) is not list or len(value) > (16 if allow else 64) or (allow and not value):
        raise Refused("INVALID_RULES")
    roots = tuple(_path(item) for item in value)
    if len(roots) != len(set(roots)) or any(not _within(root, DATA_ROOT) for root in roots):
        raise Refused("INVALID_RULES")
    return roots


def _op_rules(value: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    data = _shape(value, frozenset({"allow_roots", "deny_subtrees"}))
    allow = _roots(data["allow_roots"], allow=True)
    deny = _roots(data["deny_subtrees"], allow=False)
    # Disallow redundant/conflicting forms rather than guessing rule intent.
    if any(not any(_within(d, a) and d != a for a in allow) for d in deny):
        raise Refused("INVALID_RULES")
    if any(a != b and _within(a, b) for a in deny for b in deny):
        raise Refused("INVALID_RULES")
    return allow, deny


def _rules(value: object) -> tuple[str, str, dict[str, tuple[tuple[str, ...], tuple[str, ...]]]]:
    data = _shape(value, frozenset({"schema", "host", "profile", "operations"}))
    if (
        data["schema"] != RULES_SCHEMA
        or type(data["host"]) is not str
        or data["host"] not in HOSTS
        or data["profile"] != "rw-operator"
    ):
        raise Refused("INVALID_RULES")
    operations = _shape(data["operations"], OPS)
    return data["host"], data["profile"], {name: _op_rules(operations[name]) for name in OPS}


def preview(rules: object, queries: object) -> dict:
    host, profile, operations = _rules(rules)
    query_doc = _shape(queries, frozenset({"schema", "host", "profile", "queries"}))
    if (
        query_doc["schema"] != QUERIES_SCHEMA
        or query_doc["host"] != host
        or query_doc["profile"] != profile
    ):
        raise Refused("INVALID_QUERIES")
    request_list = query_doc["queries"]
    if type(request_list) is not list or not 1 <= len(request_list) <= 64:
        raise Refused("INVALID_QUERIES")
    results = []
    for index, item in enumerate(request_list):
        case = _shape(item, frozenset({"operation", "path"}))
        operation = case["operation"]
        if type(operation) is not str or operation not in OPS:
            raise Refused("INVALID_QUERIES")
        path = _path(case["path"])
        allow, deny = operations[operation]
        visible = any(_within(path, root) for root in allow) and not any(
            _within(path, root) for root in deny
        )
        results.append({"index": index, "visible": visible})
    return {
        "schema": REPORT_SCHEMA,
        "results": results,
        "authoritative": False,
        "deployment_ready": False,
        "host_accessed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline synthetic subtree-visibility preview; NOT policy authorization"
    )
    parser.add_argument("--rules-json", type=Path, required=True)
    parser.add_argument("--queries-json", type=Path, required=True)
    args = parser.parse_args()
    try:
        rules = _read_one_regular_file(args.rules_json)
        queries = _read_one_regular_file(args.queries_json)
        report = preview(rules, queries)
    except (Refused, InputRefused) as exc:
        print(f"refused: {exc.code}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
