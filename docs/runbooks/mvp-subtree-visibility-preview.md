# Offline subtree-visibility preview (operator CLI)

**Status: synthetic preview ONLY; no enforcement or deployment authorization.** This is an independently runnable, *non-authoritative* operator tool to exercise the proposed `fs_list`/`fs_search` allow/deny subtree visibility rule shape during [M2 protocol design review](../superpowers/specs/2026-10-23-private-compose-rw-mvp-design.md). It does not execute those MCP tools, inspect the requested paths, connect to SSH, provision host keys, update production policy, or produce a signed central snapshot/host Policy v5. **M2 protocol-freeze, all Mode A/Mode B live gates, and #342 remain HOLD.** An operator must not treat `visible: true` as access permission.

It deliberately accepts *synthetic* JSON fixtures with a fixed `rw-operator` profile, one of `node01`/`node02`, and exact root `/srv/mcp-data` (or a descendant) only. Both FS operations have explicit `allow_roots` and `deny_subtrees`; each deny subtree includes the entry node and all descendants. Deny wins even when a more specific allow would match; paths use component-boundary comparison (so `/srv/mcp-data/secrets2` is not under `/srv/mcp-data/secrets`). Glob patterns, including `/**`, are **not** accepted as v5 `deny_subtrees`: this preview requires a canonical root path. **A central policy rule spelling `.../secrets/**` is not assumed to be compiled or authorized by this preview**; that semantic translation must be separately frozen and reviewed in SMCP v2.

Example: create fixtures in an operator-owned *disposable*, unshared directory. Do not supply real secrets or privileged policy files.

```bash
mkdir -p ./tmp-mvp-preview
cat > ./tmp-mvp-preview/rules.json <<'JSON'
{
  "schema": "som-mvp-subtree-rules-preview-v1",
  "host": "node01",
  "profile": "rw-operator",
  "operations": {
    "fs_list": {
      "allow_roots": ["/srv/mcp-data"],
      "deny_subtrees": ["/srv/mcp-data/secrets"]
    },
    "fs_search": {
      "allow_roots": ["/srv/mcp-data"],
      "deny_subtrees": ["/srv/mcp-data/secrets"]
    }
  }
}
JSON
cat > ./tmp-mvp-preview/queries.json <<'JSON'
{
  "schema": "som-mvp-subtree-queries-preview-v1",
  "host": "node01",
  "profile": "rw-operator",
  "queries": [
    {"operation": "fs_list", "path": "/srv/mcp-data/secrets"},
    {"operation": "fs_search", "path": "/srv/mcp-data/secrets/keys"},
    {"operation": "fs_list", "path": "/srv/mcp-data/secrets2"}
  ]
}
JSON
python3 ops/mvp/subtree_visibility_preview.py \
  --rules-json ./tmp-mvp-preview/rules.json \
  --queries-json ./tmp-mvp-preview/queries.json
```

Expected process exit **0** and report `results` with `visible` `false`, `false`, `true`; `authoritative=false`, `deployment_ready=false`, `host_accessed=false`. Query indices only are returned, not input paths. Exit **2** and a fixed `refused: CODE` on malformed/ambiguous/oversized JSON, duplicate fields, non-regular or symlink input, foreign host/profile, unknown operation, non-canonical paths or invalid rules. The tool opens bounded regular JSON files (16 KiB per input) without following leaf symlinks; never executes filesystem operations on any **queried** path. It does not provide reliable timing side-channel protection or a production revocation barrier. Delete disposable fixtures after reviewing output.

**Formal acceptance still requires:** signed/MAC-bound complete central policy snapshots, a monotonic policy epoch/revocation ACK barrier, Host Policy v5 schema with root-and-descendant deny, FD-anchored host traversal, central result re-check, real dual-host SSH tests, and exact-HEAD Native Level-3 where applicable. This standalone helper implements **none** of those authorities.
