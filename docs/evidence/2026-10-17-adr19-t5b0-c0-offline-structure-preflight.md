# T5B-0 C0 offline structure preflight — non-authorizing

**Status:** structural evidence helper only, `C0_COLLECT_HOLD_INCOMPLETE`. Follow [C0 object classes and unresolved fields](2026-10-17-adr19-t5b0-c0-inert-candidate-object-allowlist.md). The stdlib-only `ops/t5b0/c0_manifest_preflight.py` reads a local JSON file and performs **no network, installation, import of candidate materials, trust-root import or verifier execution**. It neither generates a download command nor grants consent. No C0 candidate bytes were collected.

Usage: `python3 ops/t5b0/c0_manifest_preflight.py /path/to/untrusted-proposed-manifest.json`; exit 0 means only `STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION`, exit 2 means refusal. JSON keys must be exactly `schema`, `objects`, `approval`; schema `som-t5b0-c0-preflight-v1`, `approval: null`. Each object must contain exactly `id`, `url`, `sha256`, `bytes`, `max_bytes`; ID from `C0-W1/P1/R1/T1`, no duplicates, 1–4 objects, SHA256 64 lowercase hex, integer positive exact bytes no greater than cap (hard cap 100 MB), and syntactically pinned HTTPS URL without query, credentials, port, fragment or parent traversal, percent-encoded path components, noncanonical dot/empty path segments, backslashes, non-ASCII URL characters, or malformed ports. Input safety: `os.open(O_RDONLY|O_NONBLOCK|O_NOFOLLOW)` plus `fstat` regular-file enforcement and a single bounded `os.read(16385)` reject FIFO/symlink/directory and oversized files before parsing; changed length and JSON recursion errors refuse with exit 2. This is a best-effort offline input check, not an adversarial shared-filesystem snapshot guarantee. The checker does not establish immutability, validate endpoint identity, enforce source allowlists, resolve DNS, check bytes or attestations, or establish signer/clock trust. Passing is never permission to fetch.

Run offline tests: `python3 -m unittest discover -s ops/t5b0 -p 'test_*.py' -v`. Tests include malformed URL, digest, size, duplicate ID, duplicate JSON keys, FIFO blocking, oversized regular files, symlinks, deep JSON, unauthorized approval marker and unexpected schema fields. **No tests contact external services.** The manifest itself is not committed with pretend trusted values: object URLs, byte sizes, OS image and downloader digests, original-byte custody/retention, independently authenticated OOB root/clock and operator consent remain missing. Separate operator authorization and independent review of the full exact-object manifest and isolated environment are mandatory before any collection. T5B-0 admission, T5B-1, Mac UID502/APFS, real pkg and Linux Slice C remain HOLD.

## Hosted regression coverage

A `tests/ops` pytest bridge runs all offline C0 fixtures on both Python 3.13 and 3.14 in the existing `rest` shard, under the existing non-root, cleared-supplementary-groups Linux execution policy. Failures block the existing required aggregate contexts. Crucially, the frozen-authority `.github/workflows/ci.yml` remains byte-identical; no CI privilege, runner, external endpoint or network allowance changes.

## Canonical URL spelling (fail closed)

The local syntax check additionally rejects percent-encoded path components (including encoded dot segments and separators), dot/empty path segments, backslashes, non-ASCII URL text, and malformed ports. This avoids ambiguous URL spellings and parser exceptions; it does **not** authenticate DNS, endpoint provenance, artifact immutability or approve fetching. No network is used.

## Machine-readable offline result (`--json`)

`python3 ops/t5b0/c0_manifest_preflight.py --json /path/to/proposal.json` prints one JSON object on stdout. Fields are `status` (`STRUCTURE_ONLY_PASS` or `REFUSED`), `errors` (array of diagnostic strings), `authorization` (`NO_AUTHORIZATION`), `collection` (`C0_COLLECT_HOLD`), and `network` (`NO_NETWORK`). Exit status remains 0 for a structurally valid proposal and 2 for refused/unreadable input. Without `--json`, the original text output and exit codes are unchanged. The JSON report is an **offline syntax/structure observation only**, not proof of artifact authenticity, source identity, network permission, operator consent, or Sigstore verification.

Example successful output (field order is not contractual):

```json
{"status":"STRUCTURE_ONLY_PASS","errors":[],"authorization":"NO_AUTHORIZATION","collection":"C0_COLLECT_HOLD","network":"NO_NETWORK"}
```

Automations must check both process exit code and `status`, and must never treat `STRUCTURE_ONLY_PASS` as permission to collect or execute candidate materials.
