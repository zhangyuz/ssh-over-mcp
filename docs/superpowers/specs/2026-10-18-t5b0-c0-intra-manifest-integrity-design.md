# C0 intra-manifest object integrity (bounded security design)

**Problem:** The offline C0 validator refuses inconsistencies across separate manifests, but a single manifest can declare the same URL under different object IDs, or the same SHA-256 with conflicting byte sizes, and still pass.

**Operator capability:** Refuse ambiguous object declarations before reporting STRUCTURE_ONLY_PASS. Every URL must be unique among IDs in a manifest (including identical metadata); any shared SHA-256 must declare the same byte count. Distinct URLs that share the same SHA-256 and bytes remain valid (possible mirrors).

**Interface:** Reuse validate(doc), error code INVALID_STRUCTURE and existing reports, exit 2 refusal, cross-file consistency, and object_diff=UNAVAILABLE on invalid inputs. Never echo raw URL/digest in diagnostics. Cover single-file, --stdin, --batch, --stdin-batch, --directory and compare. Preserve existing ID/schema/URL rules, limits (4 objects; 16 manifests; 16 KiB/record; 64 directory entries) and legacy success paths.

**Implementation:** Track seen URL and SHA-256-to-byte mappings inside validate; no new option or I/O. TDD proves currently accepted conflicts, then GREEN and existing regressions. Update project runbook and roadmap.

**Authority:** No collection, verifier execution, T5B source/root admission, privileged Mac/UID502/APFS, or Linux C. NO_AUTHORIZATION, C0_COLLECT_HOLD, NO_NETWORK and five UNVERIFIED gaps remain.
