# C0 directory namespace race refusal — bounded design (2026-10-19)

**Operator problem.** A descriptor-anchored offline directory audit scans names and later opens manifests. A concurrent namespace mutation can make the observed set inconsistent while each individual regular file remains stable, yet the current report can say STRUCTURE_ONLY_PASS.

**Behavior.** Capture identity and namespace-change metadata via os.fstat on the SAME already-open, O_NOFOLLOW directory FD before iteration and after bounded inspection. Compare (st_dev, st_ino, st_mode, st_mtime_ns, st_ctime_ns). Deliberately ignore st_atime_ns since normal directory reads can update it. If observed drift occurs, fail closed: status REFUSED / exit 2, errors=['directory changed during audit'], results=[], audit_sha256=null, inventory empty. Never retain a partial semantic object diff from refused directory in either compare mode. A stable directory behaves as before. Existing per-file race checks remain independent.

**Tests.** RED deterministic mutation after enumerating/reading a valid manifest (create an auxiliary entry), plus a synthetic pair of same-FD stat observations differing only in ctime_ns; both must refuse even if an otherwise valid file was read. An atime-only change is accepted. Test direct directory, two-directory and stream-to-directory reports. Verify malformed/oversized/symlink and 64-total-entry/16-JSON manifest caps are unchanged.

**Limits.** This is best-effort namespace drift detection, NOT an atomic snapshot against privileged adversaries or proof of source integrity. No network, writes by production code, collection, trust admission, Mac UID502/APFS, Linux C or execution. NO_AUTHORIZATION / C0_COLLECT_HOLD / NO_NETWORK and UNVERIFIED evidence gaps remain unchanged.
