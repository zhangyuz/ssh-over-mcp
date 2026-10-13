# ADR 0015: Exact /private/tmp residual forensic authority

- Status: proposed read-only implementation; no cleanup authorization
- Date: 2026-10-13 (America/Toronto)

## Evidence

Trusted-main UID-502 recovery inspection [38341134143](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38341134143) confirmed that native getconf and Python tempfile select different parents. Trusted-main getconf forensic [38338824514](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38338824514) failed catalog-open-1-missing. Independent UID-501 no-follow metadata observed the same three fixed historical identities under literal /private/tmp, whose parent is root-owned mode 01777 on device 16777220. Neither observation supplies cleanup authority.

The catalog is fixed: ssh-over-mcp-e2e-i8ow1ni6 (16777220:187176421), ssh-over-mcp-e2e-recover.cc8Del (16777220:186815322), ssh-over-mcp-e2e-w_kn4rus (16777220:186877220), all UID 502, 0700. The fixed marker target is 47531dadb58d365f74089dd5f52ce1b61bb0fdd1 and owner PID 38013.

## Scope and safety

The new manual live-local-e2e-private-tmp-forensic.yml workflow only runs on trusted main, pinned github.sha, with pinned actions, read-only token, non-cancelling live-local-e2e concurrency, non-admin UID-502 runner, and no user-selected paths/arguments. Original ADR 0014 getconf inspection and recovery workflows remain unchanged.

The new inspector pins literal / then private then tmp with O_DIRECTORY and O_NOFOLLOW, exact root-owned 0755/0755/01777 modes on the same device, before/after descriptor metadata and post-close parent-edge checks. The sticky-world-writable exception applies ONLY to this fixed parent, never to children or existing general preflight. All three literal children must match the exact recorded device/inode and UID-502 0700 policy. Missing, symlink, hardlink, special file, foreign owner, unsafe mode, mount crossing, identity drift or ambiguous descriptor cleanup refuses.

Reuse fixed marker authority, bounded process snapshot and metadata-only recursive residual inventory. Observe twice and compare complete entries, limit 4096 total entries, 12 levels, 4096-byte paths, 2 MiB combined evidence, 60 seconds per inventory root/pass, and 420 seconds total. Read no payload file contents, Git objects, ISO, wheels or secrets. Only after final checks and successful descriptor cleanup serialize a private 7-day artifact explicitly bearing recovery_eligible=false. On refusal exit 70 with fixed phase only, without partial artifact.

## Remaining gates

Even successful evidence is NOT a provenance guarantee, exclusive quiescence assertion, deletion permission or marker-clearance receipt. UID-502 ABA/concurrency and post-observation changes remain possible. Independently review all three inventories, verify owner PID death and absent QEMU, investigate changed historical files, obtain explicit per-exact-identity operator authorization before any destructive action, then use existing marker-only recovery if all guards pass. Only exact-main no-network Level-3 with complete host/guest cleanup closes the issue. Future tempfile convergence requires separate design/review and must not hide these historical /private/tmp roots.

## Refusal-only phase refinement (2026-10-13)

The first trusted-main [private-tmp inspection 38383833045](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38383833045) passed fixed parent, marker and all three catalog root checks but refused at generic inventory-a, exit 70. Separate fixed labels inventory-a-1/2/3 and inventory-b-1/2/3 now identify only which of the three immutable catalog roots failed a complete metadata pass. They do not disclose any observed path, file name, file mode, owner, contents or underlying OS error; do not alter inventory policy or confer disposition authority. Failure still generates no successful artifact.
