# Typed Filesystem Mutation Implementation Plan

Date: 2026-09-30

Source design:
`docs/superpowers/specs/2026-09-30-typed-filesystem-mutations-design.md`

## Goal

Add create-only filesystem mutation in small slices without enabling
destructive pathname mutation.

## Task 1 — mkdir primitive only

Create:

- `src/ssh_over_mcp/host_agent/filesystem_mutation.py`
- `tests/host_agent/test_filesystem_mutation.py`

Implement one-level create-only directory creation.

Requirements:

- absolute canonical path;
- Linux pathname hard bound;
- existing parent traversal through pinned directory fds and `O_NOFOLLOW`;
- final destination absent;
- fixed server-owned maximum mode `0700`;
- process umask/default ACL may only make the result more restrictive;
- no recursive parents;
- no post-create reopen/chmod/stat/remove of the final pathname;
- no cleanup by blind pathname unlink/rmdir;
- no SMCP exposure.

Verification:

- regular create;
- restrictive umask never gets widened;
- existing file/directory/symlink denial;
- intermediate symlink denial;
- missing parent denial;
- proof that the final name is not reopened after successful mkdir;
- no shell/PATH/subprocess path.

## Task 2 — mkdir host policy

Modify:

- `src/ssh_over_mcp/host_agent/policy.py`
- `tests/host_agent/test_policy.py`

Add profile-scoped `mkdir_roots` to filesystem policy.

Requirements:

- same lexical canonicalization/root-containment helper as read policy;
- filesystem policy may contain read-only permissions, mkdir permissions, or
  both;
- no caller-selected mode;
- no filesystem touch during authorization.

Keep SMCP disconnected in this task.

## Task 3 — typed fs_mkdir wire operation

Modify:

- `src/ssh_over_mcp/ssh/protocol.py`
- `src/ssh_over_mcp/host_agent/protocol.py`
- `src/ssh_over_mcp/host_agent/cli.py`
- protocol/CLI tests;
- source-of-truth docs.

Requirements:

- strict `operation="fs_mkdir"` envelope;
- metadata-only request;
- trailing stdin rejected before mutation;
- policy before primitive;
- success has empty stdout and status 0;
- policy/primitive errors generic;
- no command preparation, containment, shell, or MCP tool.

## Task 4 — create-only regular-file primitive

Modify/create:

- `src/ssh_over_mcp/host_agent/filesystem_mutation.py`
- `tests/host_agent/test_filesystem_mutation.py`

Implement unnamed-inode create-only publication.

Requirements:

- pinned destination parent;
- `O_TMPFILE` on the destination filesystem;
- strict server-owned mode `0600`;
- bounded exact body length;
- fsync before publish;
- create-if-absent publish through an fd-bound Linux mechanism;
- fsync parent before success;
- existing destination never replaced;
- no named-temp fallback;
- unsupported kernel/filesystem/proc-fd publication fails closed.

This task remains internal only.

## Task 5 — write-create host policy

Modify:

- `src/ssh_over_mcp/host_agent/policy.py`
- `tests/host_agent/test_policy.py`

Add:

- profile-scoped `write_create_roots`;
- strict server-owned `max_write_bytes` bounded by the hard primitive limit.

Requirements:

- no overwrite/append flag;
- no caller mode/owner;
- lexical-only authorization;
- no object creation during policy evaluation.

## Task 6 — typed fs_write create-only wire operation

Modify:

- shared SMCP protocol;
- host-agent streaming parser/CLI;
- tests/docs.

Envelope fields:

- request ID;
- profile;
- operation `fs_write`;
- path;
- strict declared `content_length`.

Body:

- raw file bytes;
- exact length required;
- early EOF and overrun fail before publish.

Success:

- status 0;
- empty stdout.

No overwrite semantics.

## Task 7 — adversarial Linux validation

Use the Ubuntu 26.04 x86 self-hosted runner.

Prove:

- symlink/path escapes fail;
- destination collision never replaces an entry;
- unsupported `O_TMPFILE` publication fails closed;
- failed write does not publish a final pathname;
- published data is exact and fsynced before visibility;
- policy denial touches no object;
- request body mismatch touches no final object.

Do not use GitHub-hosted runners as evidence.

## Task 8 — mutation boundary review

Review Phase 3e create-only mutations as a whole.

Explicitly confirm that none of the following is remotely available:

- overwrite;
- append;
- in-place truncate;
- move/rename existing object;
- delete/unlink/rmdir existing object;
- recursive mutation;
- arbitrary chmod/chown;
- generic privileged filesystem helper.

Only after this review may a separate design investigate destructive namespace
mutation.
