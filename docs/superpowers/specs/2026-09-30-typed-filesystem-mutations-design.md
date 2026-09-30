# Typed Filesystem Mutation Design

Date: 2026-09-30

Status: proposed for implementation planning

## 1. Purpose

Phase `3e` already has descriptor-pinned read-only filesystem primitives,
profile-scoped host-local read policy, and typed SMCP v1 `fs_stat` /
`fs_read` operations.

Mutation changes the security problem materially. A pathname can be replaced
between an identity check and a later `rename()` / `unlink()`. In a
directory writable by another process, a conventional
"stat/pin, recheck, then mutate pathname" sequence can therefore overwrite,
move, or delete an object which was not the object originally authorized.

This design defines the mutation boundary before any write-capable SMCP
operation is enabled.

## 2. Security decision

The first mutation phase MUST be create-only.

Allowed initial capabilities:

- create one new directory at an absent final path;
- create one new regular file at an absent final path.

Not enabled in the initial mutation phase:

- overwrite or replace an existing file;
- append or in-place truncate/write;
- move/rename an existing object;
- delete/unlink/rmdir an existing object;
- recursive directory creation or recursive deletion;
- chmod/chown supplied by request data;
- symlink, hardlink, FIFO, socket, or device creation.

The conceptual MCP `fs_write`, `fs_move`, and `fs_delete` tools remain
future surface work until their host boundary is proven safe.

## 3. Why destructive pathname mutation is deferred

Descriptor pinning proves which inode was inspected or opened, but POSIX
`renameat()` and `unlinkat()` still operate on directory entries by name.

If another process may modify the same directory, the sequence

1. pin object A;
2. validate object A;
3. re-check object A;
4. unlink or rename the pathname

does not atomically guarantee that the final syscall still targets object A.
An attacker or concurrent peer can replace the directory entry after the last
check.

The implementation MUST NOT treat a short race window as a security boundary.

Overwrite, move, and delete therefore require a separately reviewed mechanism
which provides one of:

- an enforceable namespace-exclusion invariant for the mutation root;
- a narrow trusted helper with stronger directory-entry authority and a
  conditional identity operation;
- another kernel primitive which can prove the destructive action is bound to
  the authorized object.

Until such a mechanism exists, these operations fail closed by remaining
unimplemented.

## 4. Mutation policy

Mutation authorization is separate from read authorization.

Each already-allowed SSH profile may eventually receive:

- `mkdir_roots`;
- `write_create_roots`;
- a strict server-owned `max_write_bytes` for file creation.

Request data does not choose ownership or permission policy.

Initial server-owned maximum modes:

- directory creation: `0700`;
- regular-file creation: `0600`.

The process umask or default ACL may make a newly created object more
restrictive. The host agent does not widen it afterward merely to obtain an
exact mode.

A later policy revision may add a bounded server-owned mode allowlist. The
initial wire format MUST NOT accept arbitrary chmod/chown metadata.

Mutation roots are absolute, lexically canonical, and subject to the same Linux
pathname hard bound as the read-only policy.

Policy authorization remains lexical-only. It MUST NOT resolve, stat, open,
create, or remove caller-selected objects.

## 5. Parent traversal

Every mutation starts from a pinned `/` descriptor.

Each existing parent component is opened with:

`O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`

The final path component:

- must be a single ordinary pathname component;
- must not be empty, `.`, or `..`;
- is interpreted relative to the pinned parent fd;
- is never reached by following a symlink.

No mutation operation may fall back to an absolute-path shell command, PATH
lookup, `sh -c`, or a generic helper command string.

## 6. Directory creation primitive

The first primitive is one-level create-only `mkdir`.

Requirements:

1. the parent directory already exists and is pinned;
2. the final entry must be absent;
3. creation uses `mkdirat` semantics through Python's `dir_fd` interface;
4. the requested mode is the fixed server-owned maximum `0700`, never caller
   input;
5. after the successful `mkdirat`, the primitive does not reopen, chmod,
   stat, rename, or remove the final pathname;
6. success means the kernel atomically created an absent directory entry at the
   time of that syscall; it does not claim that another authorized namespace
   writer cannot rename or replace the entry afterward;
7. an existing file, directory, or symlink at the final name fails closed.

The primitive MUST NOT recursively create missing parents.

The no-post-create-pathname rule is intentional. `mkdirat` does not return an
fd for the newly created directory. Reopening the final name to verify or chmod
it would create a new pathname race and could operate on a replacement object.

## 7. Regular-file create primitive

The initial file-write primitive is create-only and atomically publishes a
fully written new file.

Preferred Linux sequence:

1. pin the destination parent directory;
2. create an unnamed regular inode in that same filesystem with
   `O_TMPFILE|O_WRONLY|O_CLOEXEC`;
3. write exactly the bounded request body;
4. verify the body length matches the declared content length;
5. fsync the file;
6. verify regular-file type and server-owned mode;
7. publish the inode into the final name only if that name is absent;
8. fsync the parent directory.

The publish step MUST be create-if-absent. It MUST NOT replace an existing
entry.

Failures before the publish syscall MUST leave no final pathname. Publication
is the namespace commit point. After publication, the implementation MUST NOT
blindly unlink the final pathname on a later failure because another authorized
namespace writer may already have replaced that directory entry.

A parent-directory fsync failure after successful publication is therefore a
distinct committed-but-durability-uncertain outcome. The primitive reports that
state separately from a pre-publication failure, and callers must not blindly
retry it as though no object was created. The SMCP v1 `fs_write` wire contract
maps this state to dedicated SSH status 74 plus one fixed host-owned diagnostic
which explicitly says the write committed, durability is uncertain, and blind
retry is prohibited. Status 74 is reserved for this `fs_write` outcome and is
not a child-process exit status.

If the target filesystem, kernel, Python runtime, or `/proc/self/fd` linking
path cannot safely publish the unnamed inode without extra ambient privilege,
the primitive fails closed before publication. There is no named-temp fallback
in the security contract.

## 8. Write request framing

The create-only `fs_write` SMCP request carries metadata only for:

- version;
- request ID;
- profile;
- operation;
- path;
- declared content length.

The file bytes are the bounded application body.

Rules:

- declared content length is a strict non-negative integer;
- it must not exceed the server-owned `max_write_bytes`;
- the host agent reads no more than the authorized bound plus one byte;
- early EOF and excess bytes both fail;
- object creation/publish does not begin until metadata authorization succeeds;
- overwrite semantics are not represented in this request version.

## 9. mkdir request framing

A future `fs_mkdir` request is metadata-only:

- version;
- request ID;
- profile;
- operation;
- path.

Any trailing application body is a protocol error before mutation begins.

## 10. Error and output model

Successful create-only mutations return SSH exit status 0 and no stdout body.

Policy denial returns the existing generic filesystem denial.

Pre-publication kernel/object/primitive failures return the generic
filesystem-operation failure. A post-publication parent-fsync failure returns
dedicated `fs_write` status 74 and the fixed diagnostic
`filesystem write committed; durability uncertain; do not retry blindly`.
The SSH peer must not receive:

- configured mutation roots;
- temp inode details;
- inode/device identifiers used internally;
- raw errno text which reveals unrelated filesystem state.

Audit logging may retain structured internal reasons when the audit phase is
implemented.

## 11. OS authority

OS DAC/ACL/MAC remains authoritative.

The host agent does not gain root, `CAP_DAC_OVERRIDE`,
`CAP_FOWNER`, or another mutation capability merely to make an operation
succeed.

A policy allow with insufficient OS permission is an operation failure, not a
reason to widen the host-agent privilege domain.

## 12. Required adversarial tests

Before create-only mutation is remotely reachable, tests MUST cover:

- intermediate symlink rejection;
- final existing symlink/file/directory denial;
- sibling-prefix root escape denial;
- caller mode/owner fields rejected as extra metadata;
- missing-parent denial;
- body overrun and underrun for file creation;
- no object creation before policy authorization;
- no object creation before complete authorized write body is accepted;
- create-if-absent behavior under destination collision;
- special filesystem / unsupported `O_TMPFILE` path fails closed;
- no shell, PATH lookup, containment-manager, or privileged-helper path;
- bounded output/error behavior.

## 13. Implementation order

Implement in separate reviewable slices:

1. `fs_mkdir` internal create-only primitive;
2. mkdir-specific host policy and SMCP wire operation;
3. `fs_write` create-only unnamed-inode primitive;
4. write-create host policy and SMCP wire operation;
5. real Linux adversarial validation for creation races and unsupported
   filesystem behavior;
6. reassess overwrite/move/delete only after a separate namespace-mutation
   authority design is accepted.

No later step may weaken an earlier fail-closed assertion merely to support a
filesystem which lacks the required kernel behavior.
