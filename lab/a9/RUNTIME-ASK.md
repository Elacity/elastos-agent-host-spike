# RUNTIME-ASK: per-capsule storage isolation (A9)

For Anders. Lab-only. This file does not patch Runtime.

The r2 holes on draft #290 (hard-link then unlink; intermediate-directory
TOCTOU; last-component `O_NOFOLLOW`) and the r3 holes (host-created
rename into B; two Store yards after link+unlink; bind-mount list/write)
live in the lab stand-in `lab/owned-storage` and are fixed there. The shipping store
`elastos/crates/elastos-storage/src/mutable/local.rs` still does the same
class of work over a string path. Do not treat the lab fix as a Runtime
fix. Runtime rows on A9 stay Blocked (`AC-006-STORAGE`).

## What the Runtime store does today

`LocalMutableStorage::resolve_path` joins `base_path` with the caller
string, then `canonicalize`s an ancestor. `write` then calls
`create_dir_all(parent)` and `fs::write(&full_path, data)` on that string.
`read` / `delete` / `rename` reuse the same resolved string. There is no
`fstat` of the opened fd, no `st_nlink` check, and no owner/inode set.

`elastos run` still passes every component `/tmp/elastos/storage`
(`run_cmd.rs` three times, `share_cmd.rs:183` a fourth). That is the
standing launcher blocker. Even after those four sites use a Home data
directory, two components that share a uid can still:

1. Hard-link A's file into B's tree, unlink A's name, and read A's bytes
   through `LocalMutableStorage::read` (`nlink` is then 1). Two store
   objects (one per capsule) do not share a created-inode map, so a
   per-store in-memory map does not close this.
2. Swap an intermediate directory for a symlink to B between
   `resolve_path` and `create_dir_all` / `fs::write`, so A's `write`
   creates a file in B's tree.
3. Bind-mount A's tree at a name under B. B's `list` shows A's names and
   B's `write` creates a file in A's tree. The string-path store has no
   `RESOLVE_NO_XDEV`.
4. Host-create a file in A and `rename` it into B (`nlink` stays 1). B's
   `read` returns A's bytes because the inode was never recorded.

## Minimal repro (lab shape, against Runtime store)

Use two base directories under one temp parent, same as the lab yard:

```text
A = LocalMutableStorage::new(tmp/agent-a)
B = LocalMutableStorage::new(tmp/agent-b)
A.write("note.txt", b"hello-a")
hard_link(tmp/agent-a/note.txt, tmp/agent-b/hard.txt)
remove_file(tmp/agent-a/note.txt)
B.read("hard.txt")            // today: Ok(b"hello-a")
B.write("hard.txt", b"from-b") // today: Ok, A's bytes gone
```

Race (5000 iterations, swapper thread on `tmp/agent-a/sub`):

```text
A.write("sub/race-N.txt", b"from-a")
```

Today some `Ok` results leave `tmp/agent-b/race-N.txt`.

## Exact fix needed in Runtime

In `elastos/crates/elastos-storage/src/mutable/local.rs` (and any other
store that opens by string after a check):

1. Open the capsule `base_path` once as a directory fd (`O_DIRECTORY |
   O_NOFOLLOW`). Keep that fd for the life of the store.
2. Resolve every path component fd-relative from that fd:
   `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`
   where the kernel accepts it, else per-component `openat` with
   `O_NOFOLLOW` (`O_DIRECTORY` on intermediate names) and `fstat`.
3. Never `create_dir_all` or `open` a string path after the check. Create
   intermediate directories with `mkdirat` on the parent fd, then
   `openat` that name.
4. After every open, `fstat` the fd. Refuse `st_nlink > 1`. Ownership is
   positive: a store may read, list, or write an existing file only when
   that file's `(st_dev, st_ino)` is in the agent's own on-disk record,
   written when that agent's store created the file. Persist the record
   with the agent root so it survives restart and is shared across store
   handles. A per-store in-memory inode map is not enough: two
   `LocalMutableStorage` values (one per capsule) each have an empty map,
   so a hard-link then unlink across two bases still returns A's bytes
   on B's `read` after `nlink` drops to 1. Host-created files renamed
   into B have `nlink` 1 and no record, and must be refused the same way.
   Do not expose `link` / `linkat`.
5. Last-component open must keep `O_NOFOLLOW` (or `RESOLVE_NO_SYMLINKS`).
   A unit test must fail when that flag is dropped. The test must mutate
   the live walk, not a dead helper.
6. Add `RESOLVE_NO_XDEV` to the walk. A bind-mount of another agent's
   tree under B (`unshare -Urm` then `mount --bind A B/sub`) must refuse
   list and write. Without `NO_XDEV`, B's `write("sub/planted.txt")`
   creates a file in A's tree.

Do not apply that patch from this spike. The public Runtime repo stays
untouched. RA-3 / AC-006-STORAGE still has to stop `elastos run` using
`/tmp/elastos/storage` and give each instance its own base. The fd walk
above is the isolation that base then needs.
