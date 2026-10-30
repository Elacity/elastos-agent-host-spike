# Adversarial review r5 of PR #290 (M1 check A9)

Draft only. Do not merge. This folder does not edit `lab/owned-storage/`.

```text
Lane:         lab/review-a9-290-r5
Branch / PR:  cursor/review-a9-290-r5-9855  https://github.com/Elacity/elastos-agent-host-spike/pull/423
Reviewed:     Elacity/elastos-agent-host-spike#290
Head:         78bc82bfb38047f9b8c367213bd06604e85a98cd
Tree:         /tmp/pr-290-r5 (detached, not pushed)
Base of #290: spike/agent-host merge-base b5069b992dac29d1457576efabd5700e34ea05e7
This branch:  origin/spike/agent-host a165fb8d
Machine:      Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), kernel 6.12.94+, no KVM
elastos:      not on PATH
```

## A9 wording used here

> another agent's files are denied

Anders's counting rule: a check counts only when its complete journey as
worded passes, with a refusal that carries a reason plus a CAUGHT falsifier,
and the required reviews. Lab evidence for a Runtime-side property stays
evidence until the Runtime half passes.

Round 4 (draft #411) at `c411060d` FALSIFIED a stale `(dev, ino)` after
unlink. The r4 fix at this head binds each entry to owner, exact relative
path, ctime, birth time, and a 16-byte `user.owned-storage.nonce`. This
round reviews that fix.

## Verdict

**A9 is not bookable. Lab half: FIX.**

The author's r4 journeys hold on this machine. Official counts match:
25/0/0 tests, 12/12 plants, 14/14 official mutants, race `escaped=0`,
bind-mount CAUGHT. SHA-256 of `lib.rs` / `walk.rs` / `launch.rs` match
`reports/A9-r4-fix.md`. Runtime rows stay `Blocked`. Nothing claims A9
is booked.

The new record is still a text file parsed with `split_whitespace`. Two
Store journeys returned another principal's bytes:

1. `newline-inject-owned` **SURVIVED**. `Store::write` accepts a filename
   that contains a newline and a comment marker. `save_owned` writes that
   name into `{root}.owned`. The next lines become a second ownership
   row for B's `(dev, ino)` and stamp. A host rename of B's file to
   `A/stolen.txt` made `Store::read(&a, "stolen.txt")` return `from-b`.
2. `xattr-copy-host-plant` **SURVIVED**. After A unlinks, a host create
   at the same relative path reused the inode. Same-uid `lsetxattr`
   copied `user.owned-storage.nonce`. `ctime`/`btime` collided
   (`ctime-collision` printed `same_time=true` for two Store creates).
   `Store::read(&a, "note.txt")` returned `planted`.

`host-rewrite-owned` also SURVIVED. That is the documented same-uid
write of the sibling record, not a new Store path. It still proves the
record is trusted host metadata.

The product journey is two Runtime agents. #290 starts no component.
Both Runtime rows stay `Blocked`, `executed=false`, `read_refusal=None`.
GitHub has no reviews on #290. The PR is draft.

## How this review ran

Detached worktree `/tmp/pr-290-r5` at `78bc82bf`. Official fmt, tests,
clippy rerun there. This folder's `probe.rs` links that crate and prints
`FINDING` lines. Official mutants plus extra r5 pins ran from
`mutants.py` and were restored. SHA-256 of the three sources matched the
author's r4-fix report before and after. `/tmp/elastos/storage` was
absent before and after. The #290 worktree stayed clean and was not
pushed. `Elacity/elastos-runtime` was not touched.

```text
lib.rs    sha256 76b4458f3f1fabeb632cbe85f66a9a991ecebf66104186c3e86ace464c00109a
walk.rs   sha256 4af2844f495a591606f801c740757ba95e06f3728d4351b109fa541a7b3a0b92
launch.rs sha256 d3ed87a9acfe22eab892fa13083a9ea6dabbdbbc37ac9501610f027a6c2c267c
```

## Exact official counts (this session)

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean, exit 0

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 25 tests, 0 benchmarks. No ignored names.

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --nocapture
# 25 passed; 0 failed; 0 ignored
# inode-reuse journey CAUGHT
# bind-mount unshare child: CAUGHT
# race two-store iters=5000 denied=4933 escaped=0
# NOT RUN: APFS case/Unicode (not a Mac)

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics
```

Author claim 25/0, 12/12 plants, 14/14 mutants, race 0 escapes, bind-mount
CAUGHT: **matches**, with one number different. Official race here was
`denied=4933` (author printed `denied=4906`). `escaped=0` on both.

The 25 names this session listed:

```text
launch::tests::real_runtime_rows_match_the_launcher
tests::agent_a_is_denied_b_directly
tests::agent_a_is_denied_b_list_and_rename
tests::agent_a_is_denied_b_through_a_parent_path
tests::agent_a_is_denied_b_through_a_symlink
tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink
tests::agent_a_lists_and_renames_its_own_storage
tests::agent_a_reads_and_writes_its_own_storage
tests::agent_b_is_denied_a_hard_linked_inode
tests::agent_b_is_denied_a_hard_linked_inode_after_a_unlinks
tests::apfs_case_and_unicode_not_run_off_macos
tests::bind_mount_of_another_agent_tree_is_refused
tests::cleanup_leaves_nothing_behind
tests::host_rename_into_b_is_refused
tests::host_rename_within_a_is_refused
tests::host_same_uid_walk_needs_confinement_or_runtime
tests::inode_reuse_after_unlink_is_refused
tests::intermediate_dir_swap_write_leaves_nothing_in_b
tests::last_component_nofollow_is_required
tests::live_walk_flags_are_pinned
tests::owned_root_uses_a5_usersai_agent_rest_shape
tests::ownership_record_is_on_disk_and_shared
tests::planted_shared_root_is_caught
tests::shared_temp_directory_is_refused
tests::two_yards_link_unlink_is_refused
```

`planted_shared_root_is_caught` applies the twelve official plants and
requires a `FAILED` line from each named test. That is the 12/12 plant
count.

## r1–r4 attacks replanted here

| Attack | What this session did | Verdict |
| --- | --- | --- |
| r1 Store API | `CrossAgent` / `Traversal` / `Symlink` | CAUGHT |
| r2 hard-link then unlink | `nlink=1`; `read`/`write` `HardLink` | CAUGHT |
| r3 host-rename host-created | `read` `HardLink` | CAUGHT |
| r3 bind-mount | `unshare -Urm`; `list=HardLink`, `write=CrossMount`, `planted_in_a=false` | CAUGHT |
| r4 inode reuse + host rename to `stolen.txt` | reused `new-0.txt`; `read` `HardLink` | CAUGHT |
| r4 host rename inside A | `moved` `HardLink`; old name `NotFound`; list empty of `moved.txt` | CAUGHT |

Verdict words: **CAUGHT** = the Store refused foreign bytes. **SURVIVED**
= the Store returned another agent's bytes, or the hunt granted. **NOT RUN**
= this machine could not exercise the hunt.

## Ownership record (this round's hunt)

The record is still `{agent_root}.owned`, a sibling, mode `0644`, now
`# owned-storage v2` plus
`dev ino owner path ctime_sec ctime_nsec btime_sec btime_nsec noncehex`.
Load uses `split_whitespace`. Lines that start with `#` are skipped.
`save_owned` is `fs::write` of the whole file, no temp+rename, no
`flock`, no `O_NOFOLLOW`. Directories compare only the nonce. Files
compare the full stamp. Same-uid `lsetxattr` can set
`user.owned-storage.nonce`.

| ID | Hunt | Verdict | What this session did |
| --- | --- | --- | --- |
| xattr-copy-reuse | B copies A's leftover nonce onto a reused inode; host rename to `stolen.txt` | CAUGHT | Path bind still refuses (`HardLink`). `setxattr` succeeded. |
| xattr-set-own-inode | B sets A's nonce on B's own file | CAUGHT | B's next `read` is `HardLink` (stamp no longer matches B's record). A's `read` of B is `CrossAgent`. Same-uid **can** set the xattr. |
| xattr-copy-host-plant | Host replaces A's `note.txt`, copies leftover nonce onto the reused inode | **SURVIVED** | `read=Ok(planted)`. Path matches. Inode reused. `ctime-collision` showed `same_time=true` on this kernel, so the copied nonce is the only unique field. |
| newline-inject-owned | `Store::write` of a newline name forges a second `.owned` line | **SURVIVED** | `write=Ok`, host rename `Ok`, `read=Ok(from-b)`, `owned_has_stolen=true`, `owned_lines=5`. |
| space-path-parse | Filename with a space | CAUGHT as a grant; WEAK as DoS | `write("my file.txt")` is `Ok`. Later `read("keep.txt")` is `OutsideRoot` because the record no longer parses. B's secret stays `b-secret`. |
| partial-owned-file | Truncate `.owned` in half | CAUGHT | `read`/`write` `OutsideRoot`. Fail closed. |
| crash-orphan | Host-created file, no record | CAUGHT | `write`/`read` `HardLink`. |
| concurrent-create-unlink | Host rewrites `.owned` during 400 Store writes | CAUGHT as a grant; WEAK leftover | `ok=400`, `denied=0`, `granted_foreign=0`, later `stable` `HardLink`. `fs::write` is not atomic. No `flock`. Lost update fails closed. |
| rename-across-agents | Store rename A↔B; host rename A into B | CAUGHT | Store paths `CrossAgent`. Host-moved file `HardLink` on B. |
| host-hardlink-then-unlink | Host hard link inside A; Store unlink | CAUGHT | `nlink>1` refuses both names. Store unlink itself is `HardLink`, so forget was not reached. No grant. |
| dir-nonce-only | Reuse a directory inode; copy nonce; host rename into A | NOT RUN | Directory inode not reused in 15s. Code still compares only the nonce for dirs. |
| host-rewrite-owned | Same-uid host writes A's `.owned` with B's stamp; host rename | **SURVIVED** | `read=Ok(from-b)`. Documented `NEEDS CONFINEMENT/RUNTIME`. The sibling is mode `0644`. |
| ctime-collision | Two Store creates | CAUGHT on nonce; WEAK on times | `same_time=true`, `same_nonce=false`. Times are not a generation. |
| owned-symlink-follow | Host replaces A's `.owned` with a symlink to B's record | CAUGHT as a grant | A's `read` of `note.txt` is `HardLink`. Load/save still follow the symlink. Unpinned. |
| tmpfs-xattr | Store on tmpfs | CAUGHT | User xattr works. `write`/`read` own bytes. Nonce present. |
| ramfs-no-xattr | Store on ramfs (no user xattr) | CAUGHT | `bind`/`write` never ran (`write=None`). Fail closed. Did not skip the stamp. |
| overlay-xattr | Store on overlayfs | CAUGHT | Own `write`/`read` work. Lower-layer `pre.txt` is `NotFound` (outside the instance dir). |
| fat-xattr | vfat / FAT | NOT RUN | `mkfs.vfat` / `mkfs.fat` absent. |
| r3-bind-mount | Bind-mount replay | CAUGHT | See table above. |
| runtime-rows | Blocked / not booked | CAUGHT | `executed=false`, `read_refusal=None`, both rows `BLOCKED AC-006-STORAGE`. |
| a9-not-booked | Source text | CAUGHT | `lib.rs` does not say A9 is booked. |
| host-same-uid | Sibling walk | CAUGHT as documented | `fs::read` from B's process returns `hello-a`. |

## Exact repro: newline-inject-owned (SURVIVED)

Against `lab/owned-storage` at `78bc82bf`:

1. `Store::open` a parent. Bind `agent-a` / `session-a` and `agent-b` / `session-b`.
2. `store.write(&b, "secret.txt", b"from-b")`.
3. `statx` + `lgetxattr(user.owned-storage.nonce)` on B's host file. That is
   `(dev, ino, ctime_sec, ctime_nsec, btime_sec, btime_nsec, nonce)`.
4. `store.write(&a, crafted, b"inject")` where `crafted` is exactly:

```text
x 0 0 0 0 00000000000000000000000000000000
<dev> <ino> agent-a stolen.txt <ctime_sec> <ctime_nsec> <btime_sec> <btime_nsec> <32 hex nonce>
#
```

   (`save_owned` appends this file's own stamp after `path`. The trailing
   `#` turns that leftover into a comment.)
5. Host `rename` B's `secret.txt` to `A/stolen.txt`.
6. `store.read(&a, "stolen.txt")` returns `Ok(b"from-b")`.

This session: `write=Ok(())`, `renamed=Ok(())`, `read=Ok([102, 114, 111, 109, 45, 98])`,
`owned_has_stolen=true`, `owned_lines=5`.

## Exact repro: xattr-copy-host-plant (SURVIVED)

1. `store.write(&a, "note.txt", b"hello-a")`.
2. Read `user.owned-storage.nonce` from that host file.
3. Host `unlink` `note.txt`. A's `{root}.owned` still has the line
   (host unlink does not forget).
4. Host `write` `note.txt` with `planted`. This kernel reused the inode
   on the first create.
5. `lsetxattr` the leftover nonce onto the new file. Same-uid is enough.
6. `store.read(&a, "note.txt")` returns `Ok(b"planted")`.

`ctime-collision` on the same run printed `same_time=true` for two
Store-created files, so the copied nonce is enough when the path and
`(dev, ino)` also match. The official r4 test still CAUGHT because B's
Store create writes a **new** nonce and, in the stolen-name half, the
path differs.

## Bookability under Anders's rule

| Gate | Lab half | Full A9 |
| --- | --- | --- |
| Complete journey as worded | No. Named r4 Store paths pass. A newline name forges a grant. A copied nonce on a reused inode at the same path grants. | No. Two Runtime agents never ran. |
| Refusal that carries a reason | Yes, for the named Store paths. Runtime row empty. | No captured Runtime reason. |
| CAUGHT falsifier | Official plants CAUGHT. The two survivors are not official plants. | No live Runtime plant. |
| Required reviews | None on #290 (`reviews: []`). Draft. | None. |

## Extra mutants

Official 14/14 caught (see `mutants-run.json`). Extra 6 mutants, 14 rows:
0 caught, 14 surviving. Official tests do not pin these.

| ID | Change | Official tests | Result |
| --- | --- | --- | --- |
| M-r5-owned-inside | record path becomes `root.join(".owned")` | on-disk record; host-rename; inode-reuse | **survives** all three |
| M-r5-parse-skip | bad lines are skipped | on-disk record; host-rename | **survives** both |
| M-r5-xattr-skip | `fsetxattr` errors are ignored | inode-reuse; own read/write | **survives** both |
| M-r5-dir-full-stamp | directories compare the full stamp | list/rename; inode-reuse | **survives** both (tightening, not a hole) |
| M-r5-no-lock | `load_owned` drops the mutex | on-disk record; race | **survives** both |
| M-r5-save-append | append the file instead of replace | on-disk record; host-rename; own read/write | **survives** all three |

The live record path, fail-closed parse, xattr write, the lock, and
atomic save are not pinned. The two SURVIVED journeys have no official
plant.

## RUNTIME-ASK.md

`lab/a9/RUNTIME-ASK.md` already names inode reuse and the generation
stamp. It does not name a text-format `.owned` line that can be forged
from a Store filename, or that `user.owned-storage.nonce` is a same-uid
writable xattr whose copy defeats the stamp when ctime collides.

One sentence is enough for Anders. Do not grow the ask past that. Do
not copy a patch into `Elacity/elastos-runtime`.

## Runtime rows

Honestly blocked. This session did not start `elastos`.

- `real_runtime_each_instance_has_its_own_storage_root`: `Blocked`,
  `BLOCKED AC-006-STORAGE: elastos run calls create_runtime("/tmp/elastos/storage")`.
- `real_runtime_agent_a_read_of_b_is_refused`: `Blocked`,
  `BLOCKED AC-006-STORAGE: agent file reads do not use that storage provider`.
- `executed=false`, `read_refusal=None`.

## What stays NOT RUN

- APFS case-fold and Unicode normalization (not a Mac).
- vfat / FAT user xattr (`mkfs.vfat` absent).
- Directory inode reuse + nonce copy (`dir-nonce-only` did not reuse in 15s).
- Two live Runtime agents.

## Ranked fix list

1. Keep A9 unbooked. Keep the title and body as lab only.
2. Refuse a storage name that contains whitespace, newline, or `#`.
   Encode the record so a path cannot become another line. Pin with a
   test that writes the crafted name above and fails if
   `read(&a, "stolen.txt")` returns B's bytes.
3. Treat `user.owned-storage.nonce` as untrusted host metadata, or stop
   using a same-uid-writable xattr as the only unique generation field.
   `ctime`/`btime` collided on this kernel. Pin with the host-plant
   journey (unlink, recreate at the same path, copy the leftover nonce).
4. Open the record with `O_NOFOLLOW`. Write with temp+rename and a lock.
   Cap it. Forget host-unlinked names or accept that host unlink plus
   reuse is in scope.
5. Leave Runtime rows blocked until a live component refusal exists.

## Principles

- 3 No ambient authority: Store I/O stays on the grant's root fd. A
  filename that writes a second ownership line is Store authority the
  agent did not earn on B's inode.
- 11 Fail closed, then explain: truncate and a bad line refuse. A
  well-formed injected line grants. A copied nonce on a reused inode at
  the same path grants.
- 12 Docs, code, tests agree: Runtime rows stay blocked. Official tests
  do not fail when a newline name forges a row or when the nonce is
  copied after reuse.
- 18 Isolated execution: lab directories are separate. The host process
  is not. The xattr is not.

DeepSeek: none.

Questions: security finding for Sasha, shipping `LocalMutableStorage`
still opens a string path after a check. If the lab record is copied as
written, a Store filename can forge a grant, and a same-uid xattr copy
can replay a reused inode at the same path. Details stay in this file.
Do not copy a patch into Elacity/elastos-runtime from this spike.
