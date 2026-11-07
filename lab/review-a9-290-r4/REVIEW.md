# Adversarial review r4 of PR #290 (M1 check A9)

Draft only. Do not merge. This folder does not edit `lab/owned-storage/`.

```text
Lane:         lab/review-a9-290-r4
Branch / PR:  cursor/review-a9-290-r4-9bcb  https://github.com/Elacity/elastos-agent-host-spike/pull/411
Reviewed:     Elacity/elastos-agent-host-spike#290
Head:         c411060d8c86db853fae352dd20d56da019c9d26
Tested code:  9e0f28552c9862b7c02a92467caaa746217a6c2b (ancestor; later commit only edits A9-r3-fix.md)
Tree:         /tmp/pr-290-r4 (detached, not pushed)
Base of #290: spike/agent-host merge-base b5069b992dac29d1457576efabd5700e34ea05e7
This branch:  origin/spike/agent-host 1d9b6656 Merge pull request #406
Machine:      Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), kernel 6.12.94+, no KVM
elastos:      not on PATH
```

## A9 wording used here

> another agent's files are denied

Anders's counting rule: a check counts only when its complete journey as
worded passes, with a refusal that carries a reason plus a CAUGHT falsifier,
and the required reviews. Lab evidence for a Runtime-side property stays
evidence until the Runtime half passes.

Round 1 (`lab/review-a9-290`, draft #336) at `c0b16491` found A9 not
bookable. Round 2 (`lab/review-a9-290-r2`, draft #390) at `2e5c3729`
FALSIFIED hard-link then unlink, an intermediate-directory TOCTOU, and a
surviving `M-no-nofollow`. Round 3 (`lab/review-a9-290-r3`, draft #401) at
`8d4d5010` FALSIFIED host-rename of a host-created file, two Store yards
after link+unlink, and bind-mount list/write. This round reviews the
claimed r3 fix at `9e0f2855` / head `c411060d`.

## Verdict

**A9 is not bookable. Lab half: FIX.**

The three r3 Store holes the author named are closed on the journeys they
tested. A host rename of a host-created file into B is `HardLink`. Two
Store yards after hard-link then unlink are `HardLink`. A bind-mount of
A's tree at `B/sub` is `CrossMount` / `HardLink`, with no file planted in
A. Official plants are 10/10. Official mutants are 12/12. The official
5000-iteration two-Store race left 0 files in B. This session's
20 000-iteration / 4-thread race also left 0 files in B.

The new ownership record is the trusted list. It lives beside the agent
root as `{root}.owned`, mode `0644`. Store paths cannot write that sibling
(`..` is `Traversal`, an absolute path is `OutsideRoot`). Truncation and
a bad line fail closed. A file that exists but is missing from the record
is refused.

The record never forgets. After A deletes a file, that `(dev, ino)` stays
on disk. B's next Store create reused the same pair on the first try
(`ok=1 reused=1`). A host rename of B's new file into A then made
`Store::read(&a, "stolen.txt")` return `from-b`. That is another agent's
bytes through the Store. Positive ownership as worded does not hold once
the kernel reuses an inode.

The product journey is two Runtime agents. #290 starts no component. Both
Runtime rows stay `Blocked`, `executed=false`, `read_refusal=None`. GitHub
has no reviews on #290. The PR is draft.

## How this review ran

Detached worktree `/tmp/pr-290-r4` at `c411060d`. Official fmt, tests,
clippy, and `r2-mutants.py` rerun there. This folder's `probe.rs` links
that crate and prints `FINDING` lines. Ten extra ownership mutants were
applied here and restored. SHA-256 of `lib.rs` / `walk.rs` / `launch.rs`
matched the author's r3-fix report before and after. `/tmp/elastos/storage`
was absent before and after. The #290 worktree stayed clean and was not
pushed. `Elacity/elastos-runtime` was not touched.

First `--offline` run on this VM had an empty crates cache (`rustix`
missing). `cargo fetch --locked` in the detached crate filled it. The
counts below are the second run, still `--locked --offline`.

```text
lib.rs    sha256 82b79350ae0cb7cac7b8b310ca188d29d4ea57f0d0d8a2710c3ee265dc6e8cd5
walk.rs   sha256 12577ada20a9edfcab5a149a9139e383237c5e27e445afdd00c418facdb5bc54
launch.rs sha256 d3ed87a9acfe22eab892fa13083a9ea6dabbdbbc37ac9501610f027a6c2c267c
```

## Exact official counts (this session)

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean, exit 0

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 23 tests, 0 benchmarks. No ignored names.

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --nocapture
# 23 passed; 0 failed; 0 ignored
# bind-mount unshare child: CAUGHT
# race two-store iters=5000 denied=4963 escaped=0
# NOT RUN: APFS case/Unicode (not a Mac)

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics

python3 -I lab/owned-storage/r2-mutants.py
# mutants=12 caught=12 surviving=0
```

Author claim 23/0, 10/10 plants, 12/12 mutants, race 0 escapes, bind-mount
CAUGHT: **matches**, with one number different. Official race here was
`denied=4963` (author printed `denied=4999`). `escaped=0` on both.

The 23 names this session listed:

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
tests::host_same_uid_walk_needs_confinement_or_runtime
tests::intermediate_dir_swap_write_leaves_nothing_in_b
tests::live_walk_flags_are_pinned
tests::owned_root_uses_a5_usersai_agent_rest_shape
tests::ownership_record_is_on_disk_and_shared
tests::planted_shared_root_is_caught
tests::shared_temp_directory_is_refused
tests::two_yards_link_unlink_is_refused
```

`planted_shared_root_is_caught` applies the ten official plants and
requires a `FAILED` line from each named test. That is the 10/10 plant
count.

## r1–r3 attacks replanted here

| Attack | What this session did | Verdict |
| --- | --- | --- |
| r1 Store API (foreign path, `..`, symlink, list, rename) | `CrossAgent` / `Traversal` / `Symlink`; own list is `note.txt` | HOLDS |
| r1 root-swap | `read`/`write` `Symlink`; B's bytes stay `b-secret` | HOLDS |
| r2 live hard link | `nlink=2`; `read`/`write` `HardLink` | HOLDS |
| r2 hard-link then unlink (one Store) | `nlink=1`; `read`/`write` `HardLink` | HOLDS |
| r2 intermediate-dir TOCTOU | 20 000 writes, 4 swapper threads | HOLDS (`escaped=0`, `ok=1`, `denied=19999`) |
| r3 host-rename Store-created | `nlink=1`; `read`/`write` `HardLink`; host bytes stay `hello-a` | HOLDS |
| r3 host-rename host-created | `nlink=1`; `read` `HardLink` | HOLDS |
| r3 two-yard link+unlink | `nlink=1`; `read` `HardLink` | HOLDS |
| r3 bind-mount | `unshare -Urm`; `list=HardLink`, `read=CrossMount`, `write=CrossMount`, `planted_in_a=false` | HOLDS |
| last-component symlink race | 4000 writes, 4-thread swapper | HOLDS (`truncated=0`) |
| `O_TMPFILE` + `linkat` in B | new inode; `read` `HardLink` | HOLDS |
| `linkat(AT_EMPTY_PATH)` of A's fd into B | `nlink=1`; `read` `HardLink` | HOLDS |
| rename leftover `create_dir_all` | only `bind()` still calls it (`lib.rs:194`); `Store::rename` uses `renameat` | HOLDS |
| host same-uid walk | `fs::read` of B's sibling path returns `hello-a` | HOLDS as documented hole |

Verdict words: **HOLDS** = the claim as worded stood. **FALSIFIED** = a
concrete run broke the claim. **WEAK** = leftover, unpinned, or the hunt
did not land a grant.

## Ownership record (this round's hunt)

The record is `{agent_root}.owned`, a sibling of the instance directory.
Example from this run:
`…/agent-a/session-a/1.owned` next to `…/agent-a/session-a/1/`.
It is not inside A's root or B's root. Mode `0644`. Format
`# owned-storage v1` then `dev ino` lines. `bind` records the root
directory. `write` of a new file records that file and each path
component. Load and save use `fs::read_to_string` / `fs::write` under a
process-wide `Mutex`. There is no `flock`, no temp+rename, no
`O_NOFOLLOW`, and no forget when a name is unlinked.

| ID | Hunt | Verdict | What this session did |
| --- | --- | --- | --- |
| ownership-location | Where the file lives; agent-reachable? | HOLDS | Sibling of the root, not inside either tree. Contains the file's `(dev, ino)`. |
| ownership-store-write | Can A or B Store-write the sibling? | HOLDS | `../1.owned` is `Traversal`. Absolute sibling path is `OutsideRoot` from both grants. `write(".owned")` creates `1/.owned` inside the root (a different file) and then `record_owned` rewrites the sibling with the new inode. The probe line printed `FALSIFIED` because those sibling bytes changed; that change is a new recorded inode, not user bytes in the sibling. |
| ownership-corrupt | Truncate / bad line | HOLDS | Empty file: `read` `HardLink`. Bad line / short line: `OutsideRoot`. A later `write` of a new name rebuilds the record from what load returned. Old names stay refused. |
| ownership-symlink-forge | Host replaces A's sibling with a symlink to a file B Store-writes | HOLDS as a grant | A's next `write` was `OutsideRoot` (load followed the symlink onto `starter` and failed the parse). B then wrote a well-formed record through `forge.txt`. A's `read` of a planted file stayed `OutsideRoot`. No grant this run. Load/save still follow symlinks. That is unpinned (`M-r4-owned-inside` survives). |
| inode-reuse-stale-grant | A unlinks; B's new file gets the same `(dev, ino)`; host rename into A | **FALSIFIED** | `old=(65056, 425544)`, `ok=1`, `reused=1` on `new-0.txt`. After `rename` into `A/stolen.txt`, `Store::read(&a, "stolen.txt")` returned `from-b`. |
| crash-create-before-record | File exists, not in the record | HOLDS | `write`/`read` of a host-created orphan are `HardLink`. Fail closed. The agent also cannot finish that name. |
| concurrent-lost-update | Host rewrites the sibling while two threads Store-write | WEAK | `ok=400`, `denied=0`, `unread_after=400`. Lost update fails closed. `fs::write` is not atomic. No file lock across processes. |
| record-growth | Delete never drops a line | WEAK | 64 writes, 32 host unlinks, `after_len=864`, `entries=65`. No cap. Leftover, not a grant by itself. It is why reuse stays in the set. |
| rename-within-b | Store rename of a B-owned file | HOLDS | Same inode, `read` still `hello-b`, old name `NotFound`. |
| overlay-btrfs-dev | overlayfs / btrfs `st_dev` | WEAK | `unshare -Urm` overlay mount worked. A Store-created file kept the same overlay `(dev, ino)` after an append (`same_pair=true`) and still read. The probe's `pre.txt` sat on the overlay parent, outside the agent root (`NotFound`), so it did not test a lower-layer file under the grant. No btrfs here. Remount/reboot `st_dev` change was not run; a new `st_dev` would fail closed. |
| case-unicode | APFS / macOS names | HOLDS on this ext4 kernel | `NOTE.TXT` is `NotFound`. NFD write and NFC read are different names. No APFS here. |

## Bookability under Anders's rule

| Gate | Lab half | Full A9 |
| --- | --- | --- |
| Complete journey as worded | No. Named r3 Store paths pass. A stale `(dev, ino)` after unlink plus a host rename of B's reused inode lets A Store-read B's bytes. | No. Two Runtime agents never ran. |
| Refusal that carries a reason | Yes, for the named Store paths (`HardLink`, `CrossMount`, `CrossAgent`). Runtime row empty. | No captured Runtime reason. |
| CAUGHT falsifier | Official plants CAUGHT. Inode reuse after unlink is not one of them. | No live Runtime plant. |
| Required reviews | None on #290 (`reviews: []`). Draft. | None. |

## Extra mutants (ten, ownership record)

Official 12/12 caught. Extra 10 mutants, 27 rows: 5 caught, 22 surviving.

| ID | Change | Official tests | Result |
| --- | --- | --- | --- |
| M-r4-record-noop | `record_owned` is a no-op | own read/write; on-disk record | **caught** |
| M-r4-read-skip-owned | `read` skips `require_owned` | host-rename; two-yards | **caught** |
| M-r4-bind-skip-root | `bind` does not record the root dir | list/rename | **caught** on list; on-disk record and host-uid **survive** |
| M-r4-owned-inside | record path becomes `root.join(".owned")` | on-disk record; host-rename; own read/write | **survives** all three |
| M-r4-empty-allows | empty set is a grant | host-rename; two-yards; on-disk record | **survives** |
| M-r4-parse-skip | bad lines are skipped | host-rename; on-disk record | **survives** |
| M-r4-ino-only | match `ino` only, ignore `dev` | host-rename; two-yards; walk flags | **survives** |
| M-r4-list-no-filter | `list` shows unowned names | own list; host-uid; host-rename | **survives** |
| M-r4-save-append | append the file instead of replace | on-disk record; host-rename; own read/write | **survives** |
| M-r4-no-lock | `load_owned` drops the mutex | on-disk record; race; two-yards | **survives** |

The live record path, `dev` in the pair, fail-closed parse, list filter,
atomic save, and the lock are not pinned.

## RUNTIME-ASK.md

`lab/a9/RUNTIME-ASK.md` is for Anders. It does not patch Runtime. The
four shipping holes it names are still the right ones, and the citations
still match the Runtime sources this spike vendors (same bytes on
`origin/spike/agent-host` and on the #290 tree):

- `resolve_path` joins `base_path` with the caller string
  (`elastos/crates/elastos-storage/src/mutable/local.rs:76`), then walks
  to an existing ancestor and `canonicalize`s it (`local.rs:88-107`).
  The function returns that joined string (`local.rs:109`).
- `write` calls `resolve_path`, then `create_dir_all(parent)`
  (`local.rs:142`), then `fs::write(&full_path, data)` (`local.rs:145`).
- `read` / `delete` / `rename` reuse the same resolved string
  (`local.rs:116`, `150`, `302-317`). `rename` also does
  `create_dir_all` on the destination parent (`local.rs:313`).
- There is no `fstat` of an opened fd, no `st_nlink` check, and no
  owner/inode set in that file.

`elastos run` still passes `/tmp/elastos/storage` three times in
`elastos/crates/elastos-server/src/run_cmd.rs` (lines 62, 70, 236) and
once in `share_cmd.rs:183`.

The ask is honest that lab rows stay lab and Runtime rows stay blocked.
It already names the r3 holes (second-store map, bind-mount /
`RESOLVE_NO_XDEV`, host-created rename) and says a per-store in-memory
map is not enough.

It does not yet name the hole this session landed: a persisted
`(st_dev, st_ino)` set that never forgets an unlinked inode will grant
after the kernel reuses that pair and the file appears under the grant
root. One sentence is enough. Do not grow the ask past that.

## Runtime rows

Honestly blocked. This session did not start `elastos`.

- `real_runtime_each_instance_has_its_own_storage_root`: `Blocked`,
  `BLOCKED AC-006-STORAGE: elastos run calls create_runtime("/tmp/elastos/storage")`.
- `real_runtime_agent_a_read_of_b_is_refused`: `Blocked`,
  `BLOCKED AC-006-STORAGE: agent file reads do not use that storage provider`.
- `executed=false`, `read_refusal=None`.

## What is lab-only

Per-instance directories under a private yard. Store `read` / `write` /
`list` / `rename` refusals for a foreign host path, a `..` segment, a
static outbound symlink, a swapped root, a live hard link, a
Store-created inode after unlink, a host-created file renamed in, a
second Store yard after link+unlink, a bind-mount under the root, and
`/tmp/elastos/storage`. Fd-relative walk with `RESOLVE_NO_XDEV`. Cleanup
and Drop. Ten plants. The tripwire that stays green while the four
constructors exist and the Runtime rows stay `Blocked`.

`lab/grant-binding` is a separate crate and still counts toward no M1
check.

## Ranked fix list

1. Keep A9 unbooked. Keep the title and body as lab only.
2. Close inode reuse. A recorded `(dev, ino)` that outlives the file is
   a grant when the kernel hands that pair to another agent's create and
   the file is then placed under the root. Forget, or name the file by
   more than a recycled pair. Pin it with a test that fails when the
   first reused inode becomes readable.
3. Pin the record path as a sibling outside the grant root.
   `M-r4-owned-inside` survives. `write(".owned")` already creates a
   file inside the root; if the record moves there, that write becomes
   the record.
4. Open the record with `O_NOFOLLOW` (or refuse a symlink). Load and
   save follow today.
5. Replace the record with a temp file plus `rename`, and lock it.
   `fs::write` plus a host rewrite dropped 400 new inodes this session
   (fail closed, not a grant).
6. Cap the file. Deleted lines stay forever.
7. Leave Runtime rows blocked until a live component refusal exists.
   Add one sentence to `RUNTIME-ASK.md` about inode reuse before Anders
   copies the lab record.

## Principles

- 3 No ambient authority: Store I/O stays on the grant's root fd. The
  ownership file is host metadata beside that fd. Same-uid host write of
  the sibling is the documented confinement hole. A recycled inode
  inside the fd is Store authority the agent did not create on this
  file.
- 11 Fail closed, then explain: corrupt and missing records refuse.
  A stale recorded pair grants.
- 12 Docs, code, tests agree: Runtime rows stay blocked. Official tests
  do not fail when the record moves inside the root or when `ino` is
  matched without `dev`.
- 18 Isolated execution: lab directories are separate. The host process
  is not. The on-disk pair is not a generation.

DeepSeek: none.

Questions: security finding for Sasha, shipping `LocalMutableStorage`
still opens a string path after a check (`local.rs:76-145`). The lab
record, if copied as written, grants after inode reuse. Details stay in
this file and in `lab/a9/RUNTIME-ASK.md`. Do not copy a patch into
Elacity/elastos-runtime from this spike.
