# Adversarial review r3 of PR #290 (M1 check A9)

Draft only. Do not merge. This folder does not edit `lab/owned-storage/`.

```text
Lane:         lab/review-a9-290-r3
Branch / PR:  cursor/review-a9-290-r3-e908
Reviewed:     Elacity/elastos-agent-host-spike#290
Head:         8d4d50104edcfd1eee03e4cd93816e7ed62b6088
Tested code:  578e0959a374af726bbc8f113afdbb5e7723636d (ancestor; later commit only edits A9-r2-fix.md)
Tree:         /tmp/pr-290-r3 (detached, not pushed)
Base of #290: spike/agent-host merge-base b5069b992dac29d1457576efabd5700e34ea05e7
This branch:  origin/spike/agent-host 215841921df50dd30327cc3f5ffe6ac4f811d066
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
FALSIFIED hard-link then unlink, an intermediate-directory TOCTOU
(4 escapes in 400 writes), and a surviving `M-no-nofollow`. This round
reviews the claimed fixes at `578e0959` / head `8d4d5010`.

## Verdict

**A9 is not bookable.**

The three r2 Store holes the author named are closed on the journeys they
tested. Same-Store `read`/`write` of a Store-created hard link after unlink
returns `Refuse::HardLink`. A 20 000-iteration intermediate-dir race with
four swapper threads left **0** files in B. Official `M-no-nofollow` is
caught by the new hook test.

The lab half still fails the wording. Agent B can read A's bytes through
the Store after a host `rename` of a file that A did not create through
`write` (`nlink` stays 1; the inode is missing from the created map). Two
`Store` instances have separate maps, so the r2 unlink hole returns across
yards. A bind mount of A's root at `B/sub` lets B `list` A's names and
`write` a file into A's tree. The live walk's `O_NOFOLLOW` /
`RESOLVE_NO_SYMLINKS` flags are what stop the r2 TOCTOU, and the official
nofollow plant does not touch those flags.

The product journey is two Runtime agents. #290 starts no component. Both
Runtime rows stay `Blocked`, `executed=false`, `read_refusal=None`. GitHub
has no reviews on #290. The PR is draft.

## How this review ran

Detached worktree `/tmp/pr-290-r3` at `8d4d5010`. Official fmt, tests,
clippy, and `r2-mutants.py` rerun there. This folder's `probe.rs` links
that crate and prints `FINDING` lines. Extra walk mutants and the six
official plants were applied here and restored. SHA-256 of `lib.rs` /
`walk.rs` / `launch.rs` matched before and after. `/tmp/elastos/storage`
was absent before and after. The #290 worktree stayed clean and was not
pushed.

```text
lib.rs    sha256 421aefc17dbbeff701dba066d09fe2e7d549fd5b988ce25c360c467decbffb03
walk.rs   sha256 4926d2229970f32c7933bbfdde67d0317a5fa16fddd81b7828350a8a653a8460
launch.rs sha256 d3ed87a9acfe22eab892fa13083a9ea6dabbdbbc37ac9501610f027a6c2c267c
```

## Exact official counts (this session)

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean, exit 0

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 17 tests, 0 benchmarks. No ignored names.

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
# 17 passed; 0 failed; 0 ignored
# launch::tests::real_runtime_rows_match_the_launcher
# tests::agent_a_is_denied_b_directly
# tests::agent_a_is_denied_b_list_and_rename
# tests::agent_a_is_denied_b_through_a_parent_path
# tests::agent_a_is_denied_b_through_a_symlink
# tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink
# tests::agent_a_lists_and_renames_its_own_storage
# tests::agent_a_reads_and_writes_its_own_storage
# tests::agent_b_is_denied_a_hard_linked_inode
# tests::agent_b_is_denied_a_hard_linked_inode_after_a_unlinks
# tests::cleanup_leaves_nothing_behind
# tests::host_same_uid_walk_needs_confinement_or_runtime
# tests::intermediate_dir_swap_write_leaves_nothing_in_b
# tests::last_component_nofollow_is_required
# tests::owned_root_uses_a5_usersai_agent_rest_shape
# tests::planted_shared_root_is_caught
# tests::shared_temp_directory_is_refused

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics

python3 -I lab/owned-storage/r2-mutants.py
# mutants=8 caught=8 surviving=0
```

Author claim 17/0/0, 6/6 plants, 8/8 mutants: **matches**. Author claim
5000-iteration race 0 escapes: **matches**, and this session's 20 000 /
4-thread race also left 0 files in B (`ok=235` `denied=19765` `escaped=0`).

## r2 attacks replanted here

| Attack | What this session did | Verdict |
| --- | --- | --- |
| Hard-link then unlink (Store-created, one Store) | `hard_link` + `remove_file`; `nlink=1`; `read`/`write` both `HardLink` | HOLDS |
| Intermediate-dir TOCTOU | 20 000 writes, 4 swapper threads | HOLDS (`escaped=0`) |
| Official `M-no-nofollow` / `F-A9-nofollow` | Drops `custom_flags(O_NOFOLLOW)` on dead `open_nofollow` | CAUGHT by `last_component_nofollow_is_required` |
| Live walk `O_NOFOLLOW` | `M-walk-nofollow` drops `.union(OFlags::NOFOLLOW)` in `walk.rs` | **Survives** official symlink, hook, and race tests (`openat2` still has `RESOLVE_NO_SYMLINKS`) |
| Live walk flags + fallback | Drop `NOFOLLOW`, drop `RESOLVE_NO_SYMLINKS`, force `openat` | Official symlink test still passes (`resolve()` refuses first). Official 5000-iter race **fails**: **320 files in B**, `denied=4463` |

The r2 survivor is closed only as a hook on unused `open_nofollow`
(`lib.rs:772-780`, used at `1056-1058`). Production I/O is `walk.rs`.
The flags in `walk.rs` are what stop the r2 TOCTOU. Official tests do
not fail when those flags are removed one at a time.

Independent plant replay (files restored; SHA-256 match after). Every
named test printed a `FAILED` line:

```text
F-A9-fake-runtime / launch::tests::real_runtime_rows_match_the_launcher  FAILED
F-A9-hardlink-unlink / tests::agent_b_is_denied_a_hard_linked_inode_after_a_unlinks  FAILED
F-A9-hardlink / tests::agent_b_is_denied_a_hard_linked_inode  FAILED
F-A9-nofollow / tests::last_component_nofollow_is_required  FAILED
F-A9-root-swap / tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink  FAILED
F-A9-share / tests::agent_a_is_denied_b_directly  FAILED
F-A9-share / tests::agent_a_is_denied_b_through_a_parent_path  FAILED
F-A9-share / tests::agent_a_is_denied_b_through_a_symlink  FAILED
F-A9-share / tests::agent_a_is_denied_b_list_and_rename  FAILED
```

## New hunts

| ID | Hunt | Verdict | What this session did |
| --- | --- | --- | --- |
| host-rename-store-created | Host `rename` of a Store-created A file into B (`nlink=1`) | HOLDS | `read`/`write` `HardLink`. Created-inode map still names A. Host bytes stay `hello-a`. |
| host-rename-host-created | Host `rename` of a host-created A file into B | **FALSIFIED** | `nlink=1`. `Store::read(&b, "from-a.txt")` returns `hello-a`. Inode was never recorded. |
| two-store-hardlink-unlink | Hard-link then unlink across two `Store` yards | **FALSIFIED** | Separate `created` maps. After unlink, `nlink=1`, B's `read` returns `hello-a`. |
| linkat-empty-path | `linkat(AT_EMPTY_PATH)` of A's fd into B, then unlink A | HOLDS | Same Store, Store-created inode: `HardLink`. |
| otmpfile-linkat-new | `O_TMPFILE` + `linkat` in B | HOLDS | New inode. B reads `tmp-bytes`. This is B's own file, not A's inode. |
| bind-dir-mount | Bind-mount A's root at `B/sub` (`unshare -Urm`) | **FALSIFIED** | `list("sub")` is `Ok(["note.txt"])`. `read("sub/note.txt")` is `HardLink`. `write("sub/planted.txt")` is `Ok` and `A/planted.txt` exists. Walk has no `RESOLVE_NO_XDEV`. Needs a mount (user ns here). |
| fallback | `openat2` `ENOSYS`/`EINVAL` path | HOLDS as fd-relative; WEAK as a pin | `walk.rs:180-181` and `61-75` fall back to `openat` with the same `OFlags` (including `O_NOFOLLOW`). This is not a string-path fallback. It is silent. It drops `RESOLVE_BENEATH` / `NO_SYMLINKS` / `NO_MAGICLINKS`. Comment at `walk.rs:7` says fallback does `fstat`; `walk.rs` has no `fstat`. `file.metadata()` lives in `lib.rs` after return. No official test forces the fallback. Forced-fallback official symlink and race still pass (flags kept). |
| dir-fd-leak | Directory fd given to a capsule | HOLDS | `Grant` has no fd. `walk` is `pub(crate)`. `host_root()` still returns a live path. No capsule runs. |
| inode-reuse / persistence | Created map across delete and restart | WEAK | Map is `Mutex<HashMap>` on the `Store`, cleared on `cleanup`. After host unlink of A's file, one of 64 B writes returned `HardLink` (stale owner). Reuse of the old inode number was not observed. Map is gone on a new `Store` (the two-store row is the leak). |
| case-unicode | APFS case-fold and Unicode normalization | HOLDS on this ext4 kernel; unproven on macOS | `NOTE.TXT` is `NotFound`. `Agent-A` binds as a different principal. NFD write and NFC read are different names. No APFS here. |
| last-component-symlink | Symlink created on the last name after check | HOLDS | 4000 writes, 4-thread swapper, 0 truncations of B (`ok_real=37` `denied=3963`). Live walk uses `O_NOFOLLOW` / `RESOLVE_NO_SYMLINKS`. |
| xattr-acl | xattrs / ACLs | HOLDS for Store bytes | `setxattr user.secret=hidden` succeeded. `Store::read` returned `hello-a` only. Host `getxattr` returned `hidden`. B's Store read of A's path stays `CrossAgent`. Same-uid host can still read xattrs (documented host hole). |
| rename-create-dir-all | `Store::rename` string `create_dir_all` | WEAK | `lib.rs:326` still calls `fs::create_dir_all(parent)` after `resolve`. 2000-iteration swap: 0 files in B, `B/deep` appeared 43 times. Leftover string path. |

Verdict words: **HOLDS** = the claim as worded stood. **FALSIFIED** = a
concrete run broke the claim. **WEAK** = leftover, unpinned, or the race
did not land a file.

## Bookability under Anders's rule

| Gate | Lab half | Full A9 |
| --- | --- | --- |
| Complete journey as worded | No. Named r2 Store paths pass. Host-created rename, two-Store unlink, and bind-mount list/write do not. | No. Two Runtime agents never ran. |
| Refusal that carries a reason | Yes, for the named Store paths. Runtime row empty. | No captured Runtime reason. |
| CAUGHT falsifier | Official plants CAUGHT. Live walk `O_NOFOLLOW` is not one of them. | No live Runtime plant. |
| Required reviews | None on #290 (`reviews: []`). Draft. | None. |

## RUNTIME-ASK.md

`lab/a9/RUNTIME-ASK.md` is for Anders. It does not patch Runtime. The
repro is sound and minimal for the hard-link-then-unlink shape: two
bases, `write`, `hard_link`, `unlink`, `read`. This session's Python
mirror of that sequence returned `b'hello-a'` on B's read, then B's
write replaced the bytes. A deterministic swap after resolve, then
`mkdir` + write, put **400/400** files in B. That is the class of hole
the ask attributes to `LocalMutableStorage`.

The claim about shipping `LocalMutableStorage` is supported by the
Runtime source this spike vendors (same bytes on current
`origin/spike/agent-host`):

- `resolve_path` joins `base_path` with the caller string
  (`elastos/crates/elastos-storage/src/mutable/local.rs:76`), then walks
  to an existing ancestor and `canonicalize`s it (`local.rs:88-107`).
  The function returns that joined string, not an fd (`local.rs:109`).
- `write` calls `resolve_path`, then `create_dir_all(parent)`
  (`local.rs:141-142`), then `fs::write(&full_path, data)`
  (`local.rs:145`).
- `read` / `delete` / `rename` reuse the same resolved string
  (`local.rs:116`, `150`, `302-317`). `rename` also does
  `create_dir_all` on the destination parent (`local.rs:312-313`).
- There is no `fstat` of an opened fd, no `st_nlink` check, and no
  owner/inode set in that file.

`elastos run` still passes `/tmp/elastos/storage` three times in
`elastos/crates/elastos-server/src/run_cmd.rs` (lines 62, 70, 236) and
once in `share_cmd.rs:183`. Those four sites are still on current
`origin/spike/agent-host`.

The ask's proposed Runtime fix (root dir fd, `openat2` or per-component
`openat` + `O_NOFOLLOW`, created-inode map, last-component `O_NOFOLLOW`
test) matches the lab patch. Two gaps in that list, from this session:

1. A per-store inode map does not see another store's creates. Two
   `Store` yards in one process already leak after unlink. Shipping one
   `LocalMutableStorage` per capsule has the same shape.
2. `RESOLVE_NO_XDEV` is absent. A bind mount under the root is a Store
   list/write path into the other tree.

The ask is honest that lab rows stay lab and Runtime rows stay blocked.

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
Store-created inode after unlink **in the same Store**, and
`/tmp/elastos/storage`. Fd-relative walk for those I/O paths. Cleanup
and Drop. Six plants. The tripwire that stays green while the four
constructors exist and the Runtime rows stay `Blocked`.

`lab/grant-binding` is a separate crate and still counts toward no M1
check.

## Ranked fix list

1. Keep A9 unbooked. Keep the title and body as lab only.
2. Record every inode that appears under a grant's root, not only inodes
   created through `write`. Host-created files and files introduced by
   `rename` / `linkat` must take an owner. Refuse a foreign owner after
   `nlink` drops to 1.
3. Treat the created map as per-process / per-device, or persist it with
   the yard. A second `Store` (or a Runtime process per capsule) must
   not re-open the r2 unlink hole.
4. Pin the live walk: a test that fails when `walk.rs` drops
   `O_NOFOLLOW` or `RESOLVE_NO_SYMLINKS`, including on the `openat`
   fallback. Retire or retarget `open_nofollow` so the plant hits
   production I/O.
5. Decide the mount policy. `RESOLVE_NO_XDEV` stops bind-mount list and
   write into another tree. Say so if same-uid mount stays
   `NEEDS CONFINEMENT`.
6. Remove `fs::create_dir_all` from `Store::rename` (`lib.rs:326`).
   Intermediate dirs already go through `mkdirat` in `walk.rs`.
7. Forget or transfer a created-inode entry when the last name in this
   yard is unlinked, so a reused inode number is not a false `HardLink`.
8. Leave Runtime rows blocked until a live component refusal exists.
   `RUNTIME-ASK.md` already names the string-path store. Add the
   two-store map gap and `RESOLVE_NO_XDEV` before Anders copies the lab
   patch.

## Principles

- 3 No ambient authority: Store I/O is on the grant's root fd for the
  named paths. A bind mount under that fd is still ambient host mount
  authority.
- 10 One canonical path: `rename` still has a string `create_dir_all`
  beside the fd walk.
- 11 Fail closed: a Store-created foreign inode stops with `HardLink`.
  A host-created inode after `rename` is read.
- 12 Docs, code, tests agree: Runtime rows stay blocked. The nofollow
  plant does not match the live walk.
- 18 Isolated execution: lab directories are separate. The host process
  is not. Two Store objects are not one isolation domain.

DeepSeek: none.

Questions: security finding for Sasha, shipping `LocalMutableStorage`
still opens a string path after a check (`local.rs:76-145`). Details
stay in this file and in `lab/a9/RUNTIME-ASK.md`. Do not copy a patch
into Elacity/elastos-runtime from this spike.
