# Review r6 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343-r6/`. It does not edit #343's branch, other
`lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `5547edeacab167bd822e90a6af7258c5d55f2ce1`.
- Base of this review: `origin/spike/agent-host`
  `970abb4ca83baa2ec6b94c3bc7e3d2f5fe55209a`.
- Prior reviews: PR #365 of `011d01f2` — FALSIFIED. PR #380 of
  `732b6990`. PR #394 of `87b974a1` — r3. PR #412 of `19becdd7` — r4.
  PR #422 of `9d55f8fb` — r5 **PASS** for the A12 Linux half, with
  survivors `/var/tmp`, `/dev/shm`, write-then-delete, sparse=`fs::read`,
  64 KiB hash cap, empty-handle fallback, parent-swap without re-check,
  and stubbed `prove`/`inspect` PASSing two sleep pids.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS. `mount --bind` and `unshare -m` / `unshare -p`
  are refused here. Mac owner commands stay on hold.
- How to run: `lab/review-a6-a12-343-r6/run.sh`.
- Subject worktree: `/tmp/pr343-r6`, detached at the pin above.

Anders's rule, as given for this review: A6 counts only when two
independent resident capsule instances inside one Runtime complete the
journey. #343 does not claim that. A6 stays **BLOCKED (RA-6)** on this
head. This review judges the Linux A12 lab half on its own.

## Plain status

#343's own suite at `5547edea` listed **57** lib tests. The first full
`./lab/a6-a12-evidence-fix/run.sh` printed
`FAILED. 56 passed; 1 failed`. The failure is
`tests::a12_inode_reuse_same_path_is_found`:
`same-path inode reuse did not happen; identity check would not be
decisive`. That test panics when this ext4 host does not recycle the
inode in 300 tries. Isolated reruns of the same test passed 5/5.
`same_bytes` reuse passed in the full suite. The 57/0 claim is
unstable on this machine.

The author's plant runner still printed **39 CAUGHT lines** from
**34 plants**. An independent replant, not `plant.rs`, printed the
same **39 CAUGHT lines, 0 SURVIVED**. Plants restored `manager.rs`
byte-for-byte
(`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`
before and after). After the run, `ls /tmp/elastos` was `No such file
or directory`. The subject worktree stayed clean.

The r5 survivors the author named as closed hold against their named
tests, with one exception:

- `/var/tmp` + `/dev/shm` — **CAUGHT**
- inotify create-then-delete at the top of `/var/tmp` — **CAUGHT**
- full-file last-byte 65 KiB hash — **CAUGHT**
- SEEK_HOLE vs zeros (author plant `M-A12-SPARSE-READ`) — **CAUGHT**
- claimed pair requires RA-6 — **CAUGHT**
- empty handle is FileId NOT RUN — **CAUGHT**
- `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` — **SURVIVED**.
  Zeroing the resolve flags leaves
  `a12_parent_dir_swap_after_check_cannot_write_outside` green.
  The write-time `check_tmp_root` refuses the swapped symlink.
  The named test does not pin the openat2 flags.

A6 is still one in-process `CapabilityManager` and two capsule id
strings. The ready journey reports **BLOCKED (RA-6)**. Two sleep pids
are BLOCKED. This process plus pid 1 is FAIL.

## Verdict

**A12 Linux lab half: FIX**

**A6: BLOCKED (RA-6)**

**Mac: NOT RUN**

The plant table and the r5 leftover/hash/RA-6 named tests are real.
The 57/0 run is not stable: inode reuse must fail closed as NOT RUN
when this host does not recycle. The claimed openat2 close is
untested. The claimed live watch is only the top of `/tmp`,
`/var/tmp`, and `/dev/shm`; create-then-delete in a subdirectory
SURVIVED. `IN_Q_OVERFLOW` already fails closed, but dropping that
check SURVIVED the named create-then-delete test. Watch-add failures
are ignored (`let _ = watch.add`), so an exhausted `max_user_watches`
would still PASS.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## Author claims

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 57 named lib tests pass | **UNSTABLE** | `--list` printed 57; first `run.sh` was 56/1; isolated inode-reuse 5/5 |
| 34 plants / 39 CAUGHT lines | **HOLDS** | author runner and independent replant |
| 0 SURVIVED (author plants) | **HOLDS** | replant summary |
| Plants restore `manager.rs` byte-identically | **HOLDS** | sha256 `cd4772f1…066b2a` before and after |
| r5 system temp roots closed | **HOLDS** | `R5-NO-SYSTEM-TEMPS` CAUGHT |
| r5 inotify live watch closed | **HOLDS** at top of `/var/tmp` only | `R5-NO-LIVE-WATCH` CAUGHT; subdir hunt SURVIVED |
| r5 full-file + SEEK_HOLE hash closed | **HOLDS** | author plants CAUGHT |
| r5 RA-6 required for claimed pair | **HOLDS** | `R5-CLAIMED-NO-RA6` CAUGHT |
| r5 empty handle => NOT RUN | **HOLDS** | `R5-HANDLE-EMPTY-OK` CAUGHT |
| r5 openat2 RESOLVE_BENEATH\|NO_SYMLINKS | **SURVIVED** | `R5-NO-OPENAT2` against the parent-swap test |
| two resident instances | **BLOCKED (RA-6)** | ready journey |

## Author plants, independently replanted

All 34 plants **CAUGHT**. 39 CAUGHT lines. 0 SURVIVED. See
`evidence/replant.txt`.

## r5 survivors, independently reapplied

| Id | Change | Named test | Result |
| --- | --- | --- | --- |
| R5-NO-SYSTEM-TEMPS | drop `/var/tmp` and `/dev/shm` | `a12_run_window_watches_var_tmp_and_dev_shm` | **CAUGHT** |
| R5-NO-LIVE-WATCH | ignore inotify drain | `a12_create_then_delete_between_snapshots_is_found` | **CAUGHT** |
| R5-HASH-CAP-64K | hash only first 64 KiB | `a12_large_file_inplace_rewrite_mtime_restored_is_found` | **CAUGHT** |
| R5-SPARSE-READ | `fs::read` (reviewer mutant) | `a12_sparse_hole_hash_differs_from_written_zeros` | **INCONCLUSIVE** (mutant did not compile; author plant `M-A12-SPARSE-READ` is CAUGHT) |
| R5-CLAIMED-NO-RA6 | skip `try_host` | `a6_two_other_live_pids_are_blocked` | **CAUGHT** |
| R5-HANDLE-EMPTY-OK | accept empty handle | `a12_empty_file_handle_is_not_run` | **CAUGHT** |
| R5-NO-OPENAT2 | `resolve: 0` | `a12_parent_dir_swap_after_check_cannot_write_outside` | **SURVIVED** |

## Attacks on the author's NOT COVERED list and beyond

| Id | What was tried | Result |
| --- | --- | --- |
| r6-detached-during | setsid child writes after the first snapshot; file still there at the second | **CAUGHT** |
| r6-detached-after-return | setsid/double-fork writes after `leftovers_in_run_window` returns Ok | **SURVIVED** |
| r6-bind-mount | `mount --bind` and `unshare -m` | **NOT RUN** (host refuses) |
| r6-hardlink-out | hardlink `/var/tmp/...` to `/home/ubuntu/...`, delete the watch copy | **SURVIVED** (dest leftover unseen; no source event) |
| r6-home-cache | `$HOME/.cache/secret` while `XDG_CACHE_HOME` is set; HOME outside isolation and `/tmp` | **SURVIVED** (`extra_watch_roots` skips the fallback; leftover_found=false) |
| r6-overflow | 18432 create/delete events on the isolation root | **CAUGHT** (`IN_Q_OVERFLOW` fail closed) |
| R6-IGNORE-OVERFLOW | drop the overflow check | **SURVIVED** against the named create-then-delete test |
| r6-watch-limit | source: `let _ = watch.add` | **SURVIVED** |
| r6-watch-limit-host | write `max_user_watches` | **NOT RUN** |
| r6-preopen-existing | write via fd opened before the snapshot | **CAUGHT** (FileId hash) |
| r6-preopen-dirfd | create+delete via dirfd opened before the watch, in a `/var/tmp` subdir | **SURVIVED** |
| r6-rename-out-event | rename `/var/tmp` → `/home/ubuntu` | **CAUGHT** (source event) |
| r6-rename-out-dest | same rename | **SURVIVED** (dest leftover unseen) |
| r6-rename-in | rename `/home/ubuntu` → `/var/tmp` | **CAUGHT** |
| r6-otmpfile | `O_TMPFILE` + `linkat AT_EMPTY_PATH` into `/var/tmp`; file remains | **CAUGHT** |
| r6-otmpfile-unlink | same into a `/var/tmp` subdir, then unlink | **SURVIVED** |
| r6-run-user | `/run/user/1000` | **NOT RUN** (absent; not in `writable_temp_roots`) |
| r6-pidns | `unshare -p` | **NOT RUN** |
| r6-subdir-ephemeral | create-then-delete inside `/var/tmp/<dir>/` | **SURVIVED** |
| r6-ra6-current | ready journey | **BLOCKED** |

See `evidence/new-hunts.txt` and `evidence/hunt-summary.txt`.
The HOME/.cache leftover was confirmed outside isolation and `/tmp`
(`leftover_found=false`).

Items this host cannot exercise (bind mount, pid namespace, watch
sysctl, `/run/user/$UID`) stay **NOT RUN**. They must not be counted
as a clean-window PASS.

## Exact patches for survivors

These are the smallest changes that close the holes on this Linux
lab. They belong on #343, not in this review folder.

### 1. Inode reuse: NOT RUN when this host does not recycle

In `lab/a6-a12-evidence-fix/src/lib.rs`,
`a12_inode_reuse_same_path_is_found` (and the same-bytes twin if it
takes the same path):

```rust
        if !reused {
            println!(
                "NOT RUN: same-path inode reuse did not happen; FileId reuse is not proven on this host"
            );
            a12::remove_isolated(&parent);
            return;
        }
```

A 56/1 run must not be reported as 57/0.

### 2. Pin the openat2 flags

The parent-swap test stays green with `resolve: 0`. Add a source pin
next to `a12_write_isolated_leftover_rechecks_tmp_root`:

```rust
    #[test]
    fn a12_write_uses_openat2_beneath_no_symlinks() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a12.rs"));
        let start = source.find("fn openat2_beneath").expect("openat2_beneath");
        let body = &source[start..];
        assert!(
            body.contains("RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS"),
            "openat2 dropped RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS"
        );
    }
```

Plant `R5-NO-OPENAT2` (`resolve: 0`) must then FAIL that test.

### 3. Live watch: recurse writable temps; fail closed on add

In `LiveWatch::open` and `add_dir_watches_recursive`:

```rust
        for root in writable_temp_roots() {
            if root.exists() {
                watch.add(&root)?;
                add_dir_watches_recursive(&mut watch, &root, 0)?;
            }
        }
```

and replace `let _ = watch.add(&path)` with `watch.add(&path)?`.
This closes `r6-subdir-ephemeral`, `r6-preopen-dirfd`, and
`r6-otmpfile-unlink`. Exhausted `max_user_watches` then returns Err
(NOT RUN / fail closed) instead of PASS.

### 4. `$HOME/.cache` while `XDG_CACHE_HOME` is set

In `extra_watch_roots`, add the HOME fallback even when the XDG var
is set:

```rust
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                roots.push(PathBuf::from(value));
            }
        }
        if let Some(path) = fallback {
            if !roots.iter().any(|root| root == &path) {
                roots.push(path);
            }
        }
```

Do the same for `/run/user/{uid}` when `XDG_RUNTIME_DIR` is unset.
If `/run/user/{uid}` is absent, report NOT RUN. Do not PASS.

### 5. Hardlink copied out; rename dest outside the watch

After `drain_live_watch`, for each deleted or `MOVED_FROM` path that
was in `before.ids`, try `open_by_handle_at` on the stored handle.
If the handle still opens, the inode is still linked. Fail the
census:

```rust
        if handle_still_opens(&old.file_handle) {
            return Err(format!(
                "leftover inode still reachable by handle after {} vanished; FileId NOT RUN as clean",
                path.display()
            ));
        }
```

That closes `r6-hardlink-out` and `r6-rename-out-dest`.

### 6. Detached child after the census returns

`leftovers_in_run_window` cannot see a write after it returns. A
clean `Ok(vec![])` is not a closed window. The A12 journey must
report **NOT RUN** for "detached child after return" (the author's
list already names it). A PASS line that only means "no leftover at
return" has to say that. Do not treat it as coverage of setsid /
double-fork children.

### 7. Bind mount, pid namespace, watch sysctl

This host refuses `mount --bind`, `unshare -m`, and `unshare -p`.
Those rows stay **NOT RUN**. Add explicit `HostPart::NotRun` checks
so a missing bind/pid-ns proof cannot become PASS.

### 8. Named test for `IN_Q_OVERFLOW`

The overflow path already fails closed. Plant `R6-IGNORE-OVERFLOW`
SURVIVED the current named test. Add a test that drives overflow
(or a source pin on `IN_Q_OVERFLOW`) so dropping the check is
CAUGHT.

## Commands run

Subject suite, worktree `/tmp/pr343-r6` at `5547edea`, no edits:

```
./lab/a6-a12-evidence-fix/run.sh
```

Result: `FAILED. 56 passed; 1 failed`
(`a12_inode_reuse_same_path_is_found`).
`--list` printed 57 names.
Plant runner: 34 plants, 39 CAUGHT lines.
`manager.rs` sha256 identical before and after.
After the run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Isolated inode-reuse reruns: 5/5 ok. See
`evidence/inode-reuse-reruns.txt`.

Independent replants:

```
lab/review-a6-a12-343-r6/tools/replant.sh /tmp/pr343-r6
```

Result: 34 plants, 39 CAUGHT lines, 0 SURVIVED. Exit 0. See
`evidence/replant.txt`.

r5 survivors:

```
lab/review-a6-a12-343-r6/tools/r5-survivors.sh /tmp/pr343-r6
```

See `evidence/r5-survivors.txt`.

r6 hunts:

```
lab/review-a6-a12-343-r6/tools/hunts.sh /tmp/pr343-r6
```

See `evidence/new-hunts.txt`.

Mac pack cleanup (read-only; no `rm` run against the host). Mac
owner journeys on hold:

```
lab/review-a6-a12-343-r6/tools/mac-pack-probe.sh /tmp/pr343-r6
```

See `evidence/mac-pack-probe.txt`.

r3 runner pin (from `lab/review-a6-a12-343-r3/run.sh` on
`origin/cursor/review-a6-a12-343-r3-c383`):

```
# PIN=87b974a1631efcf48e103f84d028eb5b1a2a3c7f
# subject HEAD=5547edeacab167bd822e90a6af7258c5d55f2ce1
# REFUSE
```

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome`
needs macOS). Bind-mount leftover. Pid reuse in a pid namespace.

## Anders's resident-instance rule

**It does not meet the rule. The author does not claim that it does.**

Needed: two resident capsule instances inside one running Runtime /
Home; instance-1 uses its own session token through `validate`;
instance-2 presents that token and is refused `WrongCapsule`;
removing validate step 4 fails that live journey.

What #343 ran: one `CapabilityManager` in-process, two string capsule
ids, a real minted token, a real `from_base64` / `validate` call.
`try_host_two_resident_instances` still returns Err. Two sleep pids
are BLOCKED. This process plus pid 1 is FAIL.

## Mac pack cleanup

Both `run.sh` and `mac-pack.sh` quote `rm -rf "$PACK_TMP"`. There is
no glob `rm`. Mac owner journeys stay on hold.

## Exact Mac commands still needed

Linux cannot run these. On a Mac, use the isolated pack (or
`./lab/a6-a12-evidence-fix/mac-pack.sh`):

```
PACK=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-pack.XXXXXX")
printf 'a6-a12-evidence-fix isolation\n' > "$PACK/.a6-a12-isolation"
ELASTOS_TMP_ROOT="$PACK" ELASTOS_TMP_ISOLATION="$PACK" \
  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  two_instances_overlap_with_separate_grants -- --nocapture
ELASTOS_TMP_ROOT="$PACK" ELASTOS_TMP_ISOLATION="$PACK" \
  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  instance_grant_does_not_authorise_sibling -- --nocapture
ELASTOS_TMP_ROOT="$PACK" ELASTOS_TMP_ISOLATION="$PACK" \
  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
  cleanup_census_refuses_each_leftover -- --nocapture
rm -rf "$PACK"
```

Those owner rows still use fixture deny and the throwaway TMPDIR.
They do not close RA-6.

## Principles

- 3 No ambient authority: the in-process token binds a caller string;
  the live request path still goes to pending.
- 11 Fail closed, then explain: `IN_Q_OVERFLOW` already fails closed.
  Inode reuse, bind mount, pid namespace, `/run/user/$UID`, and watch
  add failures still become a panic or a silent PASS. Those rows need
  NOT RUN.
- 12 Docs, code, tests, and operations must agree: FINDINGS.md is
  honest that detached children, bind mounts, hardlinks-out, and
  `$HOME/.cache` stay uncovered. The 57/0 line and the openat2 claim
  do not match this run.
- 18 Executable capsules are isolated execution environments: a pid
  is not a resident capsule until RA-6 fills the inspect.

DeepSeek: none.

## What is next

On #343: apply the eight patches above, replace the 57/0 claim with
the command that actually ran, pin openat2, recurse the live watch,
and fail closed (NOT RUN) for bind / pid-ns / `/run/user` / watch
add. Keep A6 BLOCKED until RA-6. Then a new review can judge the
A12 Linux half again.
