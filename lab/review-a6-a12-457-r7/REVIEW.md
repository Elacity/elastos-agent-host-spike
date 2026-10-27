# Review r7 of draft PR #457

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #457 (`cursor/a12-r6-survivors-c4de`). This folder only adds
`lab/review-a6-a12-457-r7/`. It does not edit #457, #343, other `lab/`
folders, or Runtime source. It does not merge or close anything.

- Target: #457 head `4564a30f1384f1b9d070762eb8e4a8e727bd2959`.
- Base of this review PR: `cursor/a12-r6-survivors-c4de`.
- Prior review: PR #441 of `5547edea` — r6 **FIX** (A12 Linux half).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS. `mount --bind` and `unshare -m` / `unshare -p`
  are refused here.
- How to run: `lab/review-a6-a12-457-r7/run.sh`.
- Subject worktree: `/tmp/pr457-r7`, detached at the pin above.

Anders's rule still holds: A6 counts only when two independent resident
capsule instances inside one Runtime complete the journey. #457 does
not claim that. A6 stays **BLOCKED (RA-6)**. This review judges the
Linux A12 lab half on its own.

## Counting settlement

The author's headings `Old plants 34/39 CAUGHT` and `New plants 12/14
CAUGHT` are **plants / CAUGHT-lines**, not **caught / total**.

Git on `cursor/a6-a12-evidence-fix-6e3b` (#343) lists **34** plant
files. Five of those name more than one test (`F-A12-DROP-ROOTS`,
`M-A12-TMP-DOTDOT`, `M-A12-TOCTOU-FOLLOW`, `M-A6-COMMENT-STEP4`,
`M-A6-PROVE-ALWAYS-OK`), so the runner prints **39** CAUGHT lines.

#457 adds **12** plant files and removes **0**. One new plant
(`M-A12-NO-RECURSE-WATCH`) names three tests, so the runner prints
**14** new CAUGHT lines.

Disk on this head: **46** plant files, **53** `test:` lines. No old
plant is missing. The FINDINGS table lists only CAUGHT rows because
every plant file is present and the author's runner requires CAUGHT.
That is not a hidden SURVIVED set. See `evidence/plant-count.txt`.

## Verdict

**A12 Linux lab half: FIX**

**A6: BLOCKED (RA-6)**

**Mac: NOT RUN**

The r6 items this PR claimed to close hold on this host: inode reuse
did not panic (this ext4 host recycled and the leftover was found);
`openat2` flags are pinned; hardlink dest, `$HOME/.cache` with XDG
set, recursive watches, `watch.add`, rename dest, and O_TMPFILE
unlink in a subdir are CAUGHT. Overflow under load fail-closes.
Setsid-after-return, bind, pid-ns, `/run/user`, and watch sysctl
stay HostPart::NotRun.

Three new holes keep the lab half from PASS:

1. A leftover **FIFO** under a watch root can hang
   `leftovers_in_run_window`. `hash_whole_file_sparse` uses blocking
   `fs::File::open`.
2. The **IN_Q_OVERFLOW pin** still matches if the `if` stays and the
   `return Err` is dropped. Runtime overflow fail-closed still works.
   The named pin is weaker than the author plant.
3. **TMPDIR changed mid-run** is a false FAIL: a pre-existing file in
   the new TMPDIR is listed as a leftover because the after-snapshot
   walks a root the before-snapshot never saw.

`manager.rs` sha256 stayed
`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`
before and after every run. After each run, `ls /tmp/elastos` was
`No such file or directory`. The subject worktree stayed clean.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## Author claims

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 71 named lib tests pass, 5 stable runs | **HOLDS** here | three full `run.sh`: 71/0 in 652.91s, 621.27s, 613.93s; `--list` prints 71 |
| 46 plants / 53 CAUGHT lines | **HOLDS** | author runner 53 CAUGHT on each of the three runs; independent replant 46 plants / 53 CAUGHT / 0 SURVIVED |
| headings 34/39 and 12/14 | **plants / lines, not miss rate** | 34 old files / 39 tests; 12 new files / 14 tests; 0 omitted |
| inode reuse flake closed | **HOLDS** | this host recycled; leftover found; no panic |
| openat2 flags pinned | **HOLDS** | `R7-NO-OPENAT2` CAUGHT |
| setsid late write caught | **NOT RUN** (honest) | HostPart::NotRun; live write after return still unseen |
| hardlink dest caught | **HOLDS** | hunt CAUGHT |
| `$HOME/.cache` with XDG set | **HOLDS** | hunt CAUGHT |
| recursive watches | **HOLDS** | subdir create-then-delete CAUGHT |
| watch.add honoured | **HOLDS** | source pin CAUGHT |
| overflow pinned | **PIN WEAK** | load CAUGHT; `R7-IGNORE-OVERFLOW` (keep if, drop return) SURVIVED the pin |
| rename-out dest caught | **HOLDS** | hunt CAUGHT |
| O_TMPFILE in a subdir caught | **HOLDS** | hunt CAUGHT |
| two resident instances | **BLOCKED (RA-6)** | ready journey |
| `manager.rs` unchanged | **HOLDS** | sha256 `cd4772f1…066b2a` |
| `/tmp/elastos` absent | **HOLDS** | after each run |

## Full plant table (46 plants)

Author runner, three times: every row **CAUGHT**. Independent
replant (not `plant.rs`): **46 plants, 53 CAUGHT lines, 0 SURVIVED,
0 INCONCLUSIVE**. 0 omitted. See `evidence/replant.txt`.

### Old plants (34 files / 39 lines)

| Plant | Tests | Result |
| --- | --- | --- |
| F-A6-NO-TOKEN-CHECK | 1 | **CAUGHT** |
| M-A6-PREFIX-BIND | 1 | **CAUGHT** |
| M-A6-EMPTY-TOKEN | 1 | **CAUGHT** |
| M-A6-COMMENT-STEP4 | 2 | **CAUGHT** |
| M-A6-CLAIM-RESIDENT | 1 | **CAUGHT** |
| M-A6-STUB-OK | 1 | **CAUGHT** |
| M-A6-LIVE-PIDS | 1 | **CAUGHT** |
| F-A12-DROP-ROOTS | 2 | **CAUGHT** |
| M-A12-HARDCODE-FAIL | 1 | **CAUGHT** |
| M-A12-SYMLINK-ROOT | 1 | **CAUGHT** |
| M-A12-RENAME-ROOT | 1 | **CAUGHT** |
| M-A12-RENAME-UNRELATED | 1 | **CAUGHT** |
| M-A12-NO-MARKER | 1 | **CAUGHT** |
| M-A12-TMP-SLASH | 1 | **CAUGHT** |
| M-A12-TMP-UNSET | 1 | **CAUGHT** |
| M-A12-TMP-DOTDOT | 2 | **CAUGHT** |
| M-A12-TMP-LIVE-SYMLINK | 1 | **CAUGHT** |
| M-A12-SNAP-AFTER-WRITE | 1 | **CAUGHT** |
| M-A12-SNAP-IGNORE-LIVE | 1 | **CAUGHT** |
| M-A12-NO-ISOLATION | 1 | **CAUGHT** |
| M-A12-INODE-REUSE | 1 | **CAUGHT** |
| M-A12-NO-HANDLE | 1 | **CAUGHT** |
| M-A12-HASH-MTIME | 1 | **CAUGHT** |
| M-A12-TOCTOU-FOLLOW | 2 | **CAUGHT** |
| M-A12-SIBLING-WATCH | 1 | **CAUGHT** |
| M-A12-NO-SYSTEM-TEMPS | 1 | **CAUGHT** |
| M-A12-NO-LIVE-WATCH | 1 | **CAUGHT** |
| M-A12-HASH-CAP-64K | 1 | **CAUGHT** |
| M-A12-SPARSE-READ | 1 | **CAUGHT** |
| M-A12-NO-RECHECK | 1 | **CAUGHT** |
| M-A12-HANDLE-EMPTY-OK | 1 | **CAUGHT** |
| M-A6-CLAIMED-NO-RA6 | 1 | **CAUGHT** |
| M-A6-PROVE-ALWAYS-OK | 2 | **CAUGHT** |
| M-A6-INSPECT-ALWAYS-SOME | 1 | **CAUGHT** |

### New plants (12 files / 14 lines)

| Plant | Tests | Result |
| --- | --- | --- |
| M-A12-NO-OPENAT2 | 1 | **CAUGHT** |
| M-A12-DETACHED-AFTER-PASS | 1 | **CAUGHT** |
| M-A12-NO-HANDLE-FOLLOW | 1 | **CAUGHT** |
| M-A12-NO-HOME-WATCH | 1 | **CAUGHT** |
| M-A12-SKIP-HOME-CACHE | 1 | **CAUGHT** |
| M-A12-NO-RECURSE-WATCH | 3 | **CAUGHT** |
| M-A12-IGNORE-WATCH-ADD | 1 | **CAUGHT** |
| M-A12-IGNORE-OVERFLOW | 1 | **CAUGHT** (author plant deletes the `if`) |
| M-A12-BIND-PASS | 1 | **CAUGHT** |
| M-A12-PIDNS-PASS | 1 | **CAUGHT** |
| M-A12-RUN-USER-PASS | 1 | **CAUGHT** |
| M-A12-WATCH-SYSCTL-PASS | 1 | **CAUGHT** |

## New r7 hunts

| Id | What was tried | Result |
| --- | --- | --- |
| r7-memfd | `memfd_create`, write, no link | **OUT OF SCOPE** (no directory entry) |
| r7-shm-open | `shm_open` in `/dev/shm` | **CAUGHT** |
| r7-unix-socket | `UnixListener::bind` under `/var/tmp` | **CAUGHT** |
| r7-mkfifo | `mkfifo` under `/var/tmp` | **SURVIVED** (blocking `File::open`) |
| r7-proc-fd | unlink, write via `/proc/self/fd` | **CAUGHT** (live watch) |
| r7-scm-rights | fd sent to a Python helper | **CAUGHT** (named leftover) |
| r7-after-watch | write after census returns | **SURVIVED** (same class as setsid-after-return) |
| r7-xdg-runtime | `XDG_RUNTIME_DIR` leftover | **CAUGHT** |
| r7-tmpdir-mid | change `TMPDIR` after the first snapshot | **FALSE-FAIL** |
| r7-overflow-load | 20000 create/delete events | **CAUGHT** (fail closed) |
| R7-IGNORE-OVERFLOW | keep the `if`, drop `return Err` | **SURVIVED** the pin |
| r7-rename-xdev | copy+unlink `/var/tmp` → `/dev/shm` | **CAUGHT** |
| r7-mount-ns | `unshare -m` | **NOT RUN** |
| r7-before-snapshot | create+unlink before snapshot | **EXPECTED** (not a leftover) |
| r7-system-temps | `systemd-tmpfiles --create --user` | **CLEAN** (no false FAIL) |

See `evidence/new-hunts.txt` and `evidence/hunt-summary.txt`.

## Exact patches for survivors

These belong on #457, not in this review folder.

### 1. Do not block on FIFO / socket / device leftovers

In `lab/a6-a12-evidence-fix/src/a12.rs`, `content_hash`:

```rust
    if meta.file_type().is_symlink() || meta.is_dir() || !meta.is_file() {
        return 0;
    }
```

A leftover `mkfifo` under `/var/tmp` must not hang
`leftovers_in_run_window`. The path, inode, and file handle still
identify it. Plant: leave a FIFO in a watch root; the census must
return.

### 2. Pin the overflow *return*, not only the `if`

In `a12_inotify_overflow_check_is_pinned`:

```rust
        assert!(
            body.contains("if ev.mask & libc::IN_Q_OVERFLOW != 0")
                && body.contains(
                    "return Err(\"inotify queue overflow; leftover watch fail closed\".into())"
                ),
            "dropping the IN_Q_OVERFLOW fail-closed return must be CAUGHT"
        );
```

A plant that keeps the `if` and drops the `return Err` must FAIL that
test. The author plant `M-A12-IGNORE-OVERFLOW` already deletes the
`if` and stays CAUGHT.

### 3. Freeze watch roots at the first snapshot

`snapshot_run_window` and `leftovers_in_run_window` must walk the
same root list. Store the roots `writable_temp_roots()` returned at
`start_live_watch` and reuse them for the after snapshot. A
pre-existing file in a TMPDIR that appears only after the first
snapshot is not a leftover.

### 4. Setsid / write after return stays NOT RUN

No code change. `HostPart::NotRun` is honest. Do not count a clean
`Ok([])` as a closed window for a write after return.

## Commands run

Subject worktree `/tmp/pr457-r7` at `4564a30f`, no lasting edits.

```
./lab/a6-a12-evidence-fix/run.sh
```

Three times:

| Run | Result | CAUGHT lines | Seconds |
| --- | --- | --- | --- |
| 1 | `ok. 71 passed; 0 failed` | 53 | 652.91 |
| 2 | `ok. 71 passed; 0 failed` | 53 | 621.27 |
| 3 | `ok. 71 passed; 0 failed` | 53 | 613.93 |

`--list` printed 71 names. A6 ready journey printed
`BLOCKED (RA-6)`. Mac pack printed `NOT RUN (need macOS)`.
`manager.rs` sha256 identical before and after.
After each run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Independent plant count:

```
lab/review-a6-a12-457-r7/tools/count-plants.sh /tmp/pr457-r7
```

Result: 34 old / 39 lines, 12 new / 14 lines, 46 total / 53 lines,
0 omitted. See `evidence/plant-count.txt`.

Independent replant (does not use `plant.rs`):

```
lab/review-a6-a12-457-r7/tools/replant.sh /tmp/pr457-r7
```

Result: `replant summary: 46 plants, 53 CAUGHT lines, 0 SURVIVED, 0 INCONCLUSIVE`.
`manager.rs` restored to `cd4772f1…066b2a`. See `evidence/replant.txt`.

r7 hunts:

```
lab/review-a6-a12-457-r7/tools/hunts.sh /tmp/pr457-r7
```

See `evidence/new-hunts.txt`. cargo `r7_` exit 0.

Mac pack probe (read-only):

```
lab/review-a6-a12-457-r7/tools/mac-pack-probe.sh /tmp/pr457-r7
```

`rm -rf "$PACK_TMP"` only. Mac owner journeys on hold.

r3 runner is absent on this head. The pin `87b974a1` would refuse
`4564a30f`.

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome`
needs macOS). Bind-mount leftover. Pid reuse in a pid namespace.

## Anders's resident-instance rule

**It does not meet the rule. The author does not claim that it does.**

Needed: two resident capsule instances inside one running Runtime /
Home; instance-1 uses its own session token through `validate`;
instance-2 presents that token and is refused `WrongCapsule`;
removing validate step 4 fails that live journey.

What #457 ran: one `CapabilityManager` in-process, two string capsule
ids, a real minted token, a real `from_base64` / `validate` call.
The ready journey reports BLOCKED (RA-6). Two sleep pids are
BLOCKED. This process plus pid 1 is FAIL.

## Mac pack cleanup

Both `run.sh` and `mac-pack.sh` quote `rm -rf "$PACK_TMP"`. There is
no glob `rm`. Mac owner journeys stay on hold.

## Principles

- 11 Fail closed, then explain: overflow under load already fails
  closed. A FIFO leftover hangs instead. TMPDIR mid-run fails open
  as a false leftover.
- 12 Docs, code, tests, and operations must agree: 34/39 and 12/14
  are plants/lines. FINDINGS is honest about HostPart::NotRun. The
  overflow pin does not match a plant that only drops the return.
- 18 Executable capsules are isolated execution environments: a pid
  is not a resident capsule until RA-6 fills the inspect.

DeepSeek: none.

## What is next

On #457: apply the three patches above (skip non-regular files when
hashing, pin the overflow return, freeze watch roots). Keep A6
BLOCKED until RA-6. Then a new review can judge the A12 Linux half
again.
