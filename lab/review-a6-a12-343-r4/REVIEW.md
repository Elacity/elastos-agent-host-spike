# Review r4 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343-r4/`. It does not edit #343's branch, other
`lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `19becdd74c3f96d5900487051d2e175fd5c06747`.
- Base of this review: `origin/spike/agent-host`
  `215841921df50dd30327cc3f5ffe6ac4f811d066`.
- Prior reviews: PR #365 of head `011d01f2` — **FALSIFIED**. PR #380 of
  head `732b6990` — A6 and A12 not bookable. PR #394 of head `87b974a1`
  — r3: RA-6 stub `Ok` was PASS; guard accepted `..` and a live-Home
  symlink; census missed `$TMPDIR`/XDG, inode reuse, and writes before
  the snapshot.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS. Bind mounts and `unshare -m` are refused
  here (`must be superuser` / `Operation not permitted`).
- How to run: `lab/review-a6-a12-343-r4/run.sh`.
- Subject worktree: `/tmp/pr343-r4`, detached at the pin above.

Anders's rule, as given for this review: A6 counts only when two
independent resident capsule instances inside one Runtime complete the
journey. #343 does not claim that. This review treats every other
claim as unverified until a command on this machine showed it.

## Plain status

#343's own suite at `19becdd7` is `ok. 43 passed; 0 failed; 0 ignored`
in 62.20s (compile 1m 17s). `--list` printed those 43 names. The
author's plant runner printed **22 CAUGHT lines** from **19 plants**.
Plants restored `manager.rs` byte-for-byte
(`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`
before and after). After the run, `ls /tmp/elastos` was `No such file
or directory`. The subject worktree stayed clean.

The r3 runner `lab/review-a6-a12-343-r3/run.sh` pins `87b974a1` and
refuses this head. That claim holds.

The three r3 holes the author named as fixed do hold, when judged by
the functions that now own them:

- `check_tmp_root($ISOLATION/..)` and a symlink under isolation to a
  fake live Home are refused. Independent r3 probes print **CAUGHT**.
- Same-path inode reuse with *changed* bytes is found by
  `leftovers_created`. Independent r3 probe prints **CAUGHT**.
- A leftover already on disk makes `snapshot_before_runtime` fail.
  Writes under `$TMPDIR`, a fake XDG cache, and `Library/Caches` are
  found by `leftovers_in_run_window`.

The author's note about leftover r3 **SURVIVED** labels also holds,
and it is a script/API mismatch, not a remaining r3 hole:

- The r3 `leftovers_created(watch)` probes for a late snapshot and a
  sibling folder still print **SURVIVED**. Those probes still call
  only `leftovers_created` on one watch. The new APIs catch the same
  plants.
- The r3 `ra6-stub-ok` script still prints **SURVIVED** because the
  named test line ends with `FAILED`. The panic text on this head is
  `must be BLOCKED, not FAIL` plus `empty ResidentPair`. The journey
  is **FAIL**, not **PASS**. Plant `M-A6-STUB-OK` is independently
  **CAUGHT**.

A6 is still one in-process `CapabilityManager` and two capsule id
strings. The ready journey reports **BLOCKED (RA-6)** today. An empty
`ResidentPair` is **FAIL**.

The Pass path is still reachable without resident capsules. If the
hosting stub returns `Ok` and `query_runtime_resident_instances`
returns this process's pid plus pid 1, two distinct grants, and two
ids, the named test panics with:

`must not PASS until RA-6: A6 resident: Runtime hosted instance-1 pid
10710 and instance-2 pid 1; sibling refused WrongCapsule`.

That is two live pids and an in-process `WrongCapsule` check. It is
not two resident capsule instances inside one Runtime.

A12's FileId census finds a rename, a leftover with no lab marker, and
a delete+recreate whose *bytes* change. It misses a same-path inode
reuse that writes the same bytes, and an in-place rewrite of a file
larger than 64 KiB whose mtime is restored (identity prefers birth
time; large files hash size+mtime only). The run-window watch covers
`$TMPDIR`, XDG dirs, and Mac Library dirs. It leaves `/var/tmp` and
`/dev/shm` unseen. A leftover written then deleted, or written by a
detached child after the first census, is absent from that result.

`ELASTOS_TMP_ROOT` canonicalizes and refuses `/`, empty, `$HOME`, a
`..` component, a symlink at or under isolation, a reachable live
Home, and a canonical path outside the mktemp. The check and the later
write are separate. After a passing check, replacing the folder with a
symlink lets a write land in a fake live Home. The next
`check_tmp_root` refuses that symlink. A caller that kept the first
`Ok` path still wrote outside.

The isolation-under check itself works (`/var/tmp` is refused).
Removing it leaves the author's named slash, HOME, and `..` tests
green. The `/tmp/elastos` half of `snapshot_before_runtime` is the
same kind of gap: the named late-snapshot test plants under the watch.

`run.sh` and `mac-pack.sh` quote `rm -rf "$PACK_TMP"`. Cleanup stays
inside the mktemp folder those scripts created. The three Mac owner
commands are the right names, isolated, and safe to print. They still
use fixture deny. They do not close RA-6.

## Verdict

**VERDICT: FIX**

**A6 is not bookable. A12 is not bookable.** A6 stays **BLOCKED
(RA-6)**.

The r3 fixes the author named are real. The suite count, the plant
count, the restore hash, and the r3 pin-refuse are real. The Pass
path and the FileId census still give a clean result for cases A6 and
A12 have to see.

What still has to change before this pack can claim those rows:

1. The RA-6 Pass path must demand evidence that the two live pids are
   resident capsule instances inside one Runtime. Two distinct live
   `/proc` pids and two grant strings are not that evidence. Same pid
   from one process is already FAIL. This process plus pid 1 is PASS.
2. FileId must treat a same-path reuse with the same bytes as a
   leftover, and an in-place rewrite of a large file as a leftover,
   even when birth time stays and mtime is restored.
3. Named tests must fail if the isolation-under check is dropped, if
   the `/tmp/elastos` half of `snapshot_before_runtime` is dropped, or
   if symlink walking looks only at the final path component.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## What counts for A12 on Linux

On this Linux host, A12 credit in this pack is:

- a created-set walk under the isolation mktemp, keyed by FileId
  `(dev, inode, birth/ctime, size+content hash)`;
- `snapshot_before_runtime` refusing a watch that already holds
  `storage/` or `elastos/` (or a live `/tmp/elastos` that already
  holds files);
- `leftovers_in_run_window` seeing new entries under `$TMPDIR`,
  `XDG_CACHE_HOME` / `XDG_DATA_HOME` / `XDG_STATE_HOME` /
  `XDG_RUNTIME_DIR`, and `$HOME/Library/Caches` plus
  `$HOME/Library/Application Support`;
- `ELASTOS_TMP_ROOT` refused when it is `/`, empty, relative,
  `$HOME`, a live Home path, a `..` component, a symlink at or under
  isolation, or a canonical path outside the mktemp.

A12 on Linux does **not** include: `ThrowawayHome` +
`census::cleanup` (NOT RUN; needs macOS); leftovers under `/var/tmp`
or `/dev/shm`; a file that existed only between the two snapshots; a
detached child write after the first census; a bind mount into the
watch (this host cannot create one); a same-bytes inode reuse; an
in-place rewrite of a file larger than 64 KiB with mtime restored.

Owner `census.rs` still walks the throwaway TMPDIR only.

## Commands run

Subject suite, worktree `/tmp/pr343-r4` at `19becdd7`, no edits:

```
./lab/a6-a12-evidence-fix/run.sh
```

Result: `ok. 43 passed; 0 failed; 0 ignored` in 62.20s.
`--list` printed those 43 names.
Plant runner: 19 plants, 22 CAUGHT lines (F-A12-DROP-ROOTS,
M-A12-TMP-DOTDOT, and M-A6-COMMENT-STEP4 each name two tests).
`manager.rs` sha256 identical before and after.
After the run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Independent replants (not the author's `planted_bugs_are_caught`):

```
lab/review-a6-a12-343-r4/tools/replant.sh /tmp/pr343-r4
```

Result: all eighteen named plants **CAUGHT**. `manager.rs`, `a12.rs`,
and `a6.rs` sha256 restored after each plant. Exit 0. See
`evidence/replant.txt`.

r3 hunts ported to this head, plus r4 hunts:

```
lab/review-a6-a12-343-r4/tools/new-hunts.sh /tmp/pr343-r4
```

Result: `ok. 14 passed` (r3 probes) and `ok. 14 passed` (r4 probes),
then the RA-6 / pid plants. Worktree clean afterwards. See
`evidence/new-hunts.txt`.

Guard and census mutants:

```
lab/review-a6-a12-343-r4/tools/mutants.sh /tmp/pr343-r4
```

See `evidence/mutants.txt`.

Mac pack cleanup (read-only; no `rm` run against the host):

```
lab/review-a6-a12-343-r4/tools/mac-pack-probe.sh /tmp/pr343-r4
```

See `evidence/mac-pack-probe.txt`.

r3 runner pin:

```
# lab/review-a6-a12-343-r3/run.sh PIN=87b974a1
# subject HEAD=19becdd74c3f96d5900487051d2e175fd5c06747
# REFUSE
```

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome` needs
macOS). Bind-mount leftover into the census (this host refuses mount).

## Per-claim table

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 43 named lib tests pass | **HOLDS** | `--list` printed 43 names; `run.sh` printed `43 passed` |
| 19 plants / 22 CAUGHT lines | **HOLDS** | exact CAUGHT lines in `evidence/subject-run.txt` |
| r3 runner refuses this head | **HOLDS** | pin `87b974a1` ≠ `19becdd7` |
| F-A6-NO-TOKEN-CHECK / prefix / empty / step 4 / claim-resident / stub-ok | **HOLDS** | author's plants + independent replants |
| F-A12-DROP-ROOTS and the r2/r3 A12 plants | **HOLDS** | author's plants + independent replants |
| Plants restore `manager.rs` byte-identically | **HOLDS** | sha256 `cd4772f1…066b2a` before and after |
| Instance-1 may use its session token | **HOLDS** | real `grant` + `from_base64` + `validate` as instance-1 |
| Sibling presenting owner token is `WrongCapsule` with fields compared | **HOLDS** | `expected:instance-1 got:instance-2` |
| Prefix / empty / case / zwsp / other resource/action / expired / revoked / tampered | **HOLDS** | named tests printed the typed Runtime errors |
| RA-6 journey reports BLOCKED today | **HOLDS** | `BLOCKED (RA-6): … does not host two resident capsule instances` |
| RA-6 journey FAILs if validate step 4 is removed | **HOLDS** | independent `M-A6-COMMENT-STEP4-RA6` CAUGHT |
| Empty `ResidentPair` is FAIL | **HOLDS** | `a6_empty_resident_pair_cannot_pass` + r4 hunt |
| r3 `ra6-stub-ok` SURVIVED means PASS | **FALSIFIED** as a remaining hole | panic is FAIL on empty pair; r3 script labels any FAILED line SURVIVED |
| Guard refuses `..` and a live-Home symlink | **HOLDS** | named tests + r3 probes CAUGHT |
| Created-set finds inode reuse when bytes change | **HOLDS** | named test + r3 probe CAUGHT |
| `snapshot_before_runtime` refuses a late snapshot | **HOLDS** | named test + r4 hunt CAUGHT |
| Run-window sees `$TMPDIR` / XDG / Library | **HOLDS** | named test + r4 hunt CAUGHT |
| `leftovers_created(watch)` late-snapshot / sibling probes | **SURVIVED** as those probes | expected; new APIs own those cases |
| RA-6 cannot PASS without two resident instances | **FALSIFIED** | this process pid + pid 1 is PASS |
| Same pid, two ids, one process | **HOLDS** as refuse | FAIL: `pids must be two distinct live pids` |
| FileId finds every same-path inode reuse | **FALSIFIED** | same bytes, reused ino, leftover absent |
| FileId finds an in-place large rewrite | **FALSIFIED** | 65 KiB rewrite, mtime restored, leftover absent |
| Guard is safe against a check-then-swap | **FALSIFIED** | first `Ok`, then symlink, write landed in fake live Home |
| Isolation-under check is pinned by named tests | **FALSIFIED** | mutant SURVIVED slash, HOME, and `..` tests |
| `/tmp/elastos` half of late-snapshot is pinned | **FALSIFIED** | dropping it leaves the named test green |
| Leaf-only symlink walk is enough | **WEAK** | leaf-symlink mutant SURVIVED the named live-Home test |
| Created-set finds leftovers in `/var/tmp` or `/dev/shm` | **FALSIFIED** | run-window leftovers empty |
| Created-set finds a write that is gone before the after-snapshot | **SURVIVED** | inherent to a leftover census |
| Created-set finds a detached child write at Runtime exit | **SURVIVED** | later rescan CAUGHT |
| Bind mount into the census is found | **INCONCLUSIVE** | this host cannot mount |
| `ThrowawayHome` + `census::cleanup` are invoked | **HOLDS** as a call | `ThrowawayHome::new()` runs and is NOT RUN on Linux |
| `ELASTOS_TMP_ROOT` set writes nothing under `/tmp/elastos` | **HOLDS** | suite left `/tmp/elastos` absent |
| Mac pack cleanup can delete outside the isolated folder | **FALSIFIED** as a fear | quoted `rm -rf "$PACK_TMP"`; no glob; trap after mktemp |
| These checks make A6 or A12 bookable | **FALSIFIED** | no resident instances; FileId and Pass path still hide |
| Meets Anders's independent-resident-instances-in-one-Runtime rule | **FALSIFIED** | author does not claim it; the crate is one in-process manager |

## r3 hunts, ported to this head

| Id | What was tried | r3 at `87b974a1` | This head | Honest call |
| --- | --- | --- | --- | --- |
| child-process | leftover written by `sh` after the snapshot | CAUGHT | **CAUGHT** | still holds |
| after-census-first-call | leftover after `leftovers_created` returns | SURVIVED | **SURVIVED** | inherent |
| after-census-rescan | same leftover, second call | CAUGHT | **CAUGHT** | still holds |
| sibling-outside-watch | leftover in `$TMPDIR` / fake XDG / Library via `leftovers_created(watch)` | SURVIVED | **SURVIVED** | expected; `leftovers_in_run_window` CAUGHT |
| hardlink-created-after | new file + hardlink under the watch | CAUGHT | **CAUGHT** | still holds |
| hardlink-preexisting | hardlink of a file already in the snapshot | CAUGHT | **CAUGHT** | still holds |
| inode-reuse-same-path | delete + recreate, same path, same inode, new bytes | SURVIVED | **CAUGHT** | author's r3 fix holds |
| snapshot-after-write | `leftovers_created` after the leftover already existed | SURVIVED | **SURVIVED** | expected; `snapshot_before_runtime` CAUGHT |
| guard-dotdot / nested | `$ISOLATION/..` and `hold/../..` | SURVIVED | **CAUGHT** | author's r3 fix holds |
| guard-trailing-slash | isolated folder with a trailing slash | CAUGHT | **CAUGHT** | accepted as that folder |
| guard-slash-dot / slash-slash | `/.` and `//` | CAUGHT | **CAUGHT** | Rust treats both as `/` |
| guard-slash-dotdot | `/..` | CAUGHT | **CAUGHT** | `..` refuse |
| guard-relative | `relative-tmp` | CAUGHT | **CAUGHT** | still holds |
| guard-live-home-symlink | symlink under isolation → fake live Home | SURVIVED | **CAUGHT** | author's r3 fix holds |
| guard-home-symlink-env | symlink under isolation → `$HOME` | SURVIVED | **CAUGHT** | author's r3 fix holds |
| ra6-current | live journey | BLOCKED | **BLOCKED** | still holds |
| ra6-stub-ok | hosting stub returns `Ok(ResidentPair)` | SURVIVED as PASS | **FAIL**, not PASS | author's claim holds; r3 script still prints SURVIVED |
| mac-cleanup-* | quoted `rm`, glob, empty var, trap order | CAUGHT | **CAUGHT** | still holds |

## New r4 hunts

| Id | What was tried | Result |
| --- | --- | --- |
| r4-snapshot-before-runtime | leftover already present, then `snapshot_before_runtime` | **CAUGHT** |
| r4-run-window-siblings | `$TMPDIR` / XDG / Library via `leftovers_in_run_window` | **CAUGHT** |
| toctou-check-then-swap | `check_tmp_root` Ok, replace folder with live-Home symlink, write | **SURVIVED** (write landed outside) |
| toctou-missing-then-symlink | missing path accepted, then created as a symlink, write | **SURVIVED** (write landed outside) |
| bind-mount-into-census | `mount --bind` / `unshare -m` | **INCONCLUSIVE** (host refuses) |
| hardlink-from-outside | hardlink an outside file into the watch after the snapshot | **CAUGHT** |
| hardlink-escape-delete | hardlink to `/var/tmp`, delete the watch copy | **SURVIVED** |
| write-then-delete | write then delete before the after-snapshot | **SURVIVED** (leftover census) |
| writes-var-tmp | leftover under `/var/tmp` | **SURVIVED** |
| writes-dev-shm | leftover under `/dev/shm` | **SURVIVED** |
| writes-dot-cache-when-xdg-set | `$HOME/.cache` while `XDG_CACHE_HOME` is set | **INCONCLUSIVE** as a hide proof: the plant sat under isolation, so the run-window saw it. `extra_watch_roots` still omits `$HOME/.cache` when the XDG var is set. |
| ctime-same-content-reuse | delete+recreate, reused inode, same bytes | **SURVIVED** |
| large-file-mtime-restore | 65 KiB in-place rewrite, mtime restored | **SURVIVED** |
| detached-child-at-exit | child writes after a short sleep; census at "exit" | **SURVIVED** |
| detached-child-later-rescan | same snapshot after the child wrote | **CAUGHT** |
| empty-resident-pair | `status_after_host_ok(ResidentPair)` | **CAUGHT** (FAIL) |
| guard-var-tmp | `check_tmp_root("/var/tmp")` | **CAUGHT** (outside isolation) |
| a6-same-pid | two ids, one live pid (this process), stub Ok | **CAUGHT** (FAIL) |
| a6-reused-live-pids | two ids, this pid + pid 1, stub Ok | **SURVIVED** as PASS |

`runtime_temp_census()` still lists present paths under the roots. The
created-set lives in `leftovers_created` / `runtime_temp_census_since`
/ `leftovers_in_run_window` only.

## Guard and census mutants

| Id | Change | Named test | Result |
| --- | --- | --- | --- |
| M-R4-GUARD-NO-ISOLATION | drop "canonical path under mktemp" | `a12_slash_tmp_root_is_refused` | **SURVIVED** |
| M-R4-GUARD-NO-ISOLATION-HOME | same | `a12_home_and_live_home_tmp_root_are_refused` | **SURVIVED** |
| M-R4-GUARD-NO-ISOLATION-DOTDOT | same | `a12_isolation_parent_tmp_root_is_refused` | **SURVIVED** |
| M-R4-GUARD-SKIP-CHECK | `elastos_tmp_root` skips `check_tmp_root` | `a12_slash_tmp_root_is_refused` | **CAUGHT** |
| M-R4-GUARD-LEAF-SYMLINK | inspect only the final path component | `a12_symlink_to_live_home_tmp_root_is_refused` | **SURVIVED** |
| M-R4-CENSUS-NO-HASH | `content_hash` always 0 | `a12_inode_reuse_same_path_is_found` | **SURVIVED** |
| M-R4-CENSUS-NO-CTIME | `birth_or_ctime` always 0 | `a12_inode_reuse_same_path_is_found` | **SURVIVED** |
| M-R4-CENSUS-INO-ONLY | identity is only (dev,ino)+path | `a12_inode_reuse_same_path_is_found` | **CAUGHT** |
| M-R4-SNAP-IGNORE-LIVE | ignore `/tmp/elastos` in `snapshot_before_runtime` | `a12_snapshot_before_runtime_fails_if_already_wrote` | **SURVIVED** |

The author's inode-reuse plant changes the bytes, so dropping hash or
ctime alone still leaves a FileId move. Same-bytes reuse is the case
that needs a named test. The live-Home symlink plant is a leaf link,
so a walk that only looks at the last component still refuses it.

## Anders's resident-instance rule

**It does not meet the rule. The author does not claim that it does.**

Needed: two resident capsule instances inside one running Runtime /
Home; instance-1 uses its own session token through `validate`;
instance-2 presents that token and is refused `WrongCapsule`; removing
validate step 4 fails that live journey.

What #343 ran: one `CapabilityManager` in-process, two string capsule
ids, a real minted token, a real `from_base64` / `validate` call.
`capability.rs` still sends every request to pending. Owner A6 rows
still refuse the sibling by fixture deny. Full journeys: NOT RUN.

Can the RA-6 journey report PASS without two resident instances?
**Yes.** `try_host_two_resident_instances` and
`query_runtime_resident_instances` are stubs. An empty pair is FAIL.
Two distinct live `/proc` pids, two ids, and two grant strings are
PASS. On this head the live stubs return Err, so the ready journey is
BLOCKED. The named test panics on PASS and on FAIL. That stops a
false bookable claim from an empty pair. It still lets a fabricated
live-pid pair through the Pass branch.

## Mac pack cleanup

Both `run.sh` and `mac-pack.sh` do this:

```
PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-pack.XXXXXX")
cleanup_pack() { rm -rf "$PACK_TMP"; }
trap cleanup_pack EXIT
```

`$PACK_TMP` is quoted. There is no glob `rm`. The trap is registered
after `mktemp` succeeds. `PACK_TMP` is not `ELASTOS_TMP_ROOT` and is
not an unset variable at cleanup time. If `PACK_TMP` were empty,
GNU `rm -rf ""` refuses the empty operand. Cleanup cannot become
`rm -rf /`. It can delete only the folder `mktemp` created.

The three owner commands use those same quoted env vars. They are
safe to run on a Mac. They still exercise fixture deny and the
throwaway TMPDIR.

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
They do not close RA-6. They do not census a leftover the Runtime
wrote under `/tmp/elastos/storage`, `/var/tmp`, or `/dev/shm`.

Beyond them:

1. A live A6 journey that presents instance-1's real session token as
   a second *resident* instance inside one Home, and fails when step 4
   is removed from the Runtime that journey loaded. The Pass path must
   refuse two live pids that are not those instances.
2. Owner `census::cleanup` after a real `run`, including leftovers
   outside the pack watch (Runtime temp, `$TMPDIR`, `/var/tmp`,
   `/dev/shm`, cache dirs).
3. FileId that still sees a same-bytes inode reuse and an in-place
   large-file rewrite whose mtime was restored.
4. A guard that treats the path it returned as durable, or returns
   the canonical path and re-checks at use.

#343's own macOS branch still returns NotRun for resident instances.

## Principles

- 3 No ambient authority: the in-process token now binds a caller
  string; the live request path still goes to pending.
- 11 Fail closed, then explain: sibling `WrongCapsule` is typed; a
  symlink loop errors instead of PASS; `/`, `..`, and a live-Home
  symlink are refused. The Pass branch accepts two live `/proc` pids.
  A check-then-write after a symlink swap still lands outside.
- 12 Docs, code, tests, and operations must agree: FINDINGS.md is
  honest that this is not two resident instances. "Same-path
  delete+recreate that reuses an inode" is broader than the named
  test, which changes the bytes. The r3 SURVIVED labels the author
  called expected match the commands on this head.

DeepSeek: none.
