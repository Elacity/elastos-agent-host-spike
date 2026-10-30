# Review r5 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343-r5/`. It does not edit #343's branch, other
`lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `9d55f8fbd670bbaef9cd329fd795b5fb5cb9c04e`.
- Base of this review: `origin/spike/agent-host`
  `a165fb8df9723ec10c1e0cf1b7d6acb67b6c17fe`.
- Prior reviews: PR #365 of head `011d01f2` — **FALSIFIED**. PR #380 of
  head `732b6990`. PR #394 of head `87b974a1` — r3. PR #412 of head
  `19becdd7` — r4 **FIX**: Pass path accepted this pid plus pid 1;
  FileId missed same-bytes reuse and a 65 KiB in-place rewrite;
  isolation-under and the live `/tmp/elastos` snapshot half were
  untested; a leaf symlink swap after `check_tmp_root` wrote outside.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS. Bind mounts and `unshare -m` are refused
  here. Mac owner commands stay on hold.
- How to run: `lab/review-a6-a12-343-r5/run.sh`.
- Subject worktree: `/tmp/pr343-r5`, detached at the pin above.

Anders's rule, as given for this review: A6 counts only when two
independent resident capsule instances inside one Runtime complete the
journey. #343 does not claim that. A6 stays **BLOCKED (RA-6)** on this
head. This review judges the Linux A12 lab half on its own.

## Plain status

#343's own suite at `9d55f8fb` is `ok. 49 passed; 0 failed; 0 ignored`.
`--list` printed those 49 names. The author's plant runner printed
**28 CAUGHT lines** from **25 plants**. Plants restored `manager.rs`
byte-for-byte
(`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`
before and after). After the run, `ls /tmp/elastos` was `No such file
or directory`. The subject worktree stayed clean.

An independent replant of the same 25 plant files, not `plant.rs`,
printed the same **28 CAUGHT lines**. `manager.rs`, `a6.rs`, and
`a12.rs` hashes matched the clean tree after each restore.

The two r4 mutants the author now claims are CAUGHT hold against their
new named tests:

- Drop isolation-under → `a12_outside_isolation_tmp_root_is_refused`
  **CAUGHT**. The old slash test still stays green.
- Ignore `/tmp/elastos` in `snapshot_before_runtime` →
  `a12_snapshot_before_runtime_fails_if_live_tmp_elastos_wrote`
  **CAUGHT**. The watch-only late-snapshot test still stays green.

A6 is still one in-process `CapabilityManager` and two capsule id
strings. The ready journey reports **BLOCKED (RA-6)**. An empty
`ResidentPair` is **FAIL**. This process plus pid 1 is **FAIL**. A
sleep child of this process is **FAIL**. Two threads that share one
pid are **FAIL**. Two other live pids are **FAIL** until the inspect
stub is filled.

If `prove_resident_capsule_instance` is stubbed to `Ok`, the named
self+pid1 test **CAUGHT** that plant (the test panics on PASS). The
ready journey test stays green because `try_host_two_resident_instances`
still returns Err. `status_for_claimed_resident_pair` with two sleep
pids then returns **PASS** without RA-6. Stubbing only
`inspect_runtime_hosted_resident` to `Some(())` leaves the self+pid1
test green and still PASSes two sleep pids.

A12's FileId census on this ext4 host finds a rename, a leftover with
no lab marker, same-path same-bytes inode reuse, a 65 KiB in-place
rewrite with mtime restored, and a last-byte rewrite of a 65 KiB file.
Writes re-check the root, then open with `O_NOFOLLOW` / `openat`. A
sequential parent-directory swap after the first check is refused by
that re-check. If the re-check is dropped, the same parent swap writes
outside: `O_NOFOLLOW` only protects the leaf. `/var/tmp` and `/dev/shm`
stay unseen. A file written then deleted between snapshots stays unseen.

`run.sh` and `mac-pack.sh` still quote `rm -rf "$PACK_TMP"`. The three
Mac owner commands stay on hold.

## Verdict

**A12 Linux lab half: PASS**

**A6: BLOCKED (RA-6)**

The r4 A12 holes the author named as fixed hold on this machine. The
suite count, the plant count, the restore hash, and the two r4 mutants
are real. A6 is still not two resident capsule instances inside one
Runtime. Stubbing prove or inspect can still mint a Pass string from
two live sleep pids and an in-process `WrongCapsule` check. The ready
journey stays BLOCKED because the host stub still returns Err.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## What counts for A12 on Linux

On this Linux host, A12 credit in this pack is:

- a created-set walk under the isolation mktemp, keyed by FileId
  `(dev, inode, ctime nsec, size+full-content hash, name_to_handle_at)`;
- `snapshot_before_runtime` refusing a watch that already holds
  `storage/` or `elastos/` (or a live `/tmp/elastos` that already
  holds files);
- `leftovers_in_run_window` seeing new entries under `$TMPDIR`,
  `XDG_CACHE_HOME` / `XDG_DATA_HOME` / `XDG_STATE_HOME` /
  `XDG_RUNTIME_DIR`, and `$HOME/Library/Caches` plus
  `$HOME/Library/Application Support`;
- `ELASTOS_TMP_ROOT` refused when it is `/`, empty, relative,
  `$HOME`, a live Home path, a `..` component, a symlink at or under
  isolation, `/var/tmp`, or a canonical path outside the mktemp;
- writes that re-check the root and then open with `O_NOFOLLOW` /
  `openat`, so a leaf or parent symlink swap after the first check
  does not land a leftover (the write-time re-check refuses it).

## A12 on Linux still does not cover

The author's list still holds. These additions belong on it.

- `ThrowawayHome` + `census::cleanup` (NOT RUN; needs macOS)
- leftovers under `/var/tmp` or `/dev/shm` (**SURVIVED** here)
- a file that existed only between the two snapshots (**SURVIVED**)
- a detached child write after the first census returns
- a bind mount into the watch (this host refuses `mount --bind`)
- a hardlink copied out of the watch, then the watch copy deleted
- `$HOME/.cache` while `XDG_CACHE_HOME` is set
- content hash of a sparse hole equals zeros (`fs::read` sees zeros);
  FileId still moves via ctime on this host
- the named 65 KiB rewrite test changes byte 0; a hash that only
  covers the first 64 KiB still passes that test
- `name_to_handle_at` fallback is an empty handle. Plant
  `M-A12-NO-HANDLE` is **CAUGHT** on this ext4 host, so that fallback
  is weaker for same-bytes reuse. This host's `/dev/shm` tmpfs still
  returns a 20-byte handle, so EOPNOTSUPP was not observed here
- the check-to-open path walk is still a race: sequential parent swap
  is **CAUGHT** by the write-time re-check; `O_NOFOLLOW` on the leaf
  alone writes outside

Owner `census.rs` still walks the throwaway TMPDIR only.

## Commands run

Subject suite, worktree `/tmp/pr343-r5` at `9d55f8fb`, no edits:

```
./lab/a6-a12-evidence-fix/run.sh
```

Result: `ok. 49 passed; 0 failed; 0 ignored`.
`--list` printed those 49 names.
Plant runner: 25 plants, 28 CAUGHT lines (F-A12-DROP-ROOTS,
M-A12-TMP-DOTDOT, and M-A6-COMMENT-STEP4 each name two tests).
`manager.rs` sha256 identical before and after.
After the run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Independent replants (not the author's `planted_bugs_are_caught`):

```
lab/review-a6-a12-343-r5/tools/replant.sh /tmp/pr343-r5
```

Result: 25 plants, 28 CAUGHT lines. `manager.rs` sha256
`cd4772f1…066b2a` after each restore. Exit 0. See
`evidence/replant.txt`.

r4 mutants, independently:

```
lab/review-a6-a12-343-r5/tools/mutants.sh /tmp/pr343-r5
```

See `evidence/mutants.txt`.

r5 hunts and new plants:

```
lab/review-a6-a12-343-r5/tools/new-hunts.sh /tmp/pr343-r5
```

See `evidence/new-hunts.txt`.

Mac pack cleanup (read-only; no `rm` run against the host). Mac owner
journeys on hold:

```
lab/review-a6-a12-343-r5/tools/mac-pack-probe.sh /tmp/pr343-r5
```

See `evidence/mac-pack-probe.txt`.

r3 runner pin (from `lab/review-a6-a12-343-r3/run.sh` on
`origin/cursor/review-a6-a12-343-r3-c383`):

```
# PIN=87b974a1631efcf48e103f84d028eb5b1a2a3c7f
# subject HEAD=9d55f8fbd670bbaef9cd329fd795b5fb5cb9c04e
# REFUSE
```

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome` needs
macOS). Bind-mount leftover into the census (this host refuses mount).
Pid reuse after a proven inspect (this host did not recycle the pid
in 400 spawns).

## Per-claim table

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 49 named lib tests pass | **HOLDS** | `--list` printed 49 names; `run.sh` printed `49 passed` |
| 25 plants / 28 CAUGHT lines | **HOLDS** | author runner and independent replant |
| Plants restore `manager.rs` byte-identically | **HOLDS** | sha256 `cd4772f1…066b2a` before and after |
| A6 Pass needs `prove_resident_capsule_instance`; self + pid 1 FAIL | **HOLDS** | named test + r5 child / two-other-pid hunts |
| empty until RA-6 | **HOLDS** for the ready journey | `try_host` still returns Err; inspect is `None` |
| FileId is inode+dev+ctime nsec+full-content hash+handle | **HOLDS** on this ext4 host | same-bytes, 65 KiB, last-byte, `M-A12-NO-HANDLE` |
| writes re-check via `O_NOFOLLOW` / `openat` | **HOLDS** for sequential swaps | leaf plant + r5 parent swap **CAUGHT**; no-recheck parent swap **SURVIVED** |
| isolation-under mutant CAUGHT | **HOLDS** | `M-R4-GUARD-NO-ISOLATION` against `a12_outside_isolation_tmp_root_is_refused` |
| `/tmp/elastos` snapshot-half mutant CAUGHT | **HOLDS** | `M-R4-SNAP-IGNORE-LIVE` against the live-snap test |
| two resident instances | **BLOCKED (RA-6)** | ready journey; owner rows still fixture deny |

## Author plants, independently replanted

All 25 plants **CAUGHT**. 28 CAUGHT lines. No SURVIVED. See
`evidence/replant.txt`.

## r4 mutants, independently reapplied

| Id | Change | Named test | Result |
| --- | --- | --- | --- |
| M-R4-GUARD-NO-ISOLATION | drop isolation-under | `a12_outside_isolation_tmp_root_is_refused` | **CAUGHT** |
| M-R4-GUARD-NO-ISOLATION-SLASH | same | `a12_slash_tmp_root_is_refused` | **SURVIVED** (expected; slash still refuses `/`) |
| M-R4-SNAP-IGNORE-LIVE | ignore `/tmp/elastos` | `a12_snapshot_before_runtime_fails_if_live_tmp_elastos_wrote` | **CAUGHT** |
| M-R4-SNAP-IGNORE-LIVE-WATCH | same | `a12_snapshot_before_runtime_fails_if_already_wrote` | **SURVIVED** (expected; watch leftover still fails the snapshot) |

## New r5 hunts

| Id | What was tried | Result |
| --- | --- | --- |
| r5-child-pid | this process plus a sleep child | **CAUGHT** (this lab process is not a capsule) |
| r5-prove-child | `prove` on a sleep child | **CAUGHT** (not positively proven) |
| r5-two-threads | two instance ids, one pid | **CAUGHT** (pids must be distinct) |
| r5-two-other-pids | two sleep pids, inspect still `None` | **CAUGHT** |
| r5-pid-reuse | kill a child, wait for the same pid | **INCONCLUSIVE** (not recycled in 400 spawns) |
| r5-ra6-current | live ready journey | **BLOCKED** |
| r5-handle-tmpfs | `name_to_handle_at` on `/dev/shm` | **CAUGHT** (20-byte handle; not EOPNOTSUPP here) |
| r5-handle-tmpfs-reuse | same-bytes reuse on tmpfs | **INCONCLUSIVE** (inode not reused) |
| r5-sparse-hash | zero-fill a 1 MiB hole | **SURVIVED** (`fs::read` hash unchanged) |
| r5-sparse-identity | same plant, FileId leftover | **CAUGHT** (ctime/handle still move) |
| r5-growing-file | append after snapshot | **CAUGHT** |
| r5-last-byte | 65 KiB file, last byte only | **CAUGHT** |
| r5-parent-swap | sequential parent symlink after first check | **CAUGHT** (write-time re-check) |
| r5-var-tmp | leftover under `/var/tmp` | **SURVIVED** |
| r5-dev-shm | leftover under `/dev/shm` | **SURVIVED** |
| r5-write-then-delete | create then delete before after-snapshot | **SURVIVED** |

## New r5 plants (stubs and weaker fallbacks)

| Id | Change | Result |
| --- | --- | --- |
| R5-PROVE-ALWAYS-OK | `prove` returns `Ok` | **CAUGHT** by `a6_this_process_and_pid1_cannot_pass` (panic: PASS with this pid plus pid 1) |
| R5-PROVE-ALWAYS-OK-JOURNEY | same | **SURVIVED** against `a6_resident_two_instances_is_blocked` (still BLOCKED via `try_host`) |
| R5-PROVE-ALWAYS-OK-OTHER-PIDS | same | **SURVIVED** as PASS: two sleep pids, no RA-6 host |
| R5-INSPECT-ALWAYS-SOME | inspect returns `Some(())` | **SURVIVED** against the self+pid1 test (those pids still fail before inspect) |
| R5-INSPECT-ALWAYS-SOME-JOURNEY | same | **SURVIVED** (ready journey still BLOCKED) |
| R5-INSPECT-ALWAYS-SOME-OTHER-PIDS | same | **SURVIVED** as PASS: two sleep pids, no RA-6 host |
| R5-NO-RECHECK-PARENT-SWAP | skip write-time `check_tmp_root` | **SURVIVED**: write landed outside after a parent swap |
| R5-HASH-CAP-64K | hash only the first 64 KiB | **SURVIVED** against last-byte rewrite |
| R5-HASH-CAP-64K-NAMED | same | **SURVIVED** against the named 65 KiB test (that test changes byte 0) |
| R5-HANDLE-EMPTY | force empty file handle | probe **SURVIVED** (reports empty); author's `M-A12-NO-HANDLE` remains **CAUGHT** on ext4 |

`prove` stubbed to true does **not** make the ready journey PASS.
`try_host` still returns Err. It does make
`status_for_claimed_resident_pair` PASS, and it makes the named
self+pid1 test fail closed on that PASS. Inspect stubbed to
`Some(())` leaves the named self+pid1 test green and still PASSes two
other live pids.

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
**The ready function cannot:** `try_host_two_resident_instances`
returns Err, so the status is BLOCKED. **The claimed-evidence Pass
path can:** stub `prove` or inspect, feed two live pids that are not
this process or pid 1, and `status_for_claimed_resident_pair` returns
Pass. That is still two live `/proc` pids and an in-process
`WrongCapsule` check.

## Mac pack cleanup

Both `run.sh` and `mac-pack.sh` quote `rm -rf "$PACK_TMP"`. There is
no glob `rm`. The trap is after `mktemp`. Cleanup cannot become
`rm -rf /`. Mac owner journeys stay on hold.

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

Beyond them:

1. A live A6 journey that presents instance-1's real session token as
   a second *resident* instance inside one Home, and fails when step 4
   is removed from the Runtime that journey loaded. The Pass path must
   refuse two live pids that are not those instances, including when
   inspect is later filled in.
2. Owner `census::cleanup` after a real `run`, including leftovers
   outside the pack watch (Runtime temp, `$TMPDIR`, `/var/tmp`,
   `/dev/shm`, cache dirs).

#343's own macOS branch still returns NotRun for resident instances.

## Principles

- 3 No ambient authority: the in-process token binds a caller string;
  the live request path still goes to pending.
- 11 Fail closed, then explain: sibling `WrongCapsule` is typed; a
  symlink loop errors; `/`, `..`, a live-Home symlink, and a sequential
  parent swap are refused. The claimed-evidence Pass branch still
  accepts two live `/proc` pids once prove or inspect is stubbed.
- 12 Docs, code, tests, and operations must agree: FINDINGS.md is
  honest that this is not two resident instances. The NOT COVERED
  list matches the commands on this head once sparse-hash, the 64 KiB
  hash-cap gap, the empty-handle fallback, and the parent-swap race
  are added.
- 18 Executable capsules are isolated execution environments: a pid
  is not a resident capsule until RA-6 fills the inspect.

DeepSeek: none.
