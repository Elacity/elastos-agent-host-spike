# Review r3 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343-r3/`. It does not edit #343's branch, other
`lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `87b974a1631efcf48e103f84d028eb5b1a2a3c7f`.
- Base of this review: `origin/spike/agent-host`
  `60ae15f34b41d2b50a2505b0cc0def5c7dfc90a5`.
- Prior reviews: PR #365 of head `011d01f2` — **FALSIFIED**. PR #380 of
  head `732b6990` — A6 and A12 not bookable (r2 survivors below).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS.
- How to run: `lab/review-a6-a12-343-r3/run.sh`.

Anders's rule, as given for this review: A6 counts only when two
independent resident capsule instances inside one Runtime complete the
journey. #343 does not claim that. This review treats every other
claim as unverified until a command on this machine showed it.

## Plain status

#343's own suite at `87b974a1` is `ok. 36 passed; 0 failed; 0 ignored`
in 38.37s. `--list` printed those 36 names. The author's plant runner
printed **15 CAUGHT lines** from **13 plants**. Plants restored
`manager.rs` byte-for-byte
(`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`
before and after). After the run, `ls /tmp/elastos` was `No such file
or directory`. The subject worktree stayed clean.

Every r2 survivor was independently replanted on this head and is now
**CAUGHT** by the author's named tests. That closes the r2 hide for
`moved-away`, marker-less leftovers, `/`, and unset `/tmp/elastos`.

A6 is still one in-process `CapabilityManager` and two capsule id
strings. The ready journey reports **BLOCKED (RA-6)** today. If the
hosting stub returns `Ok(ResidentPair)`, the same journey reports
**PASS** with no Runtime process and no second resident instance.
`ResidentPair` is empty. The named test forbids that PASS. The Pass
branch does not prove residency.

A12's created-set walk finds a child-process leftover and a hardlink
under the watched folder. It misses a leftover already present when
the snapshot is taken, a same-path inode reuse after delete+recreate,
and any leftover in a sibling folder (`$TMPDIR`, a fake XDG dir, a
fake `Library/Caches`). The guard refuses `/`, `//`, `/.`, empty,
`$HOME`, relative paths, and live Home *paths*. It accepts
`$ISOLATION/..` and a symlink that sits under isolation and points at
`$HOME` or a fake live Home. Writes follow that symlink.

`run.sh` and `mac-pack.sh` quote `rm -rf "$PACK_TMP"`. Cleanup cannot
become `rm -rf /` or a glob. It removes only the mktemp folder the
script created.

A6 and A12 stay in-flight.

## Verdict

**A6 is not bookable. A12 is not bookable.**

The Linux crate still mints a real token and calls real `validate`.
Sibling, prefix, empty, case, zero-width, other resource/action,
expired, revoked, and tampered-base64 cases return the typed Runtime
errors the pack names. That is one in-process manager. It is not two
resident capsule instances inside one Home.

The RA-6 journey reports BLOCKED while the hosting function returns
Err. Removing validate step 4 makes that journey FAIL (author plant
and independent replant). The journey can still report PASS without
the Runtime hosting two resident instances: flip
`try_host_two_resident_instances` to `Ok(ResidentPair)` and the Pass
branch only re-validates the same in-process token.

A12 now finds `moved-away` and a leftover with no lab marker, when the
snapshot is taken first and the watch root contains the rename. That
is the r2 hide, and it is closed. The created-set still hides a
leftover that was already on disk when `snapshot()` ran, and a
delete+recreate at the same path that reuses the inode. Leftovers
outside the watch root are invisible. The default
`runtime_temp_census()` lists every present path; it is not the
created-set. `ThrowawayHome::new` + `census::cleanup` are still NOT
RUN on Linux.

The tmp guard is tighter than r2. `/`, empty, `$HOME`, relative, and
named live Home paths are refused. A lexical `..` child of isolation,
and a live Home reached through a symlink that lives under isolation,
are accepted. The live pack scripts set `ELASTOS_TMP_ROOT` to the
mktemp folder itself, so they do not take those paths. The guard
function does not close them.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## Commands run

Subject suite, worktree `/tmp/pr343-r3` at `87b974a1`, no edits:

```
./lab/a6-a12-evidence-fix/run.sh
```

Result: `ok. 36 passed; 0 failed; 0 ignored` in 38.37s.
`--list` printed those 36 names.
Plant runner: 13 plants, 15 CAUGHT lines (F-A12-DROP-ROOTS and
M-A6-COMMENT-STEP4 each name two tests).
`manager.rs` sha256 identical before and after.
After the run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Independent r2-survivor replants (not the author's
`planted_bugs_are_caught`):

```
lab/review-a6-a12-343-r3/tools/replant.sh /tmp/pr343-r3
```

Result: all twelve named plants **CAUGHT**. `manager.rs`, `a12.rs`,
and `a6.rs` sha256 restored after each plant. Exit 0. See
`evidence/replant-r2.txt`.

New r3 hunts (injected, then restored):

```
lab/review-a6-a12-343-r3/tools/new-hunts.sh /tmp/pr343-r3
```

Result: `ok. 14 passed; 0 failed` (36 subject tests filtered out),
then the RA-6 stub plant. Worktree clean afterwards. See
`evidence/new-hunts.txt`.

Mac pack cleanup (read-only; no `rm` run against the host):

```
lab/review-a6-a12-343-r3/tools/mac-pack-probe.sh /tmp/pr343-r3
```

See `evidence/mac-pack-probe.txt`.

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome` needs
macOS).

## Per-claim table

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 36 named lib tests pass | **HOLDS** | `--list` printed 36 names; `run.sh` printed `36 passed` |
| 13 plants / 15 CAUGHT lines | **HOLDS** | exact CAUGHT lines in `evidence/subject-run.txt` |
| F-A6-NO-TOKEN-CHECK CAUGHT | **HOLDS** | sibling test FAILED under the plant |
| M-A6-PREFIX-BIND CAUGHT | **HOLDS** | author's plant + independent replant |
| M-A6-EMPTY-TOKEN CAUGHT | **HOLDS** | author's plant + independent replant |
| M-A6-COMMENT-STEP4 CAUGHT | **HOLDS** | sibling + RA-6 journey; independent replant of both |
| M-A6-CLAIM-RESIDENT CAUGHT | **HOLDS** | author's plant + independent replant |
| F-A12-DROP-ROOTS CAUGHT | **HOLDS** | list + plant tests FAILED |
| M-A12-HARDCODE-FAIL CAUGHT | **HOLDS** | clean PASS test FAILED |
| M-A12-SYMLINK-ROOT CAUGHT | **HOLDS** | symlink-through test FAILED |
| M-A12-RENAME-ROOT CAUGHT | **HOLDS** | created-set rename test FAILED |
| M-A12-RENAME-UNRELATED CAUGHT | **HOLDS** | r2 survivor; independent replant FAILED the named test |
| M-A12-NO-MARKER CAUGHT | **HOLDS** | r2 survivor; independent replant FAILED the named test |
| M-A12-TMP-SLASH CAUGHT | **HOLDS** | r2 survivor; `/` refused |
| M-A12-TMP-UNSET CAUGHT | **HOLDS** | r2 survivor; unset no longer defaults to `/tmp/elastos` |
| Plants restore `manager.rs` byte-identically | **HOLDS** | sha256 `cd4772f1…066b2a` before and after |
| Instance-1 may use its session token | **HOLDS** | real `grant` + `from_base64` + `validate` as instance-1 |
| Sibling presenting owner token is `WrongCapsule` with fields compared | **HOLDS** | `expected:instance-1 got:instance-2` |
| Prefix / empty / case / zwsp / other resource/action / expired / revoked / tampered | **HOLDS** | named tests printed the typed Runtime errors |
| RA-6 journey reports BLOCKED today | **HOLDS** | `BLOCKED (RA-6): … does not host two resident capsule instances` |
| RA-6 journey FAILs if validate step 4 is removed | **HOLDS** | independent `M-A6-COMMENT-STEP4-RA6` CAUGHT |
| RA-6 journey cannot PASS without two resident instances | **FALSIFIED** | `Ok(ResidentPair)` makes the journey PASS; pair is empty; no Runtime host |
| Cited owner lines still show the #294 holes | **HOLDS** | existing_* tests passed; request path still pending |
| `ThrowawayHome` + `census::cleanup` are invoked | **HOLDS** as a call | `ThrowawayHome::new()` runs and is NOT RUN on Linux |
| `ELASTOS_TMP_ROOT` set writes nothing under `/tmp/elastos` | **HOLDS** | suite left `/tmp/elastos` absent |
| Created-set finds `moved-away` and marker-less leftovers | **HOLDS** | author's tests + independent r2 replants |
| Created-set finds a leftover written by a child process | **HOLDS** | `HUNT child-process: CAUGHT` |
| Created-set finds leftovers after the census call ends | **WEAK** | first call misses them; a later call with the same snapshot finds them |
| Created-set finds leftovers in `$TMPDIR` / XDG / `Library/Caches` | **FALSIFIED** | `HUNT sibling-outside-watch: SURVIVED`; watch leftovers empty |
| Created-set finds hardlinks | **HOLDS** | new file + hardlink, and hardlink of a pre-existing file |
| Created-set finds inode reuse after delete+recreate at the same path | **FALSIFIED** | reused ino 675874; path absent from leftovers |
| Created-set finds leftovers if the snapshot is taken after Runtime wrote | **FALSIFIED** | leftover already in `before`; leftovers empty |
| Guard refuses `/`, empty, `$HOME`, relative | **HOLDS** | named tests + r3 hunts; `//` and `/.` compare equal to `/` |
| Guard refuses a path with `..` | **FALSIFIED** | `$ISOLATION/..` and `$ISOLATION/hold/../..` accepted |
| Guard refuses a trailing slash on the isolated folder | **HOLDS** | accepted as that same folder |
| Guard refuses a live Home reached through a symlink under isolation | **FALSIFIED** | accepted; write landed in the fake live Home |
| Mac pack cleanup can delete outside the isolated folder | **FALSIFIED** as a fear | quoted `rm -rf "$PACK_TMP"`; no glob; trap after mktemp; cannot become `rm -rf /` |
| These checks make A6 or A12 bookable | **FALSIFIED** | no resident instances; created-set and guard still have hides; owner journeys still fixture-deny / TMPDIR-only |
| Meets Anders's independent-resident-instances-in-one-Runtime rule | **FALSIFIED** | author does not claim it; the crate is one in-process manager |

## r2 survivors, replanted on this head

| Id | Change | Named test | Result |
| --- | --- | --- | --- |
| M-A6-PREFIX-BIND | `!=` → `starts_with` | `a6_prefix_capsule_id_is_refused` | **CAUGHT** |
| M-A6-EMPTY-TOKEN | skip check when capsule empty | `a6_empty_token_capsule_is_refused` | **CAUGHT** |
| M-A6-COMMENT-STEP4 | delete Runtime step 4 | `a6_sibling_presenting_owner_token_is_refused` | **CAUGHT** |
| M-A6-COMMENT-STEP4-RA6 | delete Runtime step 4 | `a6_resident_two_instances_is_blocked` | **CAUGHT** |
| M-A6-CLAIM-RESIDENT | map hosting Err to Pass | `a6_resident_two_instances_is_blocked` | **CAUGHT** |
| M-A12-HARDCODE-FAIL | census always FAIL | `a12_clean_isolated_root_passes` | **CAUGHT** |
| M-A12-SYMLINK-ROOT | do not follow symlink root | `a12_symlink_root_is_scanned_through` | **CAUGHT** |
| M-A12-RENAME-ROOT | created-set keeps nothing | `a12_renamed_root_is_found_by_created_set` | **CAUGHT** |
| M-A12-NO-MARKER | keep only leftover-marker bytes | `a12_leftover_without_marker_is_found` | **CAUGHT** |
| M-A12-RENAME-UNRELATED | hide any `moved-away` path | `a12_renamed_to_unrelated_name_is_found` | **CAUGHT** |
| M-A12-TMP-SLASH | drop the `/` refuse | `a12_slash_tmp_root_is_refused` | **CAUGHT** |
| M-A12-TMP-UNSET | unset defaults to `/tmp/elastos` | `a12_unset_tmp_root_is_refused` | **CAUGHT** |

r2's relative-root probe is now a refuse (`HUNT guard-relative: CAUGHT`).
r2's symlink-loop probe still fail-closes (`could not resolve symlink root`).

## New r3 hunts

| Id | What was tried | Result |
| --- | --- | --- |
| child-process | leftover written by `sh` after the snapshot | **CAUGHT** |
| after-census-first-call | leftover written after `leftovers_created` returns | **SURVIVED** that one result (inherent) |
| after-census-rescan | same leftover, second call, same snapshot | **CAUGHT** |
| sibling-outside-watch | leftover in `$TMPDIR`, fake XDG, fake `Library/Caches` | **SURVIVED** as a hide |
| hardlink-created-after | new file + hardlink under the watch | **CAUGHT** |
| hardlink-preexisting | hardlink of a file that was already in the snapshot | **CAUGHT** |
| inode-reuse-same-path | delete + recreate, same path, same inode | **SURVIVED** as a hide |
| snapshot-after-write | snapshot taken after the leftover already existed | **SURVIVED** as a hide |
| guard-dotdot | `ELASTOS_TMP_ROOT=$ISOLATION/..` | **SURVIVED** (accepted) |
| guard-dotdot-nested | `$ISOLATION/hold/../..` | **SURVIVED** (accepted) |
| guard-trailing-slash | isolated folder with a trailing slash | **CAUGHT** (accepted as that folder) |
| guard-slash-dot / slash-slash | `/.` and `//` | **CAUGHT** (Rust treats both as `/`) |
| guard-slash-dotdot | `/..` | **CAUGHT** (outside isolation) |
| guard-relative | `relative-tmp` | **CAUGHT** |
| guard-live-home-symlink | symlink under isolation → fake live Home, then write | **SURVIVED** (write landed outside) |
| guard-home-symlink-env | symlink under isolation → `$HOME` | **SURVIVED** (accepted) |
| ra6-current | live journey | **BLOCKED** |
| ra6-stub-ok | hosting stub returns `Ok(ResidentPair)` | **SURVIVED** as PASS without a Runtime host |
| mac-cleanup-* | quoted `rm`, glob, empty var, trap order | **CAUGHT** (cleanup stays inside the mktemp folder) |

`runtime_temp_census()` still lists present paths under the roots. The
created-set lives in `leftovers_created` / `runtime_temp_census_since`
only.

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
**Yes.** `try_host_two_resident_instances` is a stub. `ResidentPair`
has no fields. The Pass branch only repeats the in-process
`WrongCapsule` check. On this head the stub returns Err, so the live
journey is BLOCKED. The named test panics on PASS. That stops a false
bookable claim. It does not make the Pass path prove residency.

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
wrote under `/tmp/elastos/storage` or `$TMPDIR`.

Beyond them:

1. A live A6 journey that presents instance-1's real session token as
   a second *resident* instance inside one Home, and fails when step 4
   is removed from the Runtime that journey loaded. The Pass path must
   fail unless that pair is actually hosted.
2. Owner `census::cleanup` after a real `run`, including leftovers
   outside the pack watch (Runtime temp, `$TMPDIR`, cache dirs).
3. Created-set that still sees a same-path inode reuse and a leftover
   that existed before the snapshot (or the pack must take the
   snapshot before Runtime writes).
4. Guard must refuse a lexical `..` escape and a live Home reached
   through a symlink, not only the literal `$HOME` string.

#343's own macOS branch still returns NotRun for resident instances.

## Principles

- 3 No ambient authority: the in-process token now binds a caller
  string; the live request path still goes to pending.
- 11 Fail closed, then explain: sibling `WrongCapsule` is typed; a
  symlink loop errors instead of PASS; `/` is refused; `$ISOLATION/..`
  and a live-Home symlink are accepted.
- 12 Docs, code, tests, and operations must agree: FINDINGS.md is
  honest that this is not two resident instances; the created-set
  wording is broader than `runtime_temp_census()` and broader than
  what a late snapshot or an inode reuse can see.

DeepSeek: none.
