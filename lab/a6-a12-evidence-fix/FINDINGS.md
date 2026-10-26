# A6 / A12 evidence findings

Lab folder: `lab/a6-a12-evidence-fix/`. Head is this branch. Machine: Linux
x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`. Every path, line number, and
count below comes from a command run in this session.

## Plain status

#343 mints a real Runtime session token and calls real `validate`. A12
census records the (dev, inode, ctime, full-content hash) set a run
created, so a rename to `moved-away`, a leftover with no lab marker, a
same-path delete+recreate that reuses an inode with the same bytes, and
a 65 KiB in-place rewrite with mtime restored are found. The snapshot is
taken before the Runtime starts; if the Runtime already wrote under the
watch or under `/tmp/elastos`, that snapshot fails. The run-window watch
also covers `$TMPDIR`, XDG cache/data/state/runtime dirs, and
`~/Library/Caches` / `~/Library/Application Support`. `run.sh` sets
`ELASTOS_TMP_ROOT` to a fresh mktemp folder. The guard canonicalizes
(realpath) first and refuses `/`, empty, `$HOME`, a `..` component, a
symlink at or under isolation, a reachable live Home, `/var/tmp`, and
anything whose canonical path is not inside that folder. Writes reopen
the checked path with `O_NOFOLLOW` / `openat`, so a symlink swap after
the check cannot land a leftover in a fake live Home.

This Linux journey is still not two independent resident capsule instances
inside one Runtime. The ready A6 journey reports **BLOCKED (RA-6)**. An
`Ok` from a stub with an empty `ResidentPair` is FAIL. This process plus
pid 1 is FAIL. The journey never PASS until RA-6 and a real Runtime host
proves two resident capsule instances inside one Runtime, each holding
its own grant, sibling refused by the Runtime.

## Did #323 or base already fix these?

No. Skip neither check.

- Draft PR #323 still lists **A6 pending routing** and **A12
  `/tmp/elastos/storage`** as **NEEDS RUNTIME**.
- The gap tests in this folder still pass: owner A6 rows do not present a
  token, and owner `census.rs` still does not name `/tmp/elastos/storage`.

## Wrong existing tests

| File | Lines | Why it is not the claimed evidence |
| --- | --- | --- |
| `lab/agent-conformance/src/census.rs` | 79, 100, 124 | Temp walk is the throwaway TMPDIR only. Line 124 never walks `/tmp/elastos/storage`. |
| `lab/agent-conformance/tests/runtime.rs` | 324, 340 | A leftover under `/tmp/elastos/storage` is not a failure. |
| `lab/agent-conformance/tests/effects.rs` | 657, 662 | Both call `exercise_read`. No `WrongCapsule` / `from_base64`. |
| `lab/agent-conformance/tests/common/grants.rs` | sibling deny | Fixture deny, not Runtime `validate` step 4. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs` | 119 | Every request still goes to pending. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs` | 409–411 | Step 4 exists. This folder now calls it. Owner A6 journeys still do not. |
| `lab/agent-conformance/src/harness.rs` | 18 | Throwaway Homes require macOS. |

## Corrected checks

- **A6** `Session::mint_instance1` calls `CapabilityManager::grant`, then
  `from_base64` / `validate`. Owner use is `Ok`. Sibling use is
  `ValidationError::WrongCapsule { expected, got }` with those two fields
  compared. Prefix, empty, case, zero-width, other resource/action,
  expired, revoked, and tampered-base64 cases are named tests.
  Commenting out Runtime step 4 fails the sibling test and the RA-6
  journey. Two resident instances are RA-6; the ready journey is
  BLOCKED. An `Ok` from a stub with an empty `ResidentPair` is FAIL
  (plant M-A6-STUB-OK). This process plus pid 1 is FAIL (plant
  M-A6-LIVE-PIDS). PASS needs a real Runtime host.
- **A12** roots honour a guarded `ELASTOS_TMP_ROOT` after realpath. Census
  uses (dev, inode, ctime, full-content hash), not a name prefix, lab
  marker, birth time, or size+mtime. The snapshot fails if the Runtime
  already wrote under the watch or `/tmp/elastos`. The run-window watch
  includes `$TMPDIR`, XDG dirs, and Mac Library dirs. Writes use
  `O_NOFOLLOW` / `openat`. Symlink roots are resolved; a symlink loop is
  refused. `ThrowawayHome::new` + `census::cleanup` are invoked; Linux is
  NOT RUN.

## Linux vs resident instances

This crate builds one in-process `CapabilityManager` and two capsule ids
(`instance-1`, `instance-2`). That is the Runtime grant/validate path. It is
not two independent resident capsule instances inside one running Home.
Anders's A6 bookability rule still needs RA-6.

## Verdicts

Command: `./lab/a6-a12-evidence-fix/run.sh`

Result: `test result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 50.64s`.
`planted_bugs_are_caught` printed **22 CAUGHT lines** from **19 plants**
(F-A12-DROP-ROOTS, M-A12-TMP-DOTDOT, and M-A6-COMMENT-STEP4 each name two
tests). After the suite, `ls /tmp/elastos` was `No such file or directory`.
Runtime `manager.rs` sha256 stayed
`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`.
r3 `lab/review-a6-a12-343-r3/run.sh` refuses this head (it pins
`87b974a1`). `tools/new-hunts.sh` on this head: `..` and live-Home
symlink guards **CAUGHT**; inode reuse **CAUGHT**. The r3
`leftovers_created(watch)` probes for a late snapshot and a sibling
folder still print SURVIVED; those cases are CAUGHT by
`snapshot_before_runtime` and `leftovers_in_run_window`. The r3
`ra6-stub-ok` script prints SURVIVED because the named test FAILED;
the panic text is FAIL on empty `ResidentPair`, not PASS. Plant
M-A6-STUB-OK is CAUGHT.

| Check | Verdict | Notes |
| --- | --- | --- |
| A6 owner token accepted | **PASS** | real `grant` + `validate` as instance-1 |
| A6 sibling token refused | **PASS** | `WrongCapsule { expected:instance-1 got:instance-2 }` |
| A6 prefix / empty / case / zwsp | **PASS** | exact capsule id |
| A6 other resource/action sibling | **PASS** | WrongCapsule first |
| A6 expired / revoked / tampered | **PASS** | Runtime refusals named in the pack |
| A6 resident two instances | **BLOCKED (RA-6)** | empty stub Ok is FAIL; this pid + pid 1 is FAIL; never PASS from a stub |
| A12 created-set census | **PASS** | `moved-away`, no-marker, same-bytes inode reuse, 65 KiB rewrite found |
| A12 slash / unset / HOME / `..` / live-Home symlink / `/var/tmp` | **PASS** | refused after realpath |
| A12 snapshot after Runtime wrote | **PASS** | watch leftover and live `/tmp/elastos` fail the snapshot |
| A12 TOCTOU symlink swap after check | **PASS** | write refused; nothing landed outside |
| A12 run-window TMPDIR / XDG / Library | **PASS** | new entries found |
| A12 symlink loop | **PASS** | fail closed |
| A12 in-root `census::cleanup` | **NOT RUN** | `ThrowawayHome::new` refused on Linux |
| Existing A6/A12 gap pins | **PASS** | owner files still have the #294 holes |

## Falsifiers

| Id | What it breaks | Named tests that FAILED |
| --- | --- | --- |
| F-A6-NO-TOKEN-CHECK | Runtime `if token.capsule != caller` becomes `if false &&` | `tests::a6_sibling_presenting_owner_token_is_refused` |
| M-A6-PREFIX-BIND | `!=` becomes `!caller.starts_with(token)` | `tests::a6_prefix_capsule_id_is_refused` |
| M-A6-EMPTY-TOKEN | skip the check when `token.capsule` is empty | `tests::a6_empty_token_capsule_is_refused` |
| M-A6-COMMENT-STEP4 | delete Runtime step 4 | `tests::a6_sibling_presenting_owner_token_is_refused`, `tests::a6_resident_two_instances_is_blocked` |
| M-A6-CLAIM-RESIDENT | RA-6 journey returns Pass | `tests::a6_resident_two_instances_is_blocked` |
| M-A6-STUB-OK | hosting stub returns `Ok(ResidentPair)` | `tests::a6_resident_two_instances_is_blocked` |
| M-A6-LIVE-PIDS | drop resident-capsule proof on claimed pids | `tests::a6_this_process_and_pid1_cannot_pass` |
| F-A12-DROP-ROOTS | `runtime_owned_temp_roots` returns empty | `tests::a12_census_lists_runtime_storage`, `tests::a12_planted_storage_file_is_caught` |
| M-A12-HARDCODE-FAIL | census always returns FAIL | `tests::a12_clean_isolated_root_passes` |
| M-A12-SYMLINK-ROOT | do not scan through a symlink root | `tests::a12_symlink_root_is_scanned_through` |
| M-A12-RENAME-ROOT | created-set keeps nothing | `tests::a12_renamed_root_is_found_by_created_set` |
| M-A12-RENAME-UNRELATED | hide any path under `moved-away` | `tests::a12_renamed_to_unrelated_name_is_found` |
| M-A12-NO-MARKER | keep only leftover-marker bytes | `tests::a12_leftover_without_marker_is_found` |
| M-A12-TMP-SLASH | drop the `/` refuse | `tests::a12_slash_tmp_root_is_refused` |
| M-A12-TMP-UNSET | unset defaults to `/tmp/elastos` | `tests::a12_unset_tmp_root_is_refused` |
| M-A12-TMP-DOTDOT | drop the `..` refuse | `tests::a12_isolation_parent_tmp_root_is_refused`, `tests::a12_nested_dotdot_tmp_root_is_refused` |
| M-A12-TMP-LIVE-SYMLINK | drop the isolation symlink refuse | `tests::a12_symlink_to_live_home_tmp_root_is_refused` |
| M-A12-SNAP-AFTER-WRITE | allow a snapshot after Runtime wrote | `tests::a12_snapshot_before_runtime_fails_if_already_wrote` |
| M-A12-SNAP-IGNORE-LIVE | ignore `/tmp/elastos` in the late snapshot | `tests::a12_snapshot_before_runtime_fails_if_live_tmp_elastos_wrote` |
| M-A12-NO-ISOLATION | drop the isolation-under check | `tests::a12_outside_isolation_tmp_root_is_refused` |
| M-A12-INODE-REUSE | identity is only (dev,ino)+path | `tests::a12_inode_reuse_same_path_is_found` |
| M-A12-NO-CTIME | FileId ctime is always 0 | `tests::a12_same_bytes_inode_reuse_is_found` |
| M-A12-HASH-MTIME | large files hash size+mtime | `tests::a12_large_file_inplace_rewrite_mtime_restored_is_found` |
| M-A12-TOCTOU-FOLLOW | write follows a symlink after the check | `tests::a12_tmp_root_symlink_swap_after_check_cannot_write_outside` |
| M-A12-SIBLING-WATCH | extra watch roots are empty | `tests::a12_run_window_watches_tmpdir_xdg_library` |

## Plants table (r3)

| Plant | Result |
| --- | --- |
| F-A6-NO-TOKEN-CHECK | **CAUGHT** |
| M-A6-PREFIX-BIND | **CAUGHT** |
| M-A6-EMPTY-TOKEN | **CAUGHT** |
| M-A6-COMMENT-STEP4 | **CAUGHT** (sibling + RA-6 journey) |
| M-A6-CLAIM-RESIDENT | **CAUGHT** |
| M-A6-STUB-OK | **CAUGHT** |
| M-A6-LIVE-PIDS | **CAUGHT** |
| F-A12-DROP-ROOTS | **CAUGHT** (two tests) |
| M-A12-HARDCODE-FAIL | **CAUGHT** |
| M-A12-SYMLINK-ROOT | **CAUGHT** |
| M-A12-RENAME-ROOT | **CAUGHT** |
| M-A12-RENAME-UNRELATED | **CAUGHT** |
| M-A12-NO-MARKER | **CAUGHT** |
| M-A12-TMP-SLASH | **CAUGHT** |
| M-A12-TMP-UNSET | **CAUGHT** |
| M-A12-TMP-DOTDOT | **CAUGHT** (`$ISOLATION/..` and `hold/../..`) |
| M-A12-TMP-LIVE-SYMLINK | **CAUGHT** |
| M-A12-SNAP-AFTER-WRITE | **CAUGHT** |
| M-A12-SNAP-IGNORE-LIVE | **CAUGHT** |
| M-A12-NO-ISOLATION | **CAUGHT** |
| M-A12-INODE-REUSE | **CAUGHT** |
| M-A12-NO-CTIME | **CAUGHT** |
| M-A12-HASH-MTIME | **CAUGHT** |
| M-A12-TOCTOU-FOLLOW | **CAUGHT** |
| M-A12-SIBLING-WATCH | **CAUGHT** |

## Still BLOCKED

- **RA-6** — two resident capsule instances in one Runtime. The ready
  journey is written. It reports BLOCKED. A stub `Ok(ResidentPair)` is
  FAIL. This process plus pid 1 is FAIL. It does not PASS.
- **ThrowawayHome / owner `census::cleanup`** — NOT RUN on Linux.
- **Mac owner A6/A12 commands** — NOT RUN here. `run.sh` and
  `mac-pack.sh` set isolated `ELASTOS_TMP_ROOT` for them. Those owner
  rows still use fixture deny, so they do not close RA-6.

A6 and A12 stay in-flight for Anders's resident-instance rule.

## A12 on Linux still does not cover

These remain uncovered on this host. They are not claimed as PASS.

- `ThrowawayHome` + `census::cleanup` (NOT RUN; needs macOS)
- leftovers under `/var/tmp` or `/dev/shm`
- a file that existed only between the two snapshots (write then delete)
- a detached child write after the first census returns
- a bind mount into the watch (this host refuses `mount --bind`)
- a hardlink copied out of the watch, then the watch copy deleted
- `$HOME/.cache` while `XDG_CACHE_HOME` is set (`extra_watch_roots`
  uses the XDG var)

## NOT RUN (macOS / resident instances)

`run.sh` and `mac-pack.sh` set isolated `ELASTOS_TMP_ROOT` for:

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

Those owner rows still use fixture deny. They do not close RA-6. They
do not census a leftover the Runtime wrote under `/tmp/elastos/storage`
or `$TMPDIR` unless the Mac run uses this pack's run-window snapshot
(taken before the Runtime starts).
