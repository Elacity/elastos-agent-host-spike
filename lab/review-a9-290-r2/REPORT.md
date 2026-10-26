# Adversarial review r2 of PR #290 (M1 check A9)

Draft only. Do not merge. This folder does not edit `lab/owned-storage/`.

```text
Lane:         lab/review-a9-290-r2
Branch / PR:  cursor/review-a9-290-r2-26be
Reviewed:     Elacity/elastos-agent-host-spike#290
Head:         2e5c37293279996fcb98ee2623381264f2d92e3f
Tree:         /tmp/pr-290-r2 (detached, not pushed)
Base of #290: spike/agent-host merge-base b5069b992dac29d1457576efabd5700e34ea05e7
This branch:  origin/spike/agent-host e70f6e7c75f582e542d436d82ef928d4b98e1121
Machine:      Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM
elastos:      not on PATH
```

## A9 wording used here

> another agent's files are denied

Anders's counting rule, as given for this review: a check counts only when
its complete journey as worded passes, with a refusal that carries a reason
plus a CAUGHT falsifier, and the required reviews. Lab evidence for a
Runtime-side property stays evidence until the Runtime half passes.

#290's body still names the check as lab only. Tracker status is not in this
repository. A9 depends on A5 owned storage. Draft #309 lists RA-3 (`run`
storage from Home) as the small Runtime ask. AC-006-STORAGE is the standing
launcher blocker in `lab/agent-conformance/GAPS.md`.

Round 1 (`lab/review-a9-290`, draft #336) at `c0b16491` found A9 not
bookable and FALSIFIED the root-swap, hard-link, host same-uid walk, and
the missing fourth `/tmp` site. This round reviews the claimed six fixes
at `2e5c3729`.

## Verdict

**A9 is not bookable.**

Lab half: **not bookable** as the complete wording. The Store denies the
paths the official tests name, each with a reason. Two Store journeys still
let agent B see or receive bytes that started as A's, or let A create a
file in B's tree: hard-link then unlink A's name, and a TOCTOU on an
intermediate directory. Those are Store API results, not only a host walk.

Full check: **not bookable**. The product journey is two Runtime agents.
#290 starts no component. Both Runtime rows stay `Blocked`, `executed=false`,
`read_refusal=None`. GitHub has no reviews on #290. The PR is draft.

Lab evidence stays evidence. It does not count as the Runtime half.

## How this review ran

`run.py` attaches a detached worktree at `2e5c3729`, reruns #290's own
commands, then compiles `probe.rs` against that crate through
`lab/review-a9-290-r2/scratch`. The probe calls public `owned-storage`
APIs plus host `fs` on `host_root()` paths. `mutants.py` reverts each
claimed fix in that worktree, runs the named test, and restores the
original bytes.

Session results: `last-run.json`, `mutants-run.json`.

```text
lib.rs    sha256 6082614420f0f603fd8b5fd6cbcc088642bc2ba5d24fdaaf5fb80f170e03b61f
launch.rs sha256 d3ed87a9acfe22eab892fa13083a9ea6dabbdbbc37ac9501610f027a6c2c267c
worktree  clean before and after
/tmp/elastos/storage  absent before and after
```

## Per-claim table

| ID | Claim (as #290 worded it) | Verdict | What this session did |
| --- | --- | --- | --- |
| 1 root-swap | Swapping a storage root for a symlink is refused | HOLDS on clean code; WEAK as a leak-falsifier | Clean `read`/`write` return `Refuse::Symlink`; B's bytes stay `b-secret`. Plant `F-A9-root-swap` / mutant `M-root-swap` fails because the reason becomes `HardLink`, not because `read` returns `b-secret`. The PR's "before the fix, read returned b-secret" is stale on this head: `inode_in_owner_tree` already stops the leak when the root is a symlink. |
| 2 hard-link live | A hard link with `nlink > 1` is refused | HOLDS | `Store::read`/`write` of B's `hard.txt` while A's name still exists returns `Refuse::HardLink`. Official test and plant `F-A9-hardlink` match. Plant leak is real: with `refuse_hard_link` a no-op, `read` returns `hello-a`. |
| 2b hard-link unlink | A hard-linked inode from another agent is refused after the other name is removed | FALSIFIED | `hard_link(A/note.txt, B/hard.txt)` then `remove_file(A/note.txt)`: `nlink=1`, `Store::read(&b, "hard.txt")` returns `hello-a`, `Store::write` returns `Ok`. Same-uid helper, no mount. The Store then treats the inode as B's. |
| 3 list/rename | Store `list` and `rename` deny the other agent | HOLDS for the Store API | `list`/`rename` of B's host path return `Refuse::CrossAgent` with reason `cross-agent storage is refused`. Own list/rename works. |
| 3b host list/rename | The host process cannot list or rename A's files | HOLDS as documented hole | Same-uid walk still reads A's bytes. Row stays `NeedsConfinement`. #290 does not claim the Store confines the process. |
| 4 fourth `/tmp` site | Four shared-temp constructors, including `share_cmd.rs:183` | HOLDS | `create_runtime("/tmp/elastos/storage")` count: `run_cmd.rs` 3, `share_cmd.rs` 1. `main.rs:123` is a fifth *literal* (serve `--storage-path` default), not a fourth constructor. Lab `Store::open` did not create `/tmp/elastos/storage`. Mutant `share_count = 0` fails: `share_cmd.rs:183 must stay a fourth shared-temp site`. |
| 5 lab / Runtime split | Lab Ready, Runtime Blocked, no fake Runtime evidence | HOLDS | `lab_journey` Ready. Both Runtime rows `Blocked`, reasons start `BLOCKED AC-006-STORAGE:`, `executed=false`, `read_refusal=None`. Plant `F-A9-fake-runtime` / mutant `M-fake-runtime-read` fails: `ready without a runtime refusal reason`. |
| 6 A5 shape | `owned_root` is `UsersAI/<agent>/<rest>` | HOLDS for the string | `UsersAI/agent-a/session-a/1` and helper `UsersAI/agent-1/notes`. README dropped the `Decision` field-match claim. This crate still does not call `lab/grant-binding`. Mutant `Users/` fails the shape test. |
| api-read-write | Store read/write of B's host path | HOLDS | `Refuse::CrossAgent` |
| api-traversal | `..` after the caller's name | HOLDS | Every `..` segment is `Refuse::Traversal` before walk. |
| api-symlink | Outbound file symlink | HOLDS | `Refuse::Symlink` |
| intermediate-symlink | Symlinked directory inside A's root pointing at B | HOLDS | `read`/`write`/`list`/`rename` all `Refuse::Symlink`. B unchanged. |
| last-component symlink | Write through an existing last-component symlink | HOLDS | `Refuse::Symlink`; B unchanged. |
| toctou-write | Rename/swap an intermediate dir to a symlink after validation, before `open(create)` | FALSIFIED | 400 iterations, 129 swaps: 395 denied, **4 `write` returned `Ok` and left `race-N.txt` in B's tree**. B's `secret.txt` stayed `b-secret`. `O_NOFOLLOW` does not cover intermediate components. After `open`, `confirm_resolved` looks at the path string, not the fd; if `sub` is swapped back to a real dir, the path looks absent and `write_all` still goes to B's fd. |
| toctou-rename | Rename into a swapped intermediate dir | WEAK | 400 iterations: 1 `rename` `Ok`, 0 files landed in B. Not won here. Not a timeout. |
| toctou-last-component | Last component becomes a symlink to B before `open(create\|truncate)` | WEAK | 400 iterations: 3 writes created a real `alias` in A, 0 truncations of B. Not won here. |
| path-variants | Case, Unicode, encoded `..`, slashes | HOLDS | No read of `b-secret`. `..` and `.\` refused. `NOTE.TXT`, `%2e%2e`, fullwidth `．．`, combining marks: `NotFound`. `Agent-A` binds as a different principal. Unicode identity: `HostPath`. Trailing slash `note.txt/` read A's own 7 bytes; not a cross-agent leak. |
| empty-relative-roots | Empty or relative roots | HOLDS | `Store::open("")` and a missing relative path: `OutsideRoot`. `Store::open(".")` canonicalises to an absolute yard. Empty or slashed bind names: `HostPath`. |
| two-agent-race | Two threads, B reads A's host path | HOLDS | 400 writes on A; 0 Store leaks to B. |
| proc-fd-prefix | `/proc/self/fd` and `root-evil` prefix | HOLDS | `CrossAgent` and `OutsideRoot`. |
| host-same-uid | B's process walks A's files | HOLDS (still open) | `fs::read` from B's root returns `hello-a`. Documented `NEEDS CONFINEMENT/RUNTIME`. |
| blocked-not-skip-pass | A skipped test is counted as a pass | HOLDS | No `#[ignore]`. 14 tests listed, 0 ignored. Runtime rows stay Blocked inside a passing tripwire. |
| plant-child-env | Plant runner hardcoded PASS | WEAK (child path only) | `planted_shared_root_is_caught` returns at once when `OWNED_STORAGE_PLANT_CHILD` is set. The official suite in this session did not set it; plants ran and were CAUGHT (about 1.75s, `target/plant-F-A9-*` created). No timeout falsifier. No plant is a hardcoded PASS in the parent run. |

Verdict words: **HOLDS** = the claim as worded stood on this head.
**FALSIFIED** = a concrete run broke the claim. **WEAK** = the official
plant or test catches a reason mismatch, or a race was not won in the
iterations run here.

## Bookability under Anders's rule

| Gate | Lab half | Full A9 |
| --- | --- | --- |
| Complete journey as worded | No. Store `read`/`write`/`list`/`rename` of the named foreign paths pass. Unlink-after-hardlink and intermediate TOCTOU write do not. | No. Two Runtime agents never ran. |
| Refusal that carries a reason | Yes, for the named Store paths. Runtime row empty. | No captured Runtime reason. |
| CAUGHT falsifier | Official plants CAUGHT. Root-swap plant is a reason mismatch (`HardLink` vs `Symlink`), not a byte leak. No Runtime plant that shows a live refusal disappear. | No live Runtime plant. |
| Required reviews | None on #290 (`reviews: []`). Draft. | None. |

## Mutants

Each claimed fix was reverted in `/tmp/pr-290-r2` and restored. SHA-256
matched after every run. Worktree stayed clean. `/tmp/elastos/storage`
stayed absent.

| Mutant | What it removed | Named test | Caught? |
| --- | --- | --- | --- |
| M-root-swap / F-A9-root-swap | `refuse_swapped_root = false` | `agent_a_is_denied_b_when_root_is_swapped_for_a_symlink` | Yes. `left: HardLink right: Symlink`. No byte leak. |
| M-hardlink-nlink / F-A9-hardlink | `refuse_hard_link` no-op | `agent_b_is_denied_a_hard_linked_inode` | Yes. `read` succeeded (`hello-a`) at `lib.rs:918`. |
| M-list-no-resolve | `list` joins the raw path, no `resolve` | `agent_a_is_denied_b_list_and_rename` | Yes. `left: Symlink right: CrossAgent`. |
| M-a5-users | `Users/` instead of `UsersAI/` | `owned_root_uses_a5_usersai_agent_rest_shape` | Yes. |
| M-inode-noop | `inode_in_owner_tree` always `Ok` | `agent_b_is_denied_a_hard_linked_inode` | Yes. Direct foreign-inode assertion at `lib.rs:929`. |
| M-share-count-zero | `share_count = 0` | `real_runtime_rows_match_the_launcher` | Yes. `share_cmd.rs:183 must stay a fourth shared-temp site`. |
| M-fake-runtime-read / F-A9-fake-runtime | read row `Ready` | `real_runtime_rows_match_the_launcher` | Yes. `ready without a runtime refusal reason`. |
| M-no-nofollow | drop `custom_flags(O_NOFOLLOW)` | all official tests except the plant runner | **Surviving.** 13 passed, 0 failed, 1 filtered (`planted_shared_root_is_caught` skipped so plants were not stacked). The earlier "14 passed in 0.01s" run had `OWNED_STORAGE_PLANT_CHILD=1`, which is the child-path hardcoded PASS. |

Official plant `F-A9-share` (every instance uses `yard/shared`) still CAUGHT
all four named tests. Parent-path still fails only because both host roots
are `.../shared`, not because `..` succeeds. List/rename under that plant
returns `OutsideRoot`, not `CrossAgent`.

**Surviving mutant:** `M-no-nofollow`. Official tests do not notice. The
flag only covers the last component. The intermediate-directory TOCTOU
already writes into B with the flag present.

No mutant was a timeout. No mutant was accepted by a hardcoded `Ok` in the
parent plant runner.

## #290 suites rerun here

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean, exit 0

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
# 14 passed; 0 failed; 0 ignored
# launch::tests::real_runtime_rows_match_the_launcher
# tests::agent_a_is_denied_b_directly
# tests::agent_a_is_denied_b_list_and_rename
# tests::agent_a_is_denied_b_through_a_parent_path
# tests::agent_a_is_denied_b_through_a_symlink
# tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink
# tests::agent_a_lists_and_renames_its_own_storage
# tests::agent_a_reads_and_writes_its_own_storage
# tests::agent_b_is_denied_a_hard_linked_inode
# tests::cleanup_leaves_nothing_behind
# tests::host_same_uid_walk_needs_confinement_or_runtime
# tests::owned_root_uses_a5_usersai_agent_rest_shape
# tests::planted_shared_root_is_caught
# tests::shared_temp_directory_is_refused

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 14 tests, 0 benchmarks. No ignored names.

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics

python3 -I lab/review-a9-290-r2/run.py
# fmt 0, tests 0, clippy 0, probe 0; 14 passed; findings as above

python3 -I lab/review-a9-290-r2/mutants.py
# 8 mutants; 7 caught; 1 surviving (M-no-nofollow); sources restored
```

Independent plant replay (files restored; SHA-256 match after):

```text
F-A9-root-swap / tests::agent_a_is_denied_b_when_root_is_swapped_for_a_symlink
  left: HardLink
  right: Symlink
  FAILED

F-A9-hardlink / tests::agent_b_is_denied_a_hard_linked_inode
  read succeeded (hello-a) at lib.rs:918
  FAILED

F-A9-share / tests::agent_a_is_denied_b_directly
  FAILED (shared root)

F-A9-share / tests::agent_a_is_denied_b_through_a_parent_path
  assertion `left != right` failed: agents share a storage root
  FAILED

F-A9-share / tests::agent_a_is_denied_b_through_a_symlink
  FAILED

F-A9-share / tests::agent_a_is_denied_b_list_and_rename
  left: OutsideRoot
  right: CrossAgent
  FAILED

F-A9-fake-runtime / launch::tests::real_runtime_rows_match_the_launcher
  ready without a runtime refusal reason
  FAILED
```

## Runtime rows

Honestly blocked. This session did not start `elastos`.

- `real_runtime_each_instance_has_its_own_storage_root`: `Blocked`,
  `BLOCKED AC-006-STORAGE: elastos run calls create_runtime("/tmp/elastos/storage")`.
- `real_runtime_agent_a_read_of_b_is_refused`: `Blocked`,
  `BLOCKED AC-006-STORAGE: agent file reads do not use that storage provider`.
- `executed=false`, `read_refusal=None`.
- RA-3 as written still replaces the three `run_cmd.rs` calls only. It does
  not touch `share_cmd.rs:183`. It does not make A's read of B return a
  reason: object reads still use the Home data directory
  (`runtime.rs` `_storage` comment; `rooted_localhost_fs_path`).
- No row claims a Runtime run that did not happen.

## What is lab-only

Per-instance directories under a private yard. Store `read` / `write` /
`list` / `rename` refusals for a foreign host path, a `..` segment, a
static outbound symlink, a swapped root (as `Symlink`), a live hard link
(`nlink > 1`), and `/tmp/elastos/storage`. Cleanup and Drop. Plants
`F-A9-share`, `F-A9-root-swap`, `F-A9-hardlink`, `F-A9-fake-runtime`.
The tripwire that stays green while the four constructors exist and the
Runtime rows stay `Blocked`.

`lab/grant-binding` is a separate crate and still counts toward no M1 check.

## Ranked fix list

1. Do not book A9 from this PR. Keep the title and body as lab only.
2. After `open`, check the fd (`fstat`) against the owner's device and
   inode set. Do not trust a second path lookup. `create|truncate` must
   not land in another root when an intermediate directory is a symlink
   for one scheduling gap.
3. Walk every component with `openat` and `O_NOFOLLOW` / `O_DIRECTORY`.
   Add a test that fails when `O_NOFOLLOW` is removed (`M-no-nofollow`
   survives today).
4. Refuse an inode that has (or had) a link outside the owner's tree, not
   only `nlink > 1` while both names exist. The unlink-after-hardlink
   probe is the missing official test.
5. Change the root-swap plant so a leak (`read` returns `b-secret`) is
   the catch, not `HardLink != Symlink`.
6. Keep `F-A9-share` for equal roots. Add a plant that removes only the
   `..` check, and one that makes `list`/`rename` return the other
   agent's names.
7. Host same-uid mode 0755 stays `NEEDS CONFINEMENT/RUNTIME` until C3/C9
   or the Runtime confines the process.
8. Runtime rows stay `Blocked` until two component processes produce a
   non-empty bridge reason. RA-3 is still not that proof.

## Not run here

- A live `elastos run` or `elastos serve`.
- Mac `HOME` vs `XDG_DATA_HOME` data-dir proof.
- `lab/agent-conformance` ignored row `operator_storage_is_under_throwaway_home`.
- Bind mounts (this uid cannot mount).
- Lane reviews of #290 (none posted).

## Principles

- 3 No ambient authority: the Store confines the named path operations;
  `host_root()`, same-uid siblings, a stolen inode, and an open fd after
  a directory swap do not.
- 5 Small trusted core: this crate is a stand-in, not the trusted core.
- 7 One authority model: the grant name is `UsersAI/...` and still unbound
  to A5.
- 10 One canonical path: `run` still uses a different storage literal
  than `capsule`.
- 11 Fail closed, then explain: named Store refusals explain. Runtime
  rows stay BLOCKED instead of reporting a run that did not happen.
- 12 Docs, code, tests agree on the Runtime block and the host hole. The
  hard-link and root-swap plants do not match the leak story in the PR
  body.
- 18 Isolated execution: lab directories are separate. The host process
  and an open fd are not.

DeepSeek: none.
