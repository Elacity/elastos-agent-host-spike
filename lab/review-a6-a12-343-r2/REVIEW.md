# Review r2 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343-r2/`. It does not edit #343's branch, other
`lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `732b6990a4f8c2663eea4d13c549cbea402dcfd7`.
- Base of this review: `origin/spike/agent-host` `889019aeb835554b43889e3f10db53bb3f1deba0`.
- Prior review: PR #365 of head `011d01f2` — **FALSIFIED**.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS.
- How to run: `lab/review-a6-a12-343-r2/run.sh`.

Anders's rule, as given for this review: A6 counts only when two
independent resident capsule instances inside one Runtime complete the
journey. #343 does not claim that. This review treats every other
claim as unverified until a command on this machine showed it.

## Plain status

#343's own suite at `732b6990` is `ok. 20 passed; 0 failed; 0 ignored`
in 35.32s. The author's plant runner printed **9 CAUGHT lines** from
**8 plants**. Plants restored `manager.rs` byte-for-byte
(`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`
before and after). After the run, `ls /tmp/elastos` was `No such file
or directory`. The worktree stayed clean.

The #365 surviving mutants are now CAUGHT by the author's plants.
Independent replants of those six mutants, and the new r2 probes, are
recorded under Commands and Surviving mutants below.

This still does **not** meet Anders's resident-instance rule. A6 and
A12 stay in-flight.

## Verdict

**A6 is not bookable. A12 is not bookable.**

The Linux crate now mints a real `CapabilityManager` token and calls
real `validate`. Sibling, prefix, and empty-capsule cases return
`WrongCapsule` with the two fields compared. That is one in-process
manager and two capsule id strings. It is not two resident capsule
instances inside one Home.

A12 now honours `ELASTOS_TMP_ROOT`, resolves a symlink root, and finds
a leftover whose new name still starts with the old name and still
holds the lab marker bytes. `ThrowawayHome::new` + `census::cleanup`
are called and return NOT RUN on Linux. Owner census still walks only
the throwaway TMPDIR. A rename that does not keep the old name prefix,
or a leftover without the lab marker, is hidden.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## Commands run

Subject suite, worktree `/tmp/pr343-r2` at `732b6990`, no edits:

```
./lab/a6-a12-evidence-fix/run.sh
```

Result: `ok. 20 passed; 0 failed; 0 ignored` in 35.32s.
`--list` printed those 20 names.
Plant runner: 8 plants, 9 CAUGHT lines (F-A12-DROP-ROOTS is two tests).
`manager.rs` sha256 identical before and after.
After the run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Independent #365 replants (not the author's `planted_bugs_are_caught`):

```
lab/review-a6-a12-343-r2/tools/replant.sh /tmp/pr343-r2
```

Result: all six **CAUGHT**. `manager.rs` and `a12.rs` sha256 restored
after each plant. Exit 0. See `evidence/replant-365.txt`.

New r2 probes (injected, then restored):

```
lab/review-a6-a12-343-r2/tools/new-probes.sh /tmp/pr343-r2
```

Result: `ok. 15 passed; 0 failed` (20 subject tests filtered out).
Worktree clean afterwards. See `evidence/new-probes-tail.txt`.

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome` needs
macOS). Compiling that crate to run those three commands was skipped
on purpose; they remain the Mac remainder.

## Per-claim table

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 20 named lib tests pass | **HOLDS** | `--list` printed 20 names; `run.sh` printed `20 passed` |
| 8 plants / 9 CAUGHT lines | **HOLDS** | exact CAUGHT lines in `evidence/subject-run.txt` |
| F-A6-NO-TOKEN-CHECK CAUGHT | **HOLDS** | sibling test FAILED under the plant |
| M-A6-PREFIX-BIND CAUGHT | **HOLDS** | author's plant + independent replant |
| M-A6-EMPTY-TOKEN CAUGHT | **HOLDS** | author's plant + independent replant |
| M-A6-COMMENT-STEP4 CAUGHT | **HOLDS** | author's plant + independent replant |
| F-A12-DROP-ROOTS CAUGHT | **HOLDS** | list + plant tests FAILED |
| M-A12-HARDCODE-FAIL CAUGHT | **HOLDS** | clean PASS test FAILED |
| M-A12-SYMLINK-ROOT CAUGHT | **HOLDS** | symlink-through test FAILED |
| M-A12-RENAME-ROOT CAUGHT | **HOLDS** | prefix `.bak` + marker test FAILED |
| Plants restore `manager.rs` byte-identically | **HOLDS** | sha256 `cd4772f1…066b2a` before and after |
| Instance-1 may use its session token | **HOLDS** | real `grant` + `from_base64` + `validate` as instance-1 |
| Sibling presenting owner token is `WrongCapsule` with fields compared | **HOLDS** | `expected:instance-1 got:instance-2` |
| Prefix `instance-1-evil` refused | **HOLDS** | exact-match WrongCapsule |
| Empty token capsule refused | **HOLDS** | `from_base64("")` fails; empty grant is WrongCapsule |
| Cited owner lines still show the #294 holes | **HOLDS** | existing_* tests passed; request path still pending |
| `ThrowawayHome` + `census::cleanup` are invoked | **HOLDS** as a call | `ThrowawayHome::new()` runs and is NOT RUN on Linux |
| `ELASTOS_TMP_ROOT` set writes nothing under `/tmp/elastos` | **HOLDS** | suite left `/tmp/elastos` absent |
| Token for a different resource/action, sibling still WrongCapsule | **HOLDS** (Runtime) | r2 probes; pack itself does not name these cases |
| Expired / revoked token refused | **HOLDS** (Runtime) | r2 probes; already unit-tested in `manager.rs`; pack does not name them |
| Tampered base64 refused | **HOLDS** (Runtime) | r2 probe; pack does not name it |
| Capsule id case / unicode variants refused | **HOLDS** (Runtime) | exact `!=`; r2 probes; pack does not name them |
| Census cannot be fooled by a renamed tree | **WEAK** | only names that still start with the old name, and only with the lab marker |
| Renamed leftover trees are found by marker bytes | **WEAK** | `named-root.bak` is found; `moved-away` is hidden |
| `ELASTOS_TMP_ROOT` unset writes to `/tmp/elastos` | **WEAK** | documented default; acceptable for a real census, not for an unattended Mac pack next to a live Home |
| Relative `ELASTOS_TMP_ROOT` or `/` is safe | **WEAK** | no guard; `/` would walk the host; relative writes under cwd |
| Marker-absent renamed tree is found | **gap / WEAK** | no marker means the scan has nothing to find; a real Runtime leftover would look like this |
| Unrelated-name rename is found by marker | **FALSIFIED** | `moved-away` does not match the `starts_with` prefix scan; leftovers listed only the recreated empty name |
| These checks make A6 or A12 bookable | **FALSIFIED** | no resident instances; owner journeys still fixture-deny / TMPDIR-only |
| Meets Anders's independent-resident-instances-in-one-Runtime rule | **FALSIFIED** | author does not claim it; the crate is one in-process manager |

## Surviving mutants

#365 survivors, re-applied on this head:

| Id | Change | Named test | Result |
| --- | --- | --- | --- |
| M-A6-PREFIX-BIND | `!=` → `starts_with` | `a6_prefix_capsule_id_is_refused` | **CAUGHT** |
| M-A6-EMPTY-TOKEN | skip check when capsule empty | `a6_empty_token_capsule_is_refused` | **CAUGHT** |
| M-A6-COMMENT-STEP4 | delete Runtime step 4 | `a6_sibling_presenting_owner_token_is_refused` | **CAUGHT** |
| M-A12-HARDCODE-FAIL | census always FAIL | `a12_clean_isolated_root_passes` | **CAUGHT** |
| M-A12-SYMLINK-ROOT | do not follow symlink root | `a12_symlink_root_is_scanned_through` | **CAUGHT** |
| M-A12-RENAME-ROOT | drop `scan_parent_for_marker` | `a12_renamed_root_is_found_by_marker` | **CAUGHT** |

New r2 probes that the live walker still fails (not author's plants):

| Id | Change | Result |
| --- | --- | --- |
| M-A12-NO-MARKER | rename a tree that has no leftover-marker bytes | **SURVIVED** as a hide (lab marker is not a Runtime leftover) |
| M-A12-RENAME-UNRELATED | rename to `moved-away` (no prefix) | **SURVIVED** as a hide |
| M-A12-SYMLINK-LOOP | root symlink points at itself | walk returns Err (fail closed); no PASS |
| M-A12-TMP-SLASH | `ELASTOS_TMP_ROOT=/` | listed as `/` and `/storage`; no guard |
| M-A12-TMP-RELATIVE | relative env value | accepted and written under cwd |
| M-A12-TMP-UNSET | env unset | defaults to `/tmp/elastos` |

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

## What remains for A6 / A12 beyond the three Mac commands

The three Mac commands still matter, and they are still not enough:

```
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  two_instances_overlap_with_separate_grants -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  instance_grant_does_not_authorise_sibling -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
  cleanup_census_refuses_each_leftover -- --nocapture
```

Those owner rows still use fixture deny and the throwaway TMPDIR.
Beyond them:

1. A new A6 journey that presents instance-1's real session token as a
   second *resident* instance inside one Home, and fails when step 4 is
   removed from the Runtime that journey loaded.
2. Owner `census::cleanup` after a real `run` that constructs
   `/tmp/elastos/storage` (or the Mac pack's `ELASTOS_TMP_ROOT`).
3. Leftovers found after a rename that does not keep the old name
   prefix, and leftovers that are not the lab marker bytes.
4. Mac pack must set `ELASTOS_TMP_ROOT` to an isolated folder. Unset
   defaults to `/tmp/elastos`. That is the real Runtime temp. It is
   acceptable as a census target, and it is not acceptable as a plant
   target next to a live Home. `run.sh` does not set the env.
5. `ELASTOS_TMP_ROOT=/` has no guard. Do not point it at `/`.

#343's own macOS branch still returns NotRun for resident instances.

## Principles

- 3 No ambient authority: the in-process token now binds a caller
  string; the live request path still goes to pending.
- 11 Fail closed, then explain: sibling `WrongCapsule` is typed;
  a symlink loop errors instead of PASS; `/` is not refused.
- 12 Docs, code, tests, and operations must agree: FINDINGS.md is
  honest that this is not two resident instances; the rename/marker
  wording is broader than the test.

DeepSeek: none.
