# Review of draft PR #323 (sixth pass, r6)

Independent adversarial review of the lab-side C1-C7 macOS sandbox
profile contract in draft PR #323 (`cursor/redteam-fix-4bfb` at
`65f003aaa67173f7b74a0233232d24c4a5d01b39`). Work ran from a detached
worktree. This folder only adds `lab/review-c1-c7-323-r6/`. It does not
edit #323 files, push to #323, or touch `Elacity/elastos-runtime`.

- Target: #323 head `65f003aaa67173f7b74a0233232d24c4a5d01b39`
  (`lab/redteam-fix: record r5 close counts in the spike log`).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. Absent: `sandbox-exec`, `wasmtime`, `wasmer`.
- Binding CTO decisions: (F1) every `#\` character literal is refused
  by the profile contract, anywhere; (F2) a citation counts only if
  the cited file itself holds that `#[test]` and the owning crate's
  `cargo test -p <crate> --test|--lib|--bin <that target> -- --list`
  names it. No union of crate lists.
- How the live checkers are called: `python3 -I lab/review-c1-c7-323-r6/extract.py`
  copies the #323 functions into `lab/review-c1-c7-323-r6/probe/`.
- How to run: `lab/review-c1-c7-323-r6/run.sh`.

Anders's counting rule still holds: a check counts only with its
complete journey, a refusal with a reason, a CAUGHT falsifier, and the
required reviews. C1-C7 lean on these checkers and on the Mac
`sandbox-exec` run.

## Verdict

**PASS** for the Linux lab half only.

F1 holds. Every planted `#\` form refuses, including the r4/r5 W1
spelling `#\;(allow file*)`. The contract returns
`{'ok': False, 'reason': 'fixture-provider must reject Scheme comment form #; or #|'}`.
The extra grant does not pass. That is the F1 policy, not a reopened
hide.

F2 holds. A name from another crate does not count. A `#[test]` behind
`cfg(target_os = "macos")`, or inside a macos-only `mod`, does not
count on Linux. A plain `fn` that shares a name with another file does
not count. An `include!` file that does not itself hold the `#[test]`
does not count.

Owner suites match #323. r1–r3 are green. r4 is 74/75 and r5 is 91/92.
The only red on those two runners is
`test_weak_hash_backslash_one_datum_comments_the_grant_out`, which
still expects `#\;(allow file*)` accepted. That is the one expected
red under F1.

The author's five mutants are CAUGHT, then reverted. New reader-macro,
unicode, bidi, CRLF, NUL, and string-escape decoys refuse on the live
checker. Some new code mutants SURVIVED the named owner test they
were aimed at, because that test plants a different arm. Follow-up on
those mutants did not show a live extra grant. They are pin gaps, not
reopened hides.

**C1-C7 cannot count.** This host has no `/usr/bin/sandbox-exec`. The
32 named Mac tests stay **NOT RUN**. Whether Apple's reader keeps
`#\; x (allow file*)` live is unmeasured.

## What must still happen before C1-C7 count

1. Run the 32 named `sandbox-exec` tests on a Mac.
2. Measure whether Apple's reader keeps `#\; x (allow file*)` as a
   live grant.
3. Keep this independent review. This folder is that review for this
   head; it does not close C1-C7.

## C1-C7

C1-C7 names are inferred, as in #294, #346, #352, #370, #385 and #402.
The M1 check text is not in this repository. None of the seven count
on Linux.

| Check | Counted? | Why |
| --- | --- | --- |
| C1 file-profile allowlist | No | Lab refusals hold, including every `#\`. No `sandbox-exec` journey. |
| C2 storage not host-wide | No | Prior storage spellings refuse. 11 wallet + 11 model sandbox tests NOT RUN. |
| C3 citation is this file's cargo-listed `#[test]` | No | F2 lab cases refuse. `#[ignore]` still counts when cargo lists it. No Mac journey. |
| C4 network / extra ops refused | No | Listed extra ops refuse. No `sandbox-exec` journey. |
| C5 declared-rights / leftover allow | No | Leftover `allow_head` still sees extra allows. No Mac journey. |
| C6 platform-baseline text | No | Not reopened. Still no complete macOS journey. |
| C7 model copy | No | Model `include!`s `sbpl_reader.rs` and pins the `#\` refuse text. Same Mac gap. |

## HOLDS

### H1. F1: every `#\` character literal is refused

Forms planted on the fixture, all refused:

`#\;`, `#\; x (allow file*)`, `#\; "x" (allow file*)`, `#\; 1 (allow file*)`,
`#\;(allow file*)`, `#\;(version 0)(allow file*)`, `#\a`, `#\space`,
`#\newline`, `#\x`, `#\(`, `#\;"x"`, `#\#t`, `#\t`,
`(allow file-read* (literal #\ /))`, `(allow file-read* (literal "#\;"))`.

Command: `HoldsF1EveryHashBackslash`. Result: all `ok`.
Checker: `capsules/wallet-provider/tests/confine.rs` `profile_characters`
and `check_profile_contract` (`profile_holds_scheme_comment`).

### H2. F2: citation is this file's `#[test]` plus that target's list

A plain listed `#[test] fn present_case` counts. A name the cited file
does not hold does not count. `model_provider_ops_under_profile` on a
wallet snippet that cannot compile does not count (no union list).
`#[cfg(target_os = "macos")] #[test] fn present_case` does not count
on Linux. The same `#[test]` inside `#[cfg(target_os = "macos")] mod`
does not count. A plain `fn present_case()` does not count when
another file may list that name. `tests/sbpl_include.rs` (only
`include!("sbpl_reader.rs")`) does not count as holding
`shared_sbpl_reader_refuses_every_hash_backslash_character_literal`.

Command: `HoldsF2CitationOwnedFileAndList`. Result: all `ok`.
Checker: `confine.rs` `rust_holds_cited_test`.

### H3. Prior allowlist holes stay closed

Unfiltered `(allow file-read*)` as storage refuses. `(allow default)`,
`(ALLOW DEFAULT)`, and `(allow system-socket)` refuse.

Command: `HoldsPriorAllowlistStillClosed`. Result: all `ok`.

### H4. extract.py copies match `sbpl_reader.rs`

`profile_characters` in wallet `confine.rs`, did `confine.rs`, and the
r6 probe body match `capsules/wallet-provider/tests/sbpl_reader.rs`.
Model `include!`s that file.

Command: `HuntExtractCopyDrift`. Result: all `ok`.

## #323 owner suites re-run on this machine

| Suite | Result |
| --- | --- |
| `capsules/wallet-provider` `--test confine` | `55 passed; 0 failed; 11 ignored` |
| `capsules/model-provider` `--test confine` | `26 passed; 0 failed; 11 ignored` |
| `capsules/did-provider` `--test confine` | `13 passed; 0 failed; 11 ignored` |
| `lab/wasm-capsule` `--test run` | `33 passed; 0 failed; 9 ignored` |

These match the #323 PR body.

## Review runners r1–r5 re-run on this machine

r4 and r5 runners were copied from PRs #385 and #402 into the
worktree for the rerun. They are not part of this PR.

| Suite | Result |
| --- | --- |
| `lab/review-323/run.sh` | `Ran 24 tests. OK` |
| `lab/review-323-v2/run.sh` | `Ran 39 tests. OK` |
| `lab/review-323-v3/run.sh` | `Ran 52 tests. OK` |
| `lab/review-323-v4/run.sh` | `74/75` — only W1 |
| `lab/review-323-r5/run.sh` | `91/92` — only W1 |
| `lab/review-c1-c7-323-r6/run.sh` | `Ran 22 tests. OK` |

### The one expected red (r4 and r5 W1)

Both failures are
`WeakRemainingGaps.test_weak_hash_backslash_one_datum_comments_the_grant_out`.
They still assert `contract("#\\;(allow file*)")` is `ok`. This head
returns `ok: False`. The reason names the scheme-comment refuse. The
grant is not accepted. This is F1. It is not a reopened hide.

No other r4 or r5 test failed. The six r5 FALSIFIED tests that used
to fail (atom/string/number `#\;` hide, and the three union-list
citation cases) are now `ok`.

## Author mutants (each reverted)

Each break was patched, the named test was run, then the file was
restored. `git diff -- capsules` was empty after the set.

| Id | Break | Named test | Result |
| --- | --- | --- | --- |
| A1 | Skip the first non-ASCII `allowed` assert | `file_profile_contract_refuses_zwsp_hash_semicolon` | CAUGHT (exit 101) |
| A2 | Allow any string escape | `file_profile_contract_refuses_unknown_string_escape` | CAUGHT (exit 101) |
| A3 | Allow CR in the ASCII set | `file_profile_contract_refuses_carriage_return` | CAUGHT (exit 101) |
| A4 | Skip the mid-token `#` panic | `file_profile_contract_refuses_hash_mid_token` | CAUGHT (exit 101) |
| A5 | Drop the `#\` panic in `sbpl_reader.rs` only | `shared_sbpl_reader_mutation_fails_this_suite` on wallet, did, and model | CAUGHT (3/3, exit 101) |

## New mutants and decoys

### Decoy inputs against the live contract (all refused)

These are new planted profiles and citations. The live checker
refuses each one. Evidence: `lab/review-c1-c7-323-r6/run.sh` `OK`.

| Id | Decoy | Result |
| --- | --- | --- |
| D1 | `#\| (allow file*) \|#` and nested `#\| #\| inner \|# (allow file*) \|#` | CAUGHT |
| D2 | `#;(allow file*)` and `#;(version 0)(allow file*)` | CAUGHT |
| D3 | `#t (allow file*)`, `#f (allow file*)` | CAUGHT (extra allow) |
| D4 | `#x2f`, `#o77`, `#b101`, `#vu8(1 2)`, `#(allow file*)`, `#'`, `#\``, `#,@`, `#!`, `#+`, `#-`, `#hash((a . 1))` | CAUGHT |
| D5 | Fullwidth `＃;`, ZWSP / ZWNJ / word-joiner / BOM / NBSP / line-separator / bidi RLO between `#` and `;`; fullwidth / division / fraction slash in a path | CAUGHT |
| D6 | CR, CRLF, and NUL between forms or in a path | CAUGHT |
| D7 | Unknown string escapes `\r \0 \x \u \U \( \) \# \; \a \b \f \v` | CAUGHT |
| D8 | `#[cfg(target_os = "macos")]` test, and the same test in a macos-only `mod` | CAUGHT (does not count) |
| D9 | Plain `fn present_case()` shadowed by another file's `#[test]` | CAUGHT (does not count) |
| D10 | `include!` file cited as holding the included `#[test]` | CAUGHT (does not count) |
| D11 | extract.py / wallet / did `profile_characters` vs `sbpl_reader.rs` | CAUGHT (bodies match; a later one-copy edit is N9/N10) |

### Code mutants (applied, named test run, reverted)

| Id | Break | Named test | Result | Note |
| --- | --- | --- | --- | --- |
| N1 | Treat `#\| ... \|#` as a dropped comment | `file_profile_contract_refuses_scheme_comments` | CAUGHT | |
| N2 | Treat token `#;` as empty | same | SURVIVED | No-op: the reader builds token `#` only; `;` is not in the hash-token set. Live `#;` still refuses. |
| N3 | Accept `#x` `#o` `#b` as named hash tokens | same | SURVIVED | `#x2f` is still an unknown token. `#x (allow file*)` still refuses the extra allow. |
| N4 | Allow NUL in the ASCII set | `file_profile_contract_refuses_zwsp_hash_semicolon` | SURVIVED | The named test plants U+200B, not NUL. NUL still fails the symbol assert. |
| N5 | Allow `\x` `\u` `\0` escapes | `file_profile_contract_refuses_unknown_string_escape` | SURVIVED | The named test plants `\r`. Live `\x` still refuses. An allowed `\x` would keep the backslash bytes and would not become `/`. |
| N6 | Treat `cfg(target_os = "macos")` as listable | `citation_refuses_feature_gated_test_when_cargo_cannot_list` | SURVIVED | That test plants `feature = "never"`. A compilable macos `#[test]` already returns `Some(false)` from the tiny-crate list. |
| N7 | Skip the cited-file `#[test]` source walk | same | SURVIVED | Owner lookup still needs an exact file match. The planted snippet matches no file. |
| N8 | Count when no owning file matches | same | SURVIVED | The source walk still returns false first. |
| N9 | Drop the `#\` panic in wallet `confine.rs` only | `shared_sbpl_reader_mutation_fails_this_suite` | CAUGHT | extract.py copy drifted from `sbpl_reader.rs`. |
| N10 | Drop the `#\` panic in did `confine.rs` only | same on did | CAUGHT | |
| N11 | Allow CR inside `;` comments | `file_profile_contract_refuses_carriage_return` | SURVIVED | The named test plants CR inside a string. `;` comments already eat until newline. |
| N12 | Accept unknown hash tokens | `file_profile_contract_refuses_scheme_comments` | CAUGHT | |

SURVIVED here means the named owner test still passed. It does not
mean the live contract accepted the decoy. D1–D11 are the decoy
evidence on the unreverted tree.

## WEAK

### W1. r4/r5 still expect `#\;(allow file*)` accepted

Expected red under F1. Recorded so it is not mistaken for a hide.

### W2. Some reader arms have no dedicated owner test

NUL, `\x`, a lone `#x` token, and `cfg(target_os = "macos")` are
refused or fail-closed today, but the named owner tests plant a
different arm (ZWSP, `\r`, `#;`, `feature = "never"`). That is a pin
gap. It is not a live grant.

### W3. `#[ignore]` still counts when cargo lists it

Same as r5 W4. cargo lists them. They do not prove a journey.

### W4. macOS sandbox tests remain NOT RUN

Wallet 11, model 11, did 10 sandbox-exec tests, plus did
`ignored_falsifier_fixture`. Forced `--ignored` still panics
`NOT RUN: sandbox-exec is macOS only`. This host has no
`/usr/bin/sandbox-exec`.

### W5. Wasmer without a memory cap stays an open gap

`wasmer_without_a_memory_cap_is_an_open_gap_not_proof` is among the 33
wasm passes. Honest. Not C0 proof.

## What remains for the Mac

Linux cannot run `/usr/bin/sandbox-exec`. These tests stay `#[ignore]`
here and panic `NOT RUN` when forced. They are the confinement
journey C1-C7 still need. Count: 32 named sandbox-exec tests.

Wallet (11):

- `confined_provider_serves_wallet_operations_under_its_root`
- `confined_outside_write_is_denied`
- `confined_outside_read_is_denied`
- `planted_key_beneath_storage_parent_is_not_read`
- `account_operations_beneath_storage_parent_are_refused`
- `startup_is_refused_when_the_profile_cannot_be_applied`
- `unbound_copy_is_refused_under_profile`
- `bound_copy_serves_under_profile`
- `startup_denial_reports_its_reason`
- `the_bare_value_fixture_loads_under_sandbox_exec`
- `the_string_fixture_loads_under_sandbox_exec`

Model (11):

- `model_provider_ops_under_profile`
- `model_outside_write_denied`
- `model_outside_read_denied`
- `model_outside_create_reports_access_denied`
- `model_local_offer_fails_closed_under_profile`
- `model_hosted_run_fails_closed_under_profile`
- `model_hosted_run_reaches_runtime_socket_when_unconfined`
- `model_unbound_program_refused_under_profile`
- `model_bound_copy_serves_under_profile`
- `byte_different_file_at_bound_path_starts`
- `startup_is_refused_when_the_profile_cannot_be_applied`

Did (10 sandbox-exec; `ignored_falsifier_fixture` is the eleventh ignore):

- `confined_provider_serves_did_operations_under_its_root`
- `verify_did_recovery_under_profile`
- `outside_write_denied`
- `outside_read_denied`
- `planted_file_beneath_storage_parent_is_neither_read_nor_written`
- `persona_key_beneath_storage_parent_is_not_adopted`
- `startup_denial_reports_its_reason`
- `startup_is_refused_when_the_profile_cannot_be_applied`
- `unbound_copy_is_refused_under_profile`
- `bound_copy_serves_under_profile`

Whether Apple's reader keeps `#\; x (allow file*)` as a live grant is
unmeasured here.

## Checker bytes at `65f003aa`

| File | sha256 | bytes |
| --- | --- | --- |
| `capsules/wallet-provider/tests/confine.rs` | `71b31314236fa20fd5bae58944d6282630165b80d8f9b504aab6f27a332ae27c` | 254860 |
| `capsules/wallet-provider/tests/sbpl_reader.rs` | `49dd5f049af68e53c93e679cfaf5d6b053937b483dad88c8b9419503fb0c997f` | 8318 |
| `capsules/model-provider/tests/confine/main.rs` | `163cfa20aa05c21f8aecac0b11b721f6c1d6768192e23befbb613972d8a5f2f1` | 121705 |
| `capsules/did-provider/tests/confine.rs` | `1d4c2d954e8476f039b98a54ecd301bb2dd10efa8a7eff230ed2dbacfdabf03f` | 71314 |
| `lab/wasm-capsule/tests/run.rs` | `e70531eadbabb4c03d92d6a48e441826de61b5c4781a6a4ce14b1fc666ce4b79` | 100149 |

## Limits

- No `sandbox-exec`. Whether Apple's reader keeps
  `#\; x (allow file*)` live is unmeasured.
- No `wasmtime` or `wasmer`. Wasm honesty was checked through
  `#[ignore]` and the wasmer-cap test that names the gap (W5).
- C1-C7 names are inferred. The M1 check text is not in this
  repository.
- A8 is out of scope (#301). Runtime gaps A6, A10, A11, A12 stay
  NEEDS RUNTIME, as #323 said.

## Next

The Linux lab half of F1 and F2 can be trusted on this head. Do not
count C1-C7 until the Mac `sandbox-exec` run of the 32 named tests
passes, and until someone measures whether Apple's reader keeps
`#\; x (allow file*)` live. Draft only. Do not merge.
