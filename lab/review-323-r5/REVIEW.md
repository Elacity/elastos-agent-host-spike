# Review of draft PR #323 (fifth pass)

Independent adversarial review of the lab-side M1 fix in draft PR #323
(`cursor/redteam-fix-4bfb` at `6a2f0cb6f62adb6a9101960604463281f90b58cd`).
The checkers live in this tree. This review only adds `lab/review-323-r5/`.
It does not edit #323 files, `lab/review-323/`, `lab/review-323-v2/`,
`lab/review-323-v3/`, or `lab/review-323-v4/`.

- Target: #323 head `6a2f0cb6f62adb6a9101960604463281f90b58cd`
  (`lab/redteam-fix: record r4 close counts in the spike log`).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`, Python 3.12.3.
  Absent: `sandbox-exec`, `wasmtime`, `wasmer`.
- How the live checkers are called: `python3 -I lab/review-323-r5/extract.py`
  copies the #323 functions into `lab/review-323-r5/probe/`. The review tests
  drive that probe. They do not re-implement the walk.
- How to run: `python3 -I -m unittest discover -s lab/review-323-r5/py -v`
  (or `lab/review-323-r5/run.sh`). That command exits 1 while the FALSIFIED
  items below still hold.

Anders's counting rule, as given for this review: a check counts only with
its complete journey, a refusal with a reason, a CAUGHT falsifier, and the
required reviews. C1-C7 lean on these checkers. A profile the lab accepts
while a Scheme reader would keep an extra grant cannot carry that count.
A citation that matches a name from another crate's `cargo test -- --list`
cannot carry that count either.

## Verdict

**FIX.** C1-C7 stay open. None of them count on this Linux lab run.

The four r4 holes now refuse. `#\;(version 0)(allow file*)` and a
zero-width space between `#` and `;` panic closed. A `present_case`
under `#[cfg(feature = "never")]` or `#[cfg(false)]` does not count
when cargo cannot list the snippet. Owner counts match #323. The four
earlier review suites are green, including `lab/review-323-v4` at 75/75.

The `#\;` tail counter only increments on `(`. An atom, a string, or a
number on the same line is not a datum, so `#\; x (allow file*)` looks
like one hidden form and the contract returns ok. A Scheme `#\;`
character leaves the decoy and the allow live.

When a snippet cannot compile as the tiny cite crate, the fallback
treats any name from wallet, model, or did `cargo test -p <crate> --
--list` as a hit. It does not check that the cited file holds that
`#[test]`. A wallet `CONFINEMENT.md` line can name a model-provider
test and still count.

Eleven wallet sandbox-exec tests remain **NOT RUN** on Linux (model
has its own eleven; did has ten plus one ignored fixture).

## What must change

1. Count every following datum after `#\;`, not only `(`. An atom, a
   string, a number, or `#t` / `#f` on that line is a datum. Two or
   more following datums stay refused.
2. Count a citation only when `cargo test -p <crate> -- --list` on
   the crate that owns the cited file names that `#[test]`, and the
   file itself still holds it. A name from another crate's list is
   not a citation of this source.
3. Keep the independent review. This folder is that review for this
   head; it does not close C1-C7.

## C1-C7

C1-C7 names are inferred, as in #294, #346, #352, #370 and #385. The
M1 check text is not in this repository. None of the seven count on
Linux.

| Check | Counted? | Why |
| --- | --- | --- |
| C1 file-profile allowlist (nested grant, import, default) | No | Prior holes refuse. `#\; x (allow file*)` still passes the lab contract. No `sandbox-exec` journey. |
| C2 storage not host-wide | No | Empty prefix and the v2/v3/v4 storage spellings refuse. The same `#\;` hide can park a storage grant behind an atom. 11 sandbox tests NOT RUN. |
| C3 citation is a cargo-listed `#[test]` | No | r4 `present_case` / `cfg(false)` refuse. The fallback union list still counts a name from another crate, and a name that is not in the cited file. `#[ignore]` still counts. |
| C4 network / extra ops refused | No | Listed extra ops refuse. `#\; x` can hide a network allow on the same line. No `sandbox-exec` journey. |
| C5 declared-rights trace / leftover allow | No | Leftover `allow_head` still sees `(ALLOW …)`. A hidden same-line grant never reaches that walk. |
| C6 platform-baseline text | No | Not reopened this pass. Still no complete macOS journey, and C1-C5 stay open. |
| C7 model copy (case-fold allow walk, param-string case) | No | The two claimed model tests hold. The model copy `include!`s the same reader, so the `#\;` atom hide is shared. |

## HOLDS

Each item passed on this machine. Command and `file:line` name the live
#323 checker.

### H1. Every #346 bypass still refuses

Unfiltered `file-read*`, `(regex "^/")`, spaced `(literal "/" )`,
`(subpath "/.")`, string and nested-comment citations, a plain `fn`,
`(ALLOW DEFAULT)`, `(allow Default)`, `(allow system-socket)`, nested
and split `(allow default)`, nested network, nested import, exact
`(subpath "/")` as storage, and forced `--ignored` (`NOT RUN`) all
refuse.

Command: `Holds346Bypasses` (16 tests). Result: all `ok`.

### H2. Every #352 bypass still refuses

`(prefix "")`, `(regex ".*")`, `(regex "^[/].*")`, `string-append` root,
unfiltered `file*` / `file-write*`, `require-any` root, vnode-type only,
`(subpath "/var")` plus `(regex ".*")`, extra `(ALLOW file-read*)` and
`(allow(file-read*))`, `mach-lookup`, `ipc-posix*`, `#[cfg(any())]`,
unused `macro_rules`, and did's `(ALLOW DEFAULT)` / `system-socket`
all refuse.

Command: `Holds352Bypasses` (17 tests). Result: all `ok`.
Checker: `capsules/wallet-provider/tests/confine.rs:1901`
(`rust_holds_cited_test`), `:6063` (`profile_characters`).

### H3. The five r3 FALSIFIED items still refuse

`#[cfg(any( ))]`, `#[cfg( any() )]`, `#[cfg(any(false))]`, and
`#[cfg(windows)]` on Linux do not count. `#;(version 0)(allow file*)`
and `#| … |#` refuse. `(prefix "")` is host-wide. The model copy sees
`(ALLOW file*)` and rejects `(param "storage_parent")`.

Command: `HoldsR3Attacks` (9 tests). Result: all `ok`.

### H4. The four r4 FALSIFIED items now refuse

`#\;(version 0)(allow file*)` refuses. A zero-width space between `#`
and `;` refuses. A `present_case` under `#[cfg(feature = "never")]`
or `#[cfg(false)]` plus a missing import does not count.

Command: `HoldsR4Attacks` (4 tests). Result: all `ok`.

### H5. v3/v4 allowlist attacks, citation HOLDS, and r5 hunts that refuse

Mixed-case extra allows, whitespace, `;` comments that leave a visible
allow, `#|` block comments, string escapes, Unicode lookalikes, filter
swaps, nested wrappers, `param` aliases, `import` / `include` /
`#include` lists, quoting, extra ops, CR, CRLF, ZWSP / BOM / NBSP /
word-joiner, unknown `\(` / `\r` / `\x` / `\u` escapes, a comment
inside a string that leaves a later allow visible, nested `#\;` with
two paren forms, and a very long `#\;` line with two paren forms all
refuse.

A doc comment, `#[cfg(test)]` without `#[test]`, and a same-name file
outside the provider directory still are not citations. An unused
`macro_rules` body is not a citation. A macro that is invoked is
listed by cargo and counts.

`profile_characters` in `sbpl_reader.rs`, wallet `confine.rs`, and did
`confine.rs` match today. Model `include!`s `sbpl_reader.rs`. Wallet
and did still keep their own copy.

Command: `HoldsNewAllowlistAttacks`, `HoldsCitedListable`,
`HuntNewProfileForms`, `HuntCitationSpoofs`, `HuntR5ProfileForms`,
`HuntR5CitationSpoofs`. Result: all `ok`.

## FALSIFIED

Each item has a test that asserts the refusal the contract still needs.
On #323 today the test fails.

The one review command:

```bash
python3 -I -m unittest discover -s lab/review-323-r5/py -v
```

Result: `Ran 92 tests in 17.488s` / `FAILED (failures=6)`.
86 HOLDS/WEAK/hunt tests passed. 6 FALSIFIED tests failed.

### F1. `#\; x (allow file*)` passes the contract

`profile_characters` treats `#\;` as the semicolon character and then
counts only `(` at depth 0 in the rest of the line. An atom is not a
datum. The extra form vanishes. A Scheme reader takes `#\;` as the
semicolon character and keeps `x` and `(allow file*)`.

Exact profile text appended to the fixture:

```
#\; x (allow file*)
```

The same hide works with a string or a number as the decoy:

```
#\; "x" (allow file*)
#\; 1 (allow file*)
```

- Checker: `confine.rs:6063` (`profile_characters`), the `#\;` tail
  loop at `:6168`.
- Tests: `FalsifiedR5Bypasses.test_falsified_hash_backslash_atom_hides_a_following_allow`,
  `..._string_...`, `..._number_...`
- Result: `FAIL` — `{'ok': True}`

This host has no `sandbox-exec`. The lab check that C1-C7 would cite
already accepts the form.

### F2. A citation counts a name from another crate's cargo list

`rust_holds_cited_test` uses the tiny-crate list when that snippet
compiles. When it does not, the fallback runs `cargo test -p` on
wallet, model, and did and keeps every listed function name. It does
not check that `source` holds that `#[test]`.

A snippet with a missing import and no `present_case` still counts
`file_profile_contract_refuses_hash_backslash_semicolon`, because
that name sits on wallet's real list. The same name under
`#[cfg(feature = "never")]` also counts. Wallet `confine.rs` itself
counts `model_provider_ops_under_profile`, a name it does not hold.

- Checker: `confine.rs:1901` (`rust_holds_cited_test`), the `None`
  arm that unions the three crate lists.
- Tests: `FalsifiedR5Bypasses.test_falsified_citation_counts_a_name_from_another_crate`,
  `..._a_real_name_under_feature_never`,
  `..._confindoc_citation_can_name_another_crates_test`
- Result: `FAIL` — `True is not false`

## WEAK

These passed as documentation of a narrower gap. They do not reopen H1-H5.

### W1. `#\;(allow file*)` comments the grant out

The extra form is `#\;` only. Both a `;` reader and a `#\;` character
reader drop the one-datum allow. Recorded so F1 is the decoy spelling.

### W2. `(LITERAL "/")` casefolds to the startup root read

`STARTUP_RULES[0]` is `(allow file-read* (literal "/"))`. The contract
accepts the case-folded copy. Declared storage still refuses it.

### W3. The tiny-crate list matcher splits on the first `:`

`other::present_case: test` becomes name `other`. Fail-closed, not a
spoof. The real-list helper splits on the last `: `.

### W4. `#[ignore]` and an empty `#[test]` count

cargo lists them. The claim is the list, so they count. They do not
prove a journey.

### W5. macOS sandbox tests remain NOT RUN

Wallet reports `11 ignored` with `NOT RUN: sandbox-exec is macOS only`.
Model reports the same eleven-count. Did reports `11 ignored`: ten
sandbox-exec tests and `ignored_falsifier_fixture`. Forced `--ignored`
on a wallet sandbox test still panics `NOT RUN`.

### W6. Wasmer without a memory cap stays an open gap

`wasmer_without_a_memory_cap_is_an_open_gap_not_proof` is among the 33
wasm passes. Honest. Not C0 proof.

### W7. A bare `#include "bsd.sb"` atom is skipped

No extra allow. The allowlist loop skips bare values. TinyScheme
`load` / `import` lists still refuse.

### W8. `include!` covers only the model copy

`sbpl_reader.rs` is the model reader. Wallet and did still keep their
own `profile_characters`. The three bodies match on this head. A later
edit of one copy can drift. Mutant M11 shows that: changing only
`sbpl_reader.rs` is CAUGHT by the model test and SURVIVED by the
wallet test.

### W9. `--list` injection via `: ` in a test name

`rust_real_list_line_function("evil: test: test")` returns `test`.
Rust function names cannot hold `: `, so a real `#[test]` cannot plant
this line. A doctest title could. Recorded as parser shape, not a
live spoof on this tree.

### W10. Nested `#\;((allow file*))` is one paren datum

The tail counter sees one `(`. Both readers drop that one list. The
inner allow is not a top-level form.

## Claimed falsifiers, re-broken on this machine

Each break was patched, the named test was run, then the file was
restored with `git checkout`. The tree of #323 files is clean.

| What I broke | Named test | Result |
| --- | --- | --- |
| `#\;` two-datum threshold `>= 3` | `file_profile_contract_refuses_hash_backslash_semicolon` | CAUGHT |
| Skip the non-ASCII `allowed` check | `file_profile_contract_refuses_zwsp_hash_semicolon` | SURVIVED (unknown `#` still refuses) |
| Restore the source-walk before cargo list | `citation_refuses_feature_gated_test_when_cargo_cannot_list` | CAUGHT |
| Split the real list on the first `: ` | `cargo_list_parser_splits_on_the_last_colon_space` | CAUGHT |
| Treat `#;` as a line comment | `file_profile_contract_refuses_scheme_comments` | CAUGHT |
| Allow any string escape | `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does` | SURVIVED |
| Allow CR in the ASCII set | `file_profile_contract_refuses_hash_backslash_semicolon` | SURVIVED |
| Skip the `#` token-boundary panic | `file_profile_contract_refuses_scheme_comments` | SURVIVED |
| Skip the unclosed-string assert | `profile_forms_rejects_unclosed_string` | CAUGHT |
| Accept a bare `#` hash token | `file_profile_contract_refuses_scheme_comments` | CAUGHT |
| Start a `;` comment inside strings | `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does` | CAUGHT |
| `sbpl_reader.rs` only: two-datum threshold `>= 3` | `model_reader_refuses_hash_reader_forms` / wallet `#\;` test | model CAUGHT, wallet SURVIVED |

Eight of twelve weakenings of the wallet reader were CAUGHT by the
named owner test. Four SURVIVED: non-ASCII (the zwsp test still
passes through the unknown-`#` arm), any string escape, CR, and a
mid-token `#`. The claimed zwsp falsifier does not pin the non-ASCII
check by itself.

## #323 owner suites re-run on this machine

All four commands from the PR body, plus the four earlier review
suites, were re-run at `6a2f0cb6f62adb6a9101960604463281f90b58cd`:

| Suite | Result |
| --- | --- |
| `capsules/wallet-provider` `--test confine` | `41 passed; 0 failed; 11 ignored` |
| `capsules/model-provider` `--test confine` | `20 passed; 0 failed; 11 ignored` |
| `capsules/did-provider` `--test confine` | `7 passed; 0 failed; 11 ignored` |
| `lab/wasm-capsule` `--test run` | `33 passed; 0 failed; 9 ignored` |
| `lab/review-323/run.sh` | `Ran 24 tests. OK` |
| `lab/review-323-v2/run.sh` | `Ran 39 tests. OK` |
| `lab/review-323-v3/run.sh` | `Ran 52 tests. OK` |
| `lab/review-323-v4/run.sh` | `Ran 75 tests. OK` |
| `lab/review-323-r5/run.sh` | `Ran 92 tests` / `FAILED (failures=6)` |

SHA-256 of the files #323 uses for these checkers, as read here:

| File | sha256 | bytes |
| --- | --- | --- |
| `capsules/wallet-provider/tests/confine.rs` | `0de3938ef900ff6c093a2675efcee82037d882d32394967a704ecf314c0a339a` | 248290 |
| `capsules/wallet-provider/tests/sbpl_reader.rs` | `50ae716d4f388c3a2a1d6eaea4e3006c110ea1cacccee2fedfecc69def70a95e` | 9238 |
| `capsules/model-provider/tests/confine/main.rs` | `8467a65dcd28658f7ea8377382837e7040d7e0570bc9d46848085310f3e15d87` | 120996 |
| `capsules/did-provider/tests/confine.rs` | `d9197e59eddc4e5e22086d3605c8ebd0988d0b0f61212df1fc47e887236e237b` | 72177 |
| `lab/wasm-capsule/tests/run.rs` | `e70531eadbabb4c03d92d6a48e441826de61b5c4781a6a4ce14b1fc666ce4b79` | 100149 |

## What remains for the Mac

Linux cannot run `/usr/bin/sandbox-exec`. These tests stay `#[ignore]`
here and panic `NOT RUN` when forced. They are the confinement
journey C1-C7 still need.

Wallet (`11` ignored, all sandbox-exec):

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

Model (`11` ignored, all sandbox-exec):

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

Did (`10` sandbox-exec ignored, plus `ignored_falsifier_fixture`):

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

A Mac run also needs to show whether Apple's reader keeps
`#\; x (allow file*)` as a live grant. That is unmeasured here.

## Limits

- No `sandbox-exec`. F1 is a lab-check finding. Whether Apple's
  TinyScheme reader applies `#\; x (allow file*)` is unmeasured here.
- No `wasmtime` or `wasmer`. Wasm honesty was checked through
  `#[ignore]` and the wasmer-cap test that names the gap (W6).
- C1-C7 names are inferred, as in #294, #346, #352, #370 and #385.
  The M1 check text is not in this repository.
- A8 is out of scope (#301). Runtime gaps A6, A10, A11, A12 stay
  NEEDS RUNTIME, as #323 said.

## Next

Do not count C1-C7 from #323. Close F1 and F2 on the same checkers,
with a CAUGHT falsifier for the `#\;` decoy and for a name that only
exists on another crate's cargo list. Pin the non-ASCII check with a
case that unknown `#` does not already catch. Then a sixth independent
review of that head. The r4 two-paren `#\;` and `present_case`
refusals hold. The `#\;` atom decoy and the union-list citation still
do not.
