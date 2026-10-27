# Review of draft PR #323 (fourth pass)

Independent adversarial review of the lab-side M1 fix in draft PR #323
(`cursor/redteam-fix-4bfb` at `b385b4c9f7a3bde162705d14f5cbc7eb2fc34292`).
The checkers live in this tree. This review only adds `lab/review-323-v4/`.
It does not edit #323 files, `lab/review-323/`, `lab/review-323-v2/`, or
`lab/review-323-v3/`.

- Target: #323 head `b385b4c9f7a3bde162705d14f5cbc7eb2fc34292`
  (`lab/redteam-fix: record r3 close counts in the spike log`).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`, Python 3.12.3.
  Absent: `sandbox-exec`, `wasmtime`, `wasmer`.
- How the live checkers are called: `python3 -I lab/review-323-v4/extract.py`
  copies the #323 functions into `lab/review-323-v4/probe/`. The review tests
  drive that probe. They do not re-implement the walk.
- How to run: `python3 -I -m unittest discover -s lab/review-323-v4/py -v`
  (or `lab/review-323-v4/run.sh`). That command exits 1 while the FALSIFIED
  items below still hold.

Anders's counting rule, as given for this review: a check counts only with
its complete journey, a refusal with a reason, a CAUGHT falsifier, and the
required reviews. C1-C7 lean on these checkers. A citation of a `#[test]`
that `cargo test -- --list` leaves out still cannot carry that count. A
profile the lab accepts while a Scheme reader would keep an extra grant
cannot carry that count either.

## Verdict

**No.** C1-C7 stay open. They are not bookable on the Linux lab run.

The five r3 FALSIFIED items now refuse. `#;` and `#|` are refused. Empty
`(prefix "")` is host-wide. The model copy sees `(ALLOW …)` and keeps
param-string case. Owner counts match #323. The three earlier review
suites are green, including `lab/review-323-v3` at 52/52.

The lab reader still starts a line comment at every `;` outside a string.
A Scheme `#\;` character on the same line as `(version 0)(allow file*)`
hides that grant from the lab and leaves it live for a Scheme reader.
The same hide works with a zero-width space between `#` and `;`.

The citation claim still is not the live cargo list on the files
`CONFINEMENT.md` cites. Those files do not compile as the tiny cite
crate, so the checker walks the source. That walk counts a `#[test]`
under `#[cfg(feature = "never")]` or `#[cfg(false)]`. rustc 1.91 also
rejects `cfg(false)` as experimental, so those names never appear in
`cargo test -- --list`.

Eleven macOS-only sandbox tests remain **NOT RUN**.

## What must change

1. Refuse `#\` character forms, or stop treating `;` as a line comment
   when it is part of a hash reader token (`#\;`, and the same hide
   with a format character between `#` and `;`).
2. Count a citation only when `cargo test --test confine -- --list` on
   the real provider crate names that `#[test] fn`. The tiny-crate
   fallback walk must blank every host-false `cfg`, including
   `feature = "…"`, `false`, `not(test)`, and `all(unix, windows)`.
3. Keep the independent review. This folder is that review for this
   head; it does not close C1-C7.

## C1-C7

C1-C7 names are inferred, as in #294, #346, #352 and #370. The M1
check text is not in this repository. None of the seven count.

| Check | Counted? | Why |
| --- | --- | --- |
| C1 file-profile allowlist (nested grant, import, default) | No | Prior holes refuse. `#\;(version 0)(allow file*)` still passes the lab contract. No `sandbox-exec` journey. |
| C2 storage not host-wide | No | Empty prefix and the v2/v3 storage spellings refuse. The same `#\;` hide can park a storage grant on one line. 11 sandbox tests NOT RUN. |
| C3 citation is a cargo-listed `#[test]` | No | r3 `any( )` / `any(false)` / `windows` refuse on the walk. Real `CONFINEMENT.md` files never reach `cargo --list`. The walk counts `feature = "never"` and `cfg(false)`. |
| C4 network / extra ops refused | No | Listed extra ops refuse. `#\;` can hide a network allow on the same line. No `sandbox-exec` journey. |
| C5 declared-rights trace / leftover allow | No | Leftover `allow_head` still sees `(ALLOW …)`. A hidden same-line grant never reaches that walk. |
| C6 platform-baseline text | No | Not reopened this pass. Still no complete macOS journey, and C1-C5 stay open. |
| C7 model copy (case-fold allow walk, param-string case) | No | The two claimed model tests hold. The model reader copies the same `;` line-comment hole. |

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
Checker: `capsules/wallet-provider/tests/confine.rs:2539`
(`check_profile_contract`), `:1795` (`is_permitted_storage_form`),
`:1894` (`rust_holds_cited_test`). Did:
`capsules/did-provider/tests/confine.rs` `profile_network_denied`.

### H3. The five r3 FALSIFIED items now refuse

`#[cfg(any( ))]`, `#[cfg( any() )]`, `#[cfg(any(false))]`, and
`#[cfg(windows)]` on Linux no longer count as citations.
`#;(version 0)(allow file*)` and `#| … |#` refuse. `(prefix "")` is
host-wide. The model copy sees `(ALLOW file*)` and rejects
`(param "storage_parent")`.

Command: `HoldsR3Attacks` (9 tests). Result: all `ok`.

### H4. v3 allowlist attacks and the earlier citation HOLDS still refuse

Mixed-case extra allows, whitespace, `;` comments that leave a visible
allow, `#|` block comments, string escapes, Unicode lookalikes, filter
swaps, nested wrappers, `param` aliases, `import` / `include` /
`#include` lists, quoting, and extra ops still refuse. A doc comment,
`#[cfg(test)]` without `#[test]`, and a same-name file outside the
provider directory still are not citations.

Command: `HoldsNewAllowlistAttacks` and `HoldsCitedListable`.
Result: all `ok`.

### H5. New reader and citation hunts that refuse

Nested `#|`, `#!` / `#!/usr/bin/sandbox-exec` / `#!r6rs` then an extra
allow, `#+` / `#-` reader conditionals, Scheme `#"…"` regex / subpath /
literal / prefix roots, `(param "/")` and empty param names,
`include-local` / `load` / `require`, a bare `#include` followed by
`(allow file*)`, mixed-case `ALLOW` / `FILE-READ*` / `REGEX` / `Subpath`,
and a string-escape that tries to close early all refuse as extra
forms or as storage.

`#[cfg(feature = "never")]`, `#[cfg(all(unix, windows))]`,
`#[cfg(not(test))]`, and `#[cfg(not(unix))]` on Linux do not count
when the tiny crate can list them.

Command: `HuntNewProfileForms` and `HuntCitationSpoofs`. Result: the
HOLDS cases `ok`. The four FALSIFIED hunts are below.

## FALSIFIED

Each item has a test that asserts the refusal the contract still needs.
On #323 today the test fails.

The one review command:

```bash
python3 -I -m unittest discover -s lab/review-323-v4/py -v
```

Result: `Ran 75 tests in 9.704s` / `FAILED (failures=4)`.
71 HOLDS/WEAK/hunt tests passed. 4 FALSIFIED tests failed.

### F1. `#\;(version 0)(allow file*)` passes the contract

`profile_characters` starts a line comment at every `;` outside a
string, including the `;` in a Scheme character `#\;`. The rest of the
line disappears. The extra form is the bare atom `#\`. A Scheme reader
takes `#\;` as the semicolon character and keeps `(version 0)` and
`(allow file*)`.

Exact profile text appended to the fixture:

```
#\;(version 0)(allow file*)
```

- Checker: `confine.rs:5831` (`profile_holds_scheme_comment`) and `:5876`
  (`profile_characters`). The refuse list is only `#;` and `#|`.
- Test: `FalsifiedNewBypasses.test_falsified_hash_backslash_semicolon_hides_a_following_allow`
- Result: `FAIL` — `{'ok': True}`

This host has no `sandbox-exec`. The lab check that C1-C7 would cite
already accepts the form.

### F2. `#\u200b;(version 0)(allow file*)` passes the contract

A zero-width space between `#` and `;` is not the token `#;`, so the
scheme-comment refuse does not fire. The `;` still starts a lab line
comment, and the allow vanishes. A reader that ignores format
characters would see `#;` and keep the later grant.

- Test: `FalsifiedNewBypasses.test_falsified_zwsp_hash_semicolon_two_datums`
- Result: `FAIL` — `{'ok': True}`

### F3. The fallback walk counts `#[cfg(feature = "never")]`

`rust_holds_cited_test` prefers `cargo test -- --list` on a tiny crate
whose only test file is the cited source. `tests/confine.rs` does not
compile there (`use elastos_wallet_contract…`), so the live list is
`None` and the source walk is the claim. That walk does not blank
`#[cfg(feature = "…")]`. A `#[test] fn present_case` under
`#[cfg(feature = "never")]` counts.

The owner suite is `cargo test --test confine -- --list` on the real
crate, default features, no `--cfg`. Those two cargo commands are not
the same feature set.

Confirmed on this head: `cargo_lists(wallet confine.rs,
confined_outside_write_is_denied)` is `None`, and the walk still finds
that ignored macOS test.

- Checker: `confine.rs:1894` and `:1958`
- Test: `FalsifiedNewBypasses.test_falsified_fallback_walk_counts_feature_gated_test`
- Result: `FAIL` — `True is not false`

### F4. The fallback walk counts `#[cfg(false)]`

rustc 1.91 rejects `cfg(false)` as experimental (`E0658`). The tiny
crate cannot list it. The walk does not treat `false` as unlistable
(only `any()`, `any(false)`, `all()`, `all(false)`, and a short OS
list). A `#[test]` under `#[cfg(false)]` counts.

- Test: `FalsifiedNewBypasses.test_falsified_fallback_walk_counts_cfg_false`
- Result: `FAIL` — `True is not false`

## WEAK

These passed as documentation of a narrower gap. They do not reopen H1-H5.

### W1. `#\;(allow file*)` comments the grant out

The extra form is `#\` only. Both a `;` reader and a `#\;` character
reader drop the one-datum allow. Recorded so F1 is the two-datum
spelling.

### W2. `(LITERAL "/")` casefolds to the startup root read

`STARTUP_RULES[0]` is `(allow file-read* (literal "/"))`. The contract
accepts the case-folded copy. Declared storage still refuses it.

### W3. The cargo list matcher splits on the first `:`

`other::present_case: test` becomes name `other` and rest
`:present_case: test`. The later `rsplit("::")` never runs. A
namespaced test that cargo lists does not count. Fail-closed, not a
spoof.

### W4. `#[ignore]` and an empty `#[test]` count

cargo lists them. The claim is the list, so they count. They do not
prove a journey.

### W5. Eleven macOS sandbox tests remain NOT RUN

Each of wallet, model and did reports `11 ignored` with
`NOT RUN: sandbox-exec is macOS only`. Forced `--ignored` still panics
`NOT RUN`.

### W6. Wasmer without a memory cap stays an open gap

`wasmer_without_a_memory_cap_is_an_open_gap_not_proof` is among the 33
wasm passes. Honest. Not C0 proof.

### W7. A bare `#include "bsd.sb"` atom is skipped

No extra allow. The allowlist loop skips bare values. TinyScheme
`load` / `import` lists still refuse.

## Claimed falsifiers, re-broken on this machine

Each break was patched, the named test was run, then the file was
restored with `git checkout`. The tree of #323 files is clean.

| What I broke | Named test | Result |
| --- | --- | --- |
| Skip cargo `--list`; unlist only exact `any()` | `operations_table_check_reports_each_missing_citation` | FAIL (`#[cfg(any( ))] must not count as a citation: []`) |
| `profile_holds_scheme_comment` always false | `file_profile_contract_refuses_scheme_comments` | FAIL (`a Scheme #; or #| form must be refused`) |
| Drop the empty-prefix arm | `leftover_root_wide_read_catches_empty_prefix` | FAIL (`an empty prefix reads the whole host`) |
| Restore lowercase `(allow ` prefix in the model copy | `model_allow_forms_see_casefolded_allows` | FAIL (`an uppercase allow must be visible`) |
| Lowercase the whole model storage form | `model_storage_keeps_param_string_case` | FAIL (`a lowercased param string is not the shared storage rule`) |

All five named falsifiers fail as claimed.

## #323 owner suites re-run on this machine

All four commands from the PR body, plus the three earlier review
suites, were re-run at `b385b4c9f7a3bde162705d14f5cbc7eb2fc34292`:

| Suite | Result |
| --- | --- |
| `capsules/wallet-provider` `--test confine` | `36 passed; 0 failed; 11 ignored` |
| `capsules/model-provider` `--test confine` | `19 passed; 0 failed; 11 ignored` |
| `capsules/did-provider` `--test confine` | `7 passed; 0 failed; 11 ignored` |
| `lab/wasm-capsule` `--test run` | `33 passed; 0 failed; 9 ignored` |
| `lab/review-323/run.sh` | `Ran 24 tests. OK` |
| `lab/review-323-v2/run.sh` | `Ran 39 tests. OK` |
| `lab/review-323-v3/run.sh` | `Ran 52 tests. OK` |
| `lab/review-323-v4/run.sh` | `Ran 75 tests` / `FAILED (failures=4)` |

SHA-256 of the four files #323 touched, as read here:

| File | sha256 | bytes |
| --- | --- | --- |
| `capsules/wallet-provider/tests/confine.rs` | `57a5bdf6dfa2485699bd3eff7e1b389eefa9aeaa00588f65d1e709298e1c9f1e` | 234448 |
| `capsules/model-provider/tests/confine/main.rs` | `15b21aefbd455f4c0622aaff53647359d2e8f0606a3c7a7ae120e5d76e7190f3` | 123818 |
| `capsules/did-provider/tests/confine.rs` | `526086931256ffe7e01181d3fc6d9e7c748e8ce7e5cb0bf5a229d9e634c23b89` | 67159 |
| `lab/wasm-capsule/tests/run.rs` | `e70531eadbabb4c03d92d6a48e441826de61b5c4781a6a4ce14b1fc666ce4b79` | 100149 |

## Limits

- No `sandbox-exec`. F1 and F2 are lab-check findings. Whether Apple's
  TinyScheme reader applies `#\;(version 0)(allow file*)` is unmeasured
  here.
- No `wasmtime` or `wasmer`. Wasm honesty was checked through
  `#[ignore]` and the wasmer-cap test that names the gap (W6).
- C1-C7 names are inferred, as in #294, #346, #352 and #370. The M1
  check text is not in this repository.
- A8 is out of scope (#301). Runtime gaps A6, A10, A11, A12 stay
  NEEDS RUNTIME, as #323 said.

## Next

Do not count C1-C7 from #323. Close F1-F4 on the same checkers, with a
CAUGHT falsifier for each new refusal. Then a fifth independent review
of that head. The r3 citation and `#;` / `#|` refusals hold. The `#\;`
reader and the real-file citation fallback still do not.
