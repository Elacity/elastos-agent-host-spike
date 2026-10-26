# Review of draft PR #323 (second pass)

Independent adversarial review of the lab-side M1 fix in draft PR #323
(`cursor/redteam-fix-4bfb` at `fa1841f35d32e7bea98e124fd406231d0088fd4e`).
The checkers live in this tree. This review only adds `lab/review-323-v2/`.
It does not edit #323 files or `lab/review-323/`.

- Target: #323 head `fa1841f35d32e7bea98e124fd406231d0088fd4e`
  (`lab/redteam-fix: nest a #[test] inside the block-comment citation`).
  This review's first commit sits on that parent.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`, Python 3.12.3.
  Absent: `sandbox-exec`, `wasmtime`, `wasmer`.
- How the live checkers are called: `python3 -I lab/review-323-v2/extract.py`
  copies the #323 functions into `lab/review-323-v2/probe/`. The review tests
  drive that probe. They do not re-implement the walk.
- How to run: `python3 -I -m unittest discover -s lab/review-323-v2/py -v`
  (or `lab/review-323-v2/run.sh`). That command exits 1 while the FALSIFIED
  items below still hold.

Anders's counting rule, as given for this review: a check counts only with
its complete journey, a refusal with a reason, a CAUGHT falsifier, and the
required reviews. C1-C7 lean on these checkers. A checker that still accepts
a host-wide `file*` as storage, or a `#[test]` that never compiles, cannot
carry that count.

The first review (#346) planted F1-F9. This pass plants other spellings:
`(subpath "/../")`, `(prefix "")`, regex `.*` and `^[/].*`,
`(string-append "/" "")`, `(allow file*)`, `(allow file-read-data)`,
`(allow file-write*)`, `require-any`, vnode-type-only, multiple filters,
deny-then-allow, `network-outbound` / `network-bind`, `mach-lookup` /
`ipc-posix*`, and citations via `#[cfg(any())]` or an unused `macro_rules`.

## Verdict

**No.** #323 is not safe to rely on for C1-C7 evidence.

The #346 cases now refuse. `(subpath "/../")`, `(regex "^/.*")`, unfiltered
`(allow file-read-data)`, `(ALLOW DEFAULT)`, `(allow system-socket)`,
`(include` / `load` / `require`, extra `process-fork`, and forced
`--ignored` on Linux all refuse on this head. Default `cargo test` counts
match #323. The first review suite is green: 24 tests, 0 failed.

The checkers still match a short spelling list. Storage may claim
`(prefix "")`, `(regex ".*")`, `(regex "^[/].*")`,
`(subpath (string-append "/" ""))`, unfiltered `file*` or `file-write*`,
`(require-any (subpath "/"))`, or a pathless `(vnode-type REGULAR-FILE)`.
An extra `(ALLOW file-read*)` or `(allow(file-read*))` is invisible to
`allow_forms`. A `#[test]` under `#[cfg(any())]`, or inside an unused
macro, satisfies a citation. did-provider's own `profile_denies_network`
still uses `starts_with("(allow ")` and `contains("network")`, so
`(ALLOW DEFAULT)` and `(allow system-socket)` pass that gate. Bare
`mach-lookup` and `ipc-posix*` pass the shared contract. Those holes are
enough to keep C1-C7 open.

## What must change

1. Treat a storage file grant as host-wide when it has no path filter, a
   regex or prefix that matches every path (`""`, `.*`, `^[/]`, `^.*`),
   a constructed path (`string-append`, unresolved `param`), a combinator
   that wraps a root filter (`require-any`, `require-all`), or a filter
   that names no path (`vnode-type`). Cover `file*`, `file-write*`, and
   `file-read*`, not only tokens that start with `file-read`.
2. Walk every allow form after case-folding the head. `allow_forms` still
   needs a literal `(allow ` prefix, so `(ALLOW file-read*)` and
   `(allow(file-read*))` never reach declared-rights.
3. Point did-provider's `profile_denies_network` at the shared
   `is_default_allow` / `is_network_allow` / `is_import` predicates. The
   sexp reader is shared. The refuse list is not.
4. A citation must name a `#[test]` that remains after `cfg` and macro
   expansion, not a token that sits in a never-compiled module or an
   unused `macro_rules` body.
5. Refuse bare `mach-lookup` and `ipc-posix*` (and any other unfiltered
   IPC or Mach grant) the same way the contract refuses `system-socket`.
6. Keep the independent review. This folder is that review for this head;
   it does not close C1-C7.

## HOLDS

Each item passed on this machine. Command and `file:line` name the live
#323 checker.

### H1. #346 F1-F4 root spellings now refuse as storage

`(allow file-read*)`, `(regex "^/")`, `(literal "/" )`, and
`(subpath "/.")` each fail `check_declared_rights` with `root-wide`.

Command: `...HoldsClaimedFixes.test_holds_unfiltered_file_read_as_storage`
(and the three sibling tests). Result: `ok`.
Checker: `capsules/wallet-provider/tests/confine.rs:1683`
(`is_root_wide_read`) and `:2398` (storage loop).

### H2. `(subpath "/../")` and `(regex "^/.*")` refuse as storage

Command: `...test_holds_parent_subpath_normalises_to_root`,
`...test_holds_regex_caret_slash_dot_star`. Result: both `ok`.
Checker: `:1698` (`filter_is_root_wide`) and `:1728`
(`path_normalises_to_root`).

### H3. Unfiltered `(allow file-read-data)` refuses as storage

Command: `...test_holds_unfiltered_file_read_data_as_storage`.
Result: `ok`. Same checker. `file-read-data` starts with `file-read`.

### H4. String, nested comment, and a plain `fn` are not citations

Command: the three citation HOLDS tests. Result: `ok`.
Checker: `:1825` (`rust_holds_cited_test`).

### H5. `(ALLOW DEFAULT)` and `(allow system-socket)` refuse the contract

Command: `...test_holds_allow_default_uppercase`,
`...test_holds_system_socket_is_a_network_grant`. Result: both `ok`.
Checker: `:1637` (`is_network_allow`), `:1646` (`is_default_allow`),
`:1547` (`NETWORK_OPERATIONS`).

### H6. `network-outbound` and `network-bind` refuse the contract

Command: `...test_holds_network_outbound`, `...test_holds_network_bind`.
Result: both `ok`. Same named list.

### H7. `include` / `load` / `require` refuse; extra `process-fork` is a second exec

Command: `...test_holds_include_load_require`,
`...test_holds_process_fork_is_second_exec`. Result: both `ok`.

### H8. did's sexp reader keeps a semicolon inside a string

Command: `...test_holds_did_reader_keeps_semicolon_in_string`.
Result: `ok`. `capsules/did-provider/tests/confine.rs:1441`.

### H9. Forced `--ignored` on Linux panics `NOT RUN`

Command: `...test_holds_ignored_wallet_sandbox_test_panics`.
Result: `ok`. Exit 101, payload `NOT RUN: sandbox-exec is macOS only`.
Checker: `capsules/wallet-provider/tests/confine.rs:732`.

## FALSIFIED

Each item has a test in `lab/review-323-v2/py/test_review_323_v2.py` that
asserts the refusal the contract still needs. On #323 today the test fails.

The one review command:

```bash
python3 -I -m unittest discover -s lab/review-323-v2/py -v
```

Result: `Ran 39 tests in 0.697s` / `FAILED (failures=17)`.
18 HOLDS tests passed. 4 WEAK tests passed. 17 FALSIFIED tests failed.

### F1. `(allow file-read* (prefix ""))` declared as storage

`path_normalises_to_root` requires a leading `/`. An empty prefix matches
every path.

- Checker: `confine.rs:1698` and `:1728`
- Test: `FalsifiedNewBypasses.test_falsified_empty_prefix_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F2. `(allow file-read* (regex ".*"))` declared as storage

`filter_is_root_wide` treats a regex as root-wide only when it starts
with `^/`. `.*` matches `/` and every other path.

- Test: `...test_falsified_regex_dot_star_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F3. `(allow file-read* (regex "^[/].*"))` declared as storage

Same checker. A character class that holds `/` does not start with `^/`.

- Test: `...test_falsified_regex_class_slash_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F4. `(allow file-read* (subpath (string-append "/" "")))` declared as storage

The second child is a list, not a string. `unquote_profile_string` leaves
`(string-append "/" "")`, which does not start with `/`.

- Test: `...test_falsified_string_append_root_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F5. Unfiltered `(allow file*)` declared as storage

`is_root_wide_read` only watches tokens that start with `file-read`.
`file*` grants every file operation on the host.

- Checker: `confine.rs:1683`
- Test: `...test_falsified_unfiltered_file_star_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F6. Unfiltered `(allow file-write*)` declared as storage

Same hole. The #346 fix closed reads. A host-wide write still counts as
storage.

- Test: `...test_falsified_unfiltered_file_write_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F7. `(allow file-read* (require-any (subpath "/")))` declared as storage

`filter_is_root_wide` reads only the first child as the filter kind.
`require-any` falls through to `_ => false`. The inner root is ignored.

- Test: `...test_falsified_require_any_root_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F8. `(allow file-read* (vnode-type REGULAR-FILE))` declared as storage

A non-empty filter list skips the unfiltered path. `vnode-type` is not a
path filter, so the grant still reads every regular file.

- Test: `...test_falsified_vnode_type_only_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F9. Multiple filters: `(subpath "/var")` plus `(regex ".*")`

`filters.iter().any(filter_is_root_wide)` still misses `.*`. The second
filter is host-wide.

- Test: `...test_falsified_multiple_filters_regex_dot_star`
- Result: `FAIL` — `{'ok': True}`

### F10. Extra `(ALLOW file-read*)` is invisible to declared-rights

`allow_forms` (`:2845`) keeps only forms that start with `(allow `.
The extra grant is not a declared-rights claimant, and
`check_profile_contract` does not refuse an unfiltered file-read.

- Test: `...test_falsified_uppercase_allow_invisible_to_allow_forms`
- Result: `FAIL` — `{'ok': True}`

### F11. Extra `(allow(file-read*))` is invisible the same way

Flush-head allow is a known default case (H5). Unfiltered `file-read*`
in that shape is not.

- Test: `...test_falsified_flush_head_file_read_invisible`
- Result: `FAIL` — `{'ok': True}`

### F12. `(allow mach-lookup)` passes the contract

`NETWORK_OPERATIONS` names five tokens. Bare Mach lookup is ambient IPC
and is not on that list.

- Checker: `confine.rs:1547` and `:1637`
- Test: `...test_falsified_mach_lookup_is_ambient_ipc`
- Result: `FAIL` — `{'ok': True}`

### F13. `(allow ipc-posix*)` passes the contract

Same named list. Bare POSIX IPC is ambient.

- Test: `...test_falsified_ipc_posix_is_ambient_ipc`
- Result: `FAIL` — `{'ok': True}`

### F14. A `#[test]` under `#[cfg(any())]` satisfies a citation

`rust_holds_cited_test` looks for `#[test] fn NAME(` in the file text.
The item never compiles.

- Checker: `confine.rs:1825`
- Test: `...test_falsified_cfg_any_module_is_not_a_citation`
- Result: `FAIL` — `problems=[]`

### F15. An unused `macro_rules` body satisfies a citation

Same checker. The `fn` lives in a macro that is never invoked.

- Test: `...test_falsified_unused_macro_is_not_a_citation`
- Result: `FAIL` — `problems=[]`

### F16. did `profile_denies_network` still misses `(ALLOW DEFAULT)`

The shared contract refuses this (H5). did's own gate still requires
`starts_with("(allow ")` and a `default` token.

- Checker: `capsules/did-provider/tests/confine.rs:1409`
- Test: `...test_falsified_did_gate_misses_uppercase_default`
- Probe op `did_denies` copies those predicates.
- Result: `FAIL` — `{'ok': True}`

### F17. did `profile_denies_network` still misses `(allow system-socket)`

Same gate: `contains("network")`. The shared contract refuses this (H5).

- Test: `...test_falsified_did_gate_misses_system_socket`
- Result: `FAIL` — `{'ok': True}`

## WEAK

These passed as documentation of a narrower gap. They do not reopen H1-H9.

### W1. U+200B after `/` is not treated as the host root

`(literal "/\u200b")` is not `path_normalises_to_root`. This host cannot
show whether `sandbox-exec` folds that path. Recorded as weak.

Command: `...test_weak_zero_width_path_is_not_normalised`. Result: `ok`.

### W2. Deny-then-allow of the exact root spelling still refuses

`(deny file-read* (subpath "/"))` then the same allow, claimed as
storage, still fails with `root-wide`. Ordering does not hide the
spellings #323 already closed. The new filters in F1-F9 still pass.

Command: `...test_weak_deny_then_allow_root_still_seen_as_root`.
Result: `ok`.

### W3. The model copy misses `(prefix "")` the same way

`model_is_root_wide_read` (`capsules/model-provider/tests/confine/main.rs:2517`)
uses the same `^/` / leading-`/` rule. Same hole as F1.

Command: `...test_weak_model_copy_misses_empty_prefix`. Result: `ok`.

### W4. did's source still holds the old predicates

Command: `...test_weak_did_source_still_has_old_predicates`. Result: `ok`.
`profile_denies_network` still contains `contains("network")` and
`starts_with("(import")`. That is the F16/F17 cause.

### W5. Wasmer without a memory cap stays an open gap

#323 records this as `OPEN GAP / NEEDS RUNTIME`. Re-run:
`wasmer_without_a_memory_cap_is_an_open_gap_not_proof` is among the 33
wasm passes. That is honest. It is not C0 proof.

## #323 owner suites re-run on this machine

All four commands from the PR body, plus the #346 suite, were re-run at
`fa1841f35d32e7bea98e124fd406231d0088fd4e` (this worktree; #323 files
unchanged):

| Suite | Result |
| --- | --- |
| `capsules/wallet-provider` `--test confine` | `34 passed; 0 failed; 11 ignored` |
| `capsules/model-provider` `--test confine` | `17 passed; 0 failed; 11 ignored` |
| `capsules/did-provider` `--test confine` | `6 passed; 0 failed; 11 ignored` |
| `lab/wasm-capsule` `--test run` | `33 passed; 0 failed; 9 ignored` |
| `python3 -I -m unittest discover -s lab/review-323/py -v` | `Ran 24 tests. OK` |

SHA-256 of the four files #323 touched, as read here:

| File | sha256 | bytes |
| --- | --- | --- |
| `capsules/wallet-provider/tests/confine.rs` | `d54803461509a63db3ec3f74b39833485e7f009a1c1a67164869b8f0f70252a9` | 211103 |
| `capsules/model-provider/tests/confine/main.rs` | `2a19c1536c335da40434c6cc235b607c85da326cc786c9ad52554f69ef36f4af` | 120490 |
| `capsules/did-provider/tests/confine.rs` | `7ea3014fc9bb14083f41361317b77306410bff1bb14a7f0fbf7840138244c2d1` | 61791 |
| `lab/wasm-capsule/tests/run.rs` | `e70531eadbabb4c03d92d6a48e441826de61b5c4781a6a4ce14b1fc666ce4b79` | 100149 |

#323's own tests still pass. This review does not reopen the #346
spellings. It shows the checkers remain spelling-narrow on a new class.

## Limits

- No `sandbox-exec`. F12, F13, and W1 are lab-check findings. Whether
  Apple's reader applies `(prefix "")`, `(ALLOW file-read*)`, or
  `mach-lookup` is unmeasured here.
- No `wasmtime` or `wasmer`. Wasm honesty was checked through `#[ignore]`
  and the wasmer-cap test that names the gap (W5).
- C1-C7 names are inferred, as in #294 and #346. The M1 check text is
  not in this repository.
- A8 is out of scope (#301). Runtime gaps A6, A10, A11, A12 stay
  NEEDS RUNTIME, as #323 said.

## Next

Do not count C1-C7 from #323. Close F1-F17 on the same checkers, with a
CAUGHT falsifier for each new refusal. Then a third independent review
of that head. Until then the #346 exact cases hold, and the class of
attack does not.
