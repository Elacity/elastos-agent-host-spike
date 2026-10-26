# Review of draft PR #323

Independent adversarial review of the lab-side M1 fix in draft PR #323
(`cursor/redteam-fix-4bfb` at `d0aa6f0d52ff9a4aa873e5b164d2f7d536833f0f`).
The checkers live in this tree. The review only adds `lab/review-323/`.

- Target: #323 head `d0aa6f0d52ff9a4aa873e5b164d2f7d536833f0f`
  (`lab/redteam-fix: parse profiles as s-expressions and stop counting skips as proof`).
  Parent of that commit: `6870b9e0c73833d62988f640c39ded6d1a2caa2f`.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`, Python 3.12.3.
  Absent: `sandbox-exec`, `wasmtime`, `wasmer`.
- How the live checkers are called: `python3 -I lab/review-323/extract.py`
  copies the #323 functions into `lab/review-323/probe/`. The review tests
  drive that probe. They do not re-implement the walk.
- How to run: `python3 -I -m unittest discover -s lab/review-323/py -v`
  (or `lab/review-323/run.sh`). That command exits 1 while the FALSIFIED
  items below still hold.

Anders's counting rule, as given for this review: a check counts only with
its complete journey, a refusal with a reason, a CAUGHT falsifier, and the
required reviews. C1-C7 lean on these checkers. A checker that still accepts
a host-wide read as storage, or a string as a function citation, cannot carry
that count.

## Verdict

**No.** #323 is not safe to rely on for C1-C7 evidence.

The exact #294 cases it names still refuse: nested and split `(allow default)`,
nested network, `(import ...)`, the exact `(subpath "/")` storage claim, a
prefix-plus-`x` justification, and a `//` comment citation. Default
`cargo test` on Linux reports the macOS and engine tests as `ignored`, not
as passed. That is real progress.

The checkers still match a short spelling list. An unfiltered
`(allow file-read*)` declared as storage passes. A string or a nested block
comment satisfies a citation. `(ALLOW DEFAULT)` and `(allow system-socket)`
pass the contract. `cargo test -- --ignored` on Linux still reports a
sandbox test as passed. Those holes are enough to keep C1-C7 open.

## What must change

1. Treat a storage file-read as root-wide when it has no path filter, a
   regex or prefix on `/`, or a path that normalises to `/` (`/.`, `//`,
   extra space inside the filter). Pin that rule, not the two current
   substrings.
2. Nest Rust block comments. Drop `fn NAME(` that sits inside a string.
   A citation must name a remaining function, not leftover text.
3. Refuse `system-socket` (and any other SBPL network operation the
   contract cares about) by an operation list, not `contains("network")`.
4. Refuse `allow default` after case folding, or refuse an unknown
   operation name.
5. A sandbox test that cannot run must panic `NOT RUN` when forced, the
   way `lab/wasm-capsule/tests/run.rs` already does. An early `return`
   after `#[ignore]` still counts as a pass under `--ignored`.
6. Point did-provider's `profile_denies_network` at the shared sexp
   reader. Its current `profile_forms` still cuts at every `;`.
7. Refuse unknown top-level forms (`include`, `load`, `require`) or pin
   the inclusion list. `import` alone is not the class.
8. Keep the independent review. This folder is that review for #323; it
   does not close C1-C7.

## HOLDS

Each item passed on this machine. Command and `file:line` name the live
#323 checker.

### H1. Nested `(if #t (allow default))` is refused

Command:

```bash
python3 -I -m unittest lab.review-323.py.test_review_323.HoldsClaimedRefusals.test_holds_nested_allow_default
```

Result: `ok`. Probe reason:
`fixture-provider must reject (allow default): (allow default)`.
Checker: `capsules/wallet-provider/tests/confine.rs:1842`
(`check_profile_contract`) and `:1555` (`is_default_allow`).

### H2. Split nested `(allow` / `default)` is refused

Command: `...HoldsClaimedRefusals.test_holds_split_allow_default`  
Result: `ok`. Same checker. This is #323's own split-form case.

### H3. Nested `(begin (allow network*))` is refused

Command: `...HoldsClaimedRefusals.test_holds_nested_network`  
Result: `ok`. Reason contains `network allow is refused`.
Checker: `:1548` (`is_network_allow`).

### H4. Nested `(import "bsd.sb")` is refused

Command: `...HoldsClaimedRefusals.test_holds_nested_import`  
Result: `ok`. Checker: `:1560` (`is_import`).

### H5. Exact `(allow file-read* (subpath "/"))` as storage is refused

Command: `...HoldsClaimedRefusals.test_holds_exact_subpath_root_as_storage`  
Result: `ok`. Reason contains `root-wide`.
Checker: `:1569` (`is_root_wide_read`) and `:2101`
(`check_declared_rights` storage loop).

### H6. Prefix plus `x` is not a justification

Command: `...HoldsClaimedRefusals.test_holds_prefix_plus_x_justification`  
Result: `ok`. Reason requires the pinned sentence and does not say
`must start with "x"`.
Checker: `:1657` (`platform_baseline_justification_text`) and `:2020`
(exact `!=` compare).

### H7. A `//` comment is not a function citation

Command: `...HoldsClaimedRefusals.test_holds_line_comment_is_not_a_citation`  
Result: `ok`. One problem, `does not hold`.
Checker: `:1604` (`rust_source_without_comments`) and `:2531`
(`operations_table_citation_problems`).

### H8. The model sexp walk sees a nested allow

Command: `...HoldsClaimedRefusals.test_holds_model_walk_sees_nested_allow`  
Result: `ok`. Forms include `(allow default)`.
Checker: `capsules/model-provider/tests/confine/main.rs:2379`
(`model_allow_forms`).

### H9. The model comment-strip function matches the wallet copy

Command: `...HoldsClaimedRefusals.test_holds_model_comment_strip_matches_wallet`  
Result: `ok`. Extracted `rust_source_without_comments` bytes are identical:
sha256 `12982c8726a7c1ac3a3a8c0e8d781be2f994cb1aebd961a895df89d5a37a530a`
from both files (50 lines). After rename, `profile_forms` and
`profile_characters` also match.

### H10. Default `cargo test` reports missing tools as ignored

Commands (this session):

```bash
(cd capsules/wallet-provider && cargo test --test confine)
(cd capsules/model-provider && cargo test --test confine)
(cd capsules/did-provider && cargo test --test confine)
(cd lab/wasm-capsule && cargo test --test run)
```

Results:

- wallet: `ok. 34 passed; 0 failed; 11 ignored` (0.11s)
- model: `ok. 17 passed; 0 failed; 11 ignored` (0.11s)
- did: `ok. 5 passed; 0 failed; 11 ignored` (0.02s)
- wasm: `ok. 33 passed; 0 failed; 9 ignored` (1.51s)

These match #323's claimed counts. Ignored lines use
`NOT RUN: sandbox-exec is macOS only` or
`NOT RUN: needs wasmtime or wasmer on PATH`.

## FALSIFIED

Each item has a test in `lab/review-323/py/test_review_323.py` that asserts
the refusal the contract still needs. On #323 today the test fails.

The one review command:

```bash
python3 -I -m unittest discover -s lab/review-323/py -v
```

Result: `Ran 24 tests in 0.491s` / `FAILED (failures=10)`.
9 HOLDS tests passed. 5 WEAK tests passed. 10 FALSIFIED tests failed.

### F1. Unfiltered `(allow file-read*)` declared as storage

`is_root_wide_read` needs `(literal "/")` or `(subpath "/")`. A bare
`file-read*` is a host-wide read and is wider than those two spellings.

- Checker: `capsules/wallet-provider/tests/confine.rs:1569` and `:2101`
- Test: `FalsifiedRootWideStorage.test_falsified_unfiltered_file_read_as_storage`
- Result: `FAIL` — checker returned `{'ok': True}`

### F2. `(allow file-read* (regex "^/"))` declared as storage

Same checker. A regex on `/` is a root-wide read.

- Test: `...test_falsified_regex_root_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F3. `(allow file-read* (literal "/" ))` declared as storage

The extra space before `)` survives `profile_forms`. The substring
`(literal "/")` is then absent, so the storage refusal does not fire.

- Test: `...test_falsified_spaced_literal_root_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F4. `(allow file-read* (subpath "/."))` declared as storage

`/.` is the host root. The checker looks for the exact `"/"` spelling.

- Test: `...test_falsified_dot_subpath_root_as_storage`
- Result: `FAIL` — `{'ok': True}`

### F5. A string literal satisfies a citation

`rust_source_without_comments` keeps string text. A file that holds only
`const S: &str = "fn present_case(";` makes
`operations_table_citation_problems` return no problems.

- Checker: `capsules/wallet-provider/tests/confine.rs:1604` and `:2531`
- Test: `FalsifiedCitationJunk.test_falsified_string_literal_is_not_a_function`
- Result: `FAIL` — `problems=[]`

The model copy is the same function (H9), so
`capsules/model-provider/tests/confine/main.rs:2507` has the same hole.

### F6. A nested block comment satisfies a citation

Rust nests `/* */`. The stripper does not. Source
`/* /* */ fn present_case() {} */` still contains `fn present_case(` after
the strip, and the citation check accepts it.

- Checker: same as F5
- Test: `...test_falsified_nested_block_comment_is_not_a_function`
- Result: `FAIL` — `problems=[]`

### F7. `--ignored` still counts a missing-tool sandbox test as passed

#323 added `#[ignore]`, so default `cargo test` no longer reports `ok`
(H10). The test body still returns when `sandbox-exec` is absent
(`capsules/wallet-provider/tests/confine.rs:732`). Forced:

```bash
(cd capsules/wallet-provider && cargo test --test confine \
  confined_outside_write_is_denied -- --ignored --test-threads=1)
```

Result: `ok. 1 passed; 0 failed; 0 ignored` (exit 0).
The same shape on did: `outside_write_denied` →
`ok. 1 passed` (exit 0).
Wasm under the same flag fails: `same_name_same_output_on_wasmtime_and_wasmer`
→ `FAILED. 0 passed; 1 failed` with
`NOT RUN: wasmtime and wasmer not found on PATH` (`lab/wasm-capsule/tests/run.rs:934`).

- Test: `FalsifiedSkipStillCounts.test_falsified_ignored_wallet_sandbox_test_still_passes`
- Result: `FAIL` — `AssertionError: 0 == 0`

A skipped test can still count as success if someone runs `--ignored`.
That is the honesty hole #323 said it closed.

### F8. `(ALLOW DEFAULT)` and `(allow Default)` pass the contract

`is_default_allow` needs a lowercase `(allow ` prefix and the token
`default`.

- Checker: `capsules/wallet-provider/tests/confine.rs:1555`
- Tests: `...test_falsified_allow_default_uppercase`,
  `...test_falsified_allow_default_titlecase`
- Result: both `FAIL` — `{'ok': True}`

`sandbox-exec` was not run here. The lab check that C1-C7 would cite
already accepts the forms.

### F9. `(allow system-socket)` passes the contract

`is_network_allow` is `starts_with("(allow ") && contains("network")`.
SBPL `system-socket` creates sockets and does not contain that word.

- Checker: `capsules/wallet-provider/tests/confine.rs:1548`
- Test: `...test_falsified_system_socket_is_a_network_grant`
- Result: `FAIL` — `{'ok': True}`

## WEAK

These passed as documentation of a narrower gap. They do not reopen H1-H7.

### W1. `(include "bsd.sb")` is not an import

`is_import` only matches a form that starts with `(import`
(`confine.rs:1560`). The contract accepts `(include "bsd.sb")`,
`(load "bsd.sb")` and `(require "bsd.sb")`. This host cannot show whether
`sandbox-exec` honours those forms.

Command: `...WeakRemainingGaps.test_weak_include_is_not_treated_as_import`  
Result: `ok` (the live checker accepts `include`).

### W2. did-provider still uses the old `;` cut

`capsules/did-provider/tests/confine.rs:1438` (`profile_forms`) still
splits every line on `;` and counts parentheses inside strings.
`#323` taught `profile_denies_network` (`:1409`) to walk nested lists, but
the reader is the pre-#323 one. On
`(deny file-read* (literal "/x;")) (allow default)` the did reader panics
`incomplete profile form`. The shared wallet check (H1) still sees the
hidden `(allow default)`.

Command: `...test_weak_did_parser_still_cuts_at_every_semicolon`  
Result: `ok` (panic observed).

### W3. `(allow(default))` is not seen as allow-default

`is_default_allow` requires `(allow ` with a space. The exec checker
already knows a flush head (`(allow(`). Default and network do not.

Command: `...test_weak_flush_head_default_is_not_seen`  
Result: `ok` (`default_allow` is false). Scheme would read this as
`(allow (default))`, so it may not be a live grant. Recorded as weak.

### W4. A second `process-fork` is not a second exec allow

`is_exec_allow` (`confine.rs:1696`) counts `process*` and `process-exec*`.
`(allow process-fork)` passes the contract. The claimed rule is "one
process-exec allow", not every process grant.

Command: `...test_weak_process_fork_is_not_an_exec_allow`  
Result: `ok` (contract accepts the extra form).

### W5. A citation still need not be a `#[test]`

#323's own docstring at `confine.rs:2463` says the check does not decide
whether the `fn` is a test. A plain `fn present_case() {}` still passes.

Command: `...test_weak_citation_does_not_require_a_test_attribute`  
Result: `ok`.

### W6. Wasmer without a memory cap stays an open gap

#323 records this as `OPEN GAP / NEEDS RUNTIME` and keeps
`memory_cap_on_wasmer_is_skipped` ignored. Re-run:
`wasmer_without_a_memory_cap_is_an_open_gap_not_proof` is among the 33
wasm passes. That is honest. It is not C0 proof.

### W7. The pinned justification is exact text, not a decision record

H6 holds: junk is refused. The pinned sentences still describe the rule
("file-read* of literal / is the startup root-directory read") and the
status line still omits "Anders decides". That is a content gap, not a
bypass of the exact-match check.

## #323 owner suites re-run on this machine

All four commands from the PR body were re-run at
`d0aa6f0d52ff9a4aa873e5b164d2f7d536833f0f`:

| Suite | Result |
| --- | --- |
| `capsules/wallet-provider` `--test confine` | `34 passed; 0 failed; 11 ignored` |
| `capsules/model-provider` `--test confine` | `17 passed; 0 failed; 11 ignored` |
| `capsules/did-provider` `--test confine` | `5 passed; 0 failed; 11 ignored` |
| `lab/wasm-capsule` `--test run` | `33 passed; 0 failed; 9 ignored` |

SHA-256 of the four files #323 touched, as read here:

| File | sha256 | bytes |
| --- | --- | --- |
| `capsules/wallet-provider/tests/confine.rs` | `553c0a3151e06b767d51f8deaa4d6e7a2b7f16dead2028149772ce75049b9915` | 197924 |
| `capsules/model-provider/tests/confine/main.rs` | `94f4befe34ff1cc7aba349e249191754c97c6c4588eb36dbc052d0b8ae226fcd` | 117565 |
| `capsules/did-provider/tests/confine.rs` | `efd9d385da7d3ad4a2986650c03e5c61c7ff11759571f8a2ff41730e8d38a07a` | 58441 |
| `lab/wasm-capsule/tests/run.rs` | `e70531eadbabb4c03d92d6a48e441826de61b5c4781a6a4ce14b1fc666ce4b79` | 100149 |

#323's eight named falsifiers (nested `if`/`begin`, split `(allow`,
root-wide `(subpath "/")`, prefix-plus-`x`, comment citation, and the
three post-fix tampers) still have passing owner tests. This review does
not reopen those exact cases. It shows the checkers remain spelling-narrow.

## Limits

- No `sandbox-exec`. F8 and W1 are lab-check findings. Whether Apple's
  reader applies `(ALLOW DEFAULT)` or `(include ...)` is unmeasured here.
- No `wasmtime` or `wasmer`. Wasm honesty was checked through `#[ignore]`
  and `--ignored` (wasm fails; wallet/did pass).
- C1-C7 names are inferred, as in #294. The M1 check text is not in this
  repository.
- A8 is out of scope (#301). Runtime gaps A6, A10, A11, A12 stay
  NEEDS RUNTIME, as #323 said.

## Next

Do not count C1-C7 from #323. Close F1-F9 on the same checkers, with a
CAUGHT falsifier for each new refusal. Then a second independent review
of that head. Until then the #294 exact cases hold, and the class of
attack does not.
