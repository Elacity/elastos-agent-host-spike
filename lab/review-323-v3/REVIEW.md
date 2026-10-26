# Review of draft PR #323 (third pass)

Independent adversarial review of the lab-side M1 fix in draft PR #323
(`cursor/redteam-fix-4bfb` at `495968e7797b6825bd9b2bf1d52396a29ef1840d`).
The checkers live in this tree. This review only adds `lab/review-323-v3/`.
It does not edit #323 files, `lab/review-323/`, or `lab/review-323-v2/`.

- Target: #323 head `495968e7797b6825bd9b2bf1d52396a29ef1840d`
  (`lab/redteam-fix: allowlist macOS sandbox profile forms`).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`, Python 3.12.3.
  Absent: `sandbox-exec`, `wasmtime`, `wasmer`.
- How the live checkers are called: `python3 -I lab/review-323-v3/extract.py`
  copies the #323 functions into `lab/review-323-v3/probe/`. The review tests
  drive that probe. They do not re-implement the walk.
- How to run: `python3 -I -m unittest discover -s lab/review-323-v3/py -v`
  (or `lab/review-323-v3/run.sh`). That command exits 1 while the FALSIFIED
  items below still hold.

Anders's counting rule, as given for this review: a check counts only with
its complete journey, a refusal with a reason, a CAUGHT falsifier, and the
required reviews. C1-C7 lean on these checkers. A citation of a `#[test]`
that `cargo test -- --list` leaves out still cannot carry that count.

## Verdict

**No.** C1-C7 stay open. They are not bookable on the macOS `sandbox-exec`
run alone.

The allowlist closed the #346 and #352 grant holes. Mixed-case extra
allows, whitespace and `#|` tricks, filter swaps, path lookalikes,
`(if …)` / `(with …)` / `(require-any …)` wrappers, `param` aliases,
`import` / `#include`, and quoting all refuse on this head. Owner
counts match #323. Both earlier review suites are green.

Citation unlisting still matches only the exact bytes `#[cfg(any())]`.
`#[cfg(any( ))]`, `#[cfg( any() )]`, `#[cfg(any(false))]`, and
`#[cfg(windows)]` on Linux keep a `#[test] fn present_case(` that
`cargo test -- --list` leaves out. The lab checker also accepts
`#;(version 0)(allow file*)`: it treats `;` as a line comment, so the
allow vanishes, while a Scheme `#;` reader would drop only
`(version 0)` and keep the grant. Those two classes keep C1-C7 open
before anyone runs `sandbox-exec`.

## What must change

1. Count a citation only when `cargo test -- --list` names that
   `#[test] fn`, or blank every always-false / host-false `cfg`, not
   only the exact token `#[cfg(any())]`.
2. Read `#;` as a datum comment, or refuse a bare `#` reader form, so a
   later `(allow …)` on the same line stays visible.
3. Keep the independent review. This folder is that review for this
   head; it does not close C1-C7.

## HOLDS

Each item passed on this machine. Command and `file:line` name the live
#323 checker.

### H1. Every #346 bypass now refuses

Unfiltered `file-read*`, `(regex "^/")`, spaced `(literal "/" )`,
`(subpath "/.")`, string and nested-comment citations, a plain `fn`,
`(ALLOW DEFAULT)`, `(allow Default)`, `(allow system-socket)`, nested
and split `(allow default)`, nested network, nested import, exact
`(subpath "/")` as storage, and forced `--ignored` (`NOT RUN`) all
refuse.

Command: `Holds346Bypasses` (16 tests). Result: all `ok`.

### H2. Every #352 bypass now refuses

`(prefix "")`, `(regex ".*")`, `(regex "^[/].*")`, `string-append` root,
unfiltered `file*` / `file-write*`, `require-any` root, vnode-type only,
`(subpath "/var")` plus `(regex ".*")`, extra `(ALLOW file-read*)` and
`(allow(file-read*))` (still invisible to `allow_forms`, caught by
`allow_head`), `mach-lookup`, `ipc-posix*`, `#[cfg(any())]`, unused
`macro_rules`, and did's `(ALLOW DEFAULT)` / `system-socket` all refuse.

Command: `Holds352Bypasses` (17 tests). Result: all `ok`.
Checker: `capsules/wallet-provider/tests/confine.rs:2407`
(`check_profile_contract`), `:1794` (`is_permitted_storage_form`),
`:1892` (`rust_holds_cited_test`). Did:
`capsules/did-provider/tests/confine.rs:1495`.

### H3. New allowlist attacks refuse

Mixed-case extra grants, tab/newline/space inside extra forms, `;`
comments that leave a visible allow, `#|` block comments, string
escapes and Unicode lookalikes, a permitted storage form plus a second
filter, regex/prefix/literal/subpath swaps, `//` `/./` `/../` and
symlink-looking names, `(if …)` / `(begin …)` / `(with …)` /
`(require-any …)` / `(require-all …)`, non-canonical `param` names,
`import` / `include` / `%include` / `#include` / `eval` / `define`,
`'` / `` ` `` / `,@` quoting, and extra ops (`file-ioctl*`, `signal`,
`iokit-user-client*`, `mach-priv-task-port`, `process-info*`,
`sysctl-write`). The same storage swaps refuse as declared storage.

Command: `HoldsNewAllowlistAttacks`. Result: all `ok`.

### H4. Citation cases that match `cargo test -- --list`

Exact `#[cfg(any())]` is unlistable. A doc comment is not a citation.
`#[cfg(test)] fn present_case()` without `#[test]` is not a citation.
`#[test] #[ignore]` is listed by cargo and counts. A `#[test]` of the
same name outside the provider directory is refused.

Command: the five `CitationUnlisting.test_holds_*` tests. Result: `ok`.

## FALSIFIED

Each item has a test that asserts the refusal the contract still needs.
On #323 today the test fails.

The one review command:

```bash
python3 -I -m unittest discover -s lab/review-323-v3/py -v
```

Result: `Ran 52 tests in 1.508s` / `FAILED (failures=5)`.
42 HOLDS tests passed. 5 WEAK tests passed. 5 FALSIFIED tests failed.

### F1. `#[cfg(any( ))]` still counts as a citation

`rust_source_without_cfg_any_items` matches only the exact bytes
`#[cfg(any())]`. A space inside `any( )` is still always-false. Cargo
lists `0` tests named `present_case`. The checker returns `holds=true`.

- Checker: `confine.rs:2012` and `:1892`
- Test: `CitationUnlisting.test_falsified_cfg_any_with_spaces_is_not_a_citation`
- Result: `FAIL` — `True is not false`

### F2. `#[cfg( any() )]` still counts as a citation

Same exact-string hole.

- Test: `...test_falsified_cfg_any_inner_spaces_is_not_a_citation`
- Result: `FAIL`

### F3. `#[cfg(any(false))]` still counts as a citation

Always-false, not listed. The unlister looks only for empty `any()`.

- Test: `...test_falsified_cfg_any_false_is_not_a_citation`
- Result: `FAIL`

### F4. `#[cfg(windows)]` still counts as a citation on Linux

`cargo test -- --list` on this host lists no `present_case`. The
checker still finds `#[test] fn present_case(`.

- Test: `...test_falsified_cfg_windows_is_not_a_citation_on_linux`
- Result: `FAIL`

### F5. `#;(version 0)(allow file*)` passes the contract

`profile_characters` starts a line comment at every `;` outside a
string, including the `;` in `#;`. The rest of the line disappears.
The extra form is the bare atom `#`. A Scheme `#;` reader comments
only the next datum `(version 0)` and keeps `(allow file*)`.

Exact profile text appended to the fixture:

```
#;(version 0)(allow file*)
```

- Checker: `confine.rs:5614` (`profile_characters`) and `:2407`
- Test: `FalsifiedNewBypasses.test_falsified_hash_semicolon_hides_a_following_allow`
- Result: `FAIL` — `{'ok': True}`

This host has no `sandbox-exec`. The lab check that C1-C7 would cite
already accepts the form.

## WEAK

These passed as documentation of a narrower gap. They do not reopen H1-H4.

### W1. `#;(allow file*)` comments the grant out

The extra form is `#` only. Both a `;` reader and a `#;` reader drop
the allow. Recorded so F5 is the two-datum spelling.

### W2. Leftover `is_root_wide_read` still misses `(prefix "")`

The dead helper is still spelling-narrow. The allowlist refuses the
same form as storage.

### W3. The model copy of `allow_forms` still needs `(allow `

`(ALLOW file*)` is invisible to `model_allow_forms`. The shared
contract refuses it through `allow_head`.

### W4. Model storage lowercases param strings

`model_is_permitted_storage_form` accepts
`(allow file-read* (literal (param "storage_parent")))`. The shared
storage allowlist still requires `STORAGE_PARENT`.

### W5. Wasmer without a memory cap stays an open gap

`wasmer_without_a_memory_cap_is_an_open_gap_not_proof` is among the 33
wasm passes. Honest. Not C0 proof.

## Claimed falsifiers, re-broken on this machine

Each break was patched, the named test was run, then the file was
restored with `git checkout`. The tree of #323 files is clean.

| What I broke | Named test | Result |
| --- | --- | --- |
| Leftover `allow_head` body replaced with `false &&` | `file_profile_contract_refuses_nested_grants` | still `ok` (unknown-head fallthrough still names the extra form) |
| Leftover `allow_head` `continue`s | `file_profile_contract_refuses_nested_grants` | FAIL (`an unpermitted allow form must fail the allowlist`) |
| `is_permitted_storage_form` always true | `declared_rights_trace_refuses_each_bad_input` | FAIL |
| Citation unlisting skipped (`cfg` / macro blanking off) | `operations_table_check_reports_each_missing_citation` | FAIL (`#[cfg(any())] must not count`) |
| `did_is_permitted_profile_form` always true | `profile_denies_network_refuses_casefolded_and_system_socket` | FAIL (`must refuse (ALLOW DEFAULT)`) |
| Unknown-head first walk and leftover both off | `file_profile_contract_refuses_nested_grants` | FAIL (`(foo bar)` accepted) |

The first wording of "skip `allow_head`" still passes the named test.
Continuing past that check, which is the skip that drops the extra
allow, fails it. The other four named falsifiers fail as claimed.

## #323 owner suites re-run on this machine

All four commands from the PR body, plus both earlier review suites,
were re-run at `495968e7797b6825bd9b2bf1d52396a29ef1840d`:

| Suite | Result |
| --- | --- |
| `capsules/wallet-provider` `--test confine` | `34 passed; 0 failed; 11 ignored` |
| `capsules/model-provider` `--test confine` | `17 passed; 0 failed; 11 ignored` |
| `capsules/did-provider` `--test confine` | `7 passed; 0 failed; 11 ignored` |
| `lab/wasm-capsule` `--test run` | `33 passed; 0 failed; 9 ignored` |
| `lab/review-323/run.sh` | `Ran 24 tests. OK` |
| `lab/review-323-v2/run.sh` | `Ran 39 tests. OK` |
| `lab/review-323-v3/run.sh` | `Ran 52 tests` / `FAILED (failures=5)` |

SHA-256 of the four files #323 touched, as read here:

| File | sha256 | bytes |
| --- | --- | --- |
| `capsules/wallet-provider/tests/confine.rs` | `7bcd8bfe26dab411e46cdc5b39d1ff2ab61656cc31350111c0d690e5db892720` | 225313 |
| `capsules/model-provider/tests/confine/main.rs` | `baf250fd73a1f3f71cd94fc933ff2ef7c51a447a92ccbb15eb57170e0505c1c6` | 120766 |
| `capsules/did-provider/tests/confine.rs` | `2809e6f15ed87690d2c342e3d807c7bcd5ef33fa255f16bf7512936bd3a6cecf` | 65983 |
| `lab/wasm-capsule/tests/run.rs` | `e70531eadbabb4c03d92d6a48e441826de61b5c4781a6a4ce14b1fc666ce4b79` | 100149 |

## Limits

- No `sandbox-exec`. F5 is a lab-check finding. Whether Apple's reader
  applies `#;(version 0)(allow file*)` is unmeasured here.
- No `wasmtime` or `wasmer`. Wasm honesty was checked through
  `#[ignore]` and the wasmer-cap test that names the gap (W5).
- C1-C7 names are inferred, as in #294, #346 and #352. The M1 check
  text is not in this repository.
- A8 is out of scope (#301). Runtime gaps A6, A10, A11, A12 stay
  NEEDS RUNTIME, as #323 said.

## Next

Do not count C1-C7 from #323. Close F1-F5 on the same checkers, with a
CAUGHT falsifier for each new refusal. Then a fourth independent review
of that head. The #346 and #352 grant spellings hold. Citation
unlisting and the `#;` reader still do not.
