# B0: one macOS root-read baseline for did, wallet and model

Measurement only. This record changes no provider profile and no Runtime code.
Base: `ea80c9ef` on `claude/confine-b0-rootread`. Host: `Darwin 25.5.0 arm64`,
rustc 1.91.0 (receipt lines 5-6); `sandbox-exec` ran in the suites (229).

The evidence is one receipt,
`~/Sparks/office/evidence/confine-b0-fix/receipt-6676d467.log`, which pins head
`6676d467` and tree `d87a2130` (receipt line 3). Its sha256, recomputed with
`shasum -a 256`, is
`e49a33b6e1d1d30eedc3734b2b063a78b49dfa15675ffc417dbfed492917c608`. The sibling
`receipt-6676d467.sha256` holds two lines because
`~/Sparks/office/receipt-local.sh:32` appends the digest with `tee -a` while
the log itself is overwritten; its second line is current and matches the
recompute, and its first line (`1851b828...`) is an earlier write of the same
path. The log prints the head, tree, toolchain and every command with its
exit and its output, apart from the Cargo progress lines (`Compiling`,
`Checking`, `Downloading` and the like) that `receipt-local.sh:26` filters.

## The committed forms

| Provider | Profile | Root-read rule |
|---|---|---|
| did | `capsules/did-provider/confine.sb:13` | `(allow file-read* (literal "/"))` |
| wallet | `capsules/wallet-provider/confine.sb:24` | `(allow file-read* (literal "/"))` |
| model | `capsules/model-provider/confine.sb:21` | `(allow file-read-data (literal "/"))` |

The lab generator at
`capsules/wallet-provider/tests/common/profile_generator.rs:134-148` emits the
three head forms, then each rule of each declared right, then each rule of each
platform-baseline entry, verbatim and in file order. The root-read form is a
fixture row, not generator code:

- did `tests/fixtures/confine/declared-rights.json:25`
- wallet `tests/fixtures/confine/declared-rights.json:25`
- model `tests/fixtures/confine/declared-rights.json:26`

The generator selects no provider and rewrites no rule, so one row can carry
the shared form for all three. The model document already says a metadata-only
grant is not enough (`capsules/model-provider/CONFINEMENT.md:101`).

## Candidate forms

Seatbelt reads narrow in this order: `file-read*` (data, metadata and
attributes), `file-read-data` (file content), `file-read-metadata` (names and
attributes), then no rule (Seatbelt operation names, not measured here). All
three providers ran the no-rule form as a plant (receipt lines 333, 1141,
1962). did and wallet ran `file-read*` as their control and `file-read-data`,
`file-read-metadata` and no rule as plants. model's control is
`file-read-data`; model never ran `file-read*`.

## Runs

Each plant is one command of the receipt. It runs
`lab/confine-measurements/root-read-b0-plant.sh`, which checks that the profile
holds exactly one copy of the expected line, substitutes the candidate or
deletes it, runs the provider's whole confine suite with `--no-fail-fast`, and
restores the profile with `cp -p` in its exit trap; `cmp` proves the bytes and
`git diff --quiet` proves the tree.

Control runs the whole confine suite per provider with `--no-fail-fast` on the
unmodified tree: did 16 passed and 1 ignored (33), wallet 103 passed (146),
model 39 passed (195).

The tool touches the restored profile after `cp -p`, because the wallet suite
embeds its profile with `include_str!`; an older mtime would keep the planted
copy inside the next test binary. The receipt also runs
`root-read-b0-interrupt-test.sh`, which plants the wallet profile, sends SIGTERM
to the plant, and proves the profile and the tree are restored. The receipt's
run printed `interrupted plant exit=143` (201), the status the plant's TERM trap
sets. That run predates the test's exit-143 check, added at `741c53da`. The
remove-restore falsifier fails at its `cmp` with `falsifier interrupt exit=5`
(2223-2227).

A second receipt runs the test with that check:
`~/Sparks/office/evidence/confine-b0-fix/receipt-af44019e-interrupt.log`,
which pins head `af44019e` and tree `85c96eb9` (its line 3), sha256
`42fc64737dc81ab2063900d4d42e7fdc974e06e8fbf4defba5ff7e6e0532940f`, recomputed
with `shasum -a 256` and equal to the one line of its `.sha256` sidecar. In
that log the test prints `interrupted plant exit=143` and exits 0 (its lines
11-13). Its falsifier drops the test's `kill -TERM "$pid"` line, so the plant
runs the whole wallet suite (97 passed, 6 failed, its line 338) and restores on
the normal path; the test then prints `plant exit=101, not 143: the plant was
not interrupted` and exits 7 (its lines 343-345). In both receipts no line
separates the SIGTERM line from the exit-143 line (200-201 here, 11-12 there),
so neither shows whether the plant's child-kill branch ran.

Each plant run records a result for every test in that provider's suite
(receipt lines 244, 325, 409, 739, 1133, 1524, 1697, 1954, 2214; bare numbers
in parentheses below are receipt lines too). The plant
edits only the provider's `confine.sb`, so only tests that start the provider
under that file, or read it, run under the candidate form. Tests that build a
profile from `declared-rights.json` keep the fixture row in every run.

| Provider | `file-read-data` | `file-read-metadata` | no root read |
|---|---|---|---|
| did | 16 passed, 1 ignored | 8 passed, 8 failed, 1 ignored | 8 passed, 8 failed, 1 ignored |
| wallet | 97 passed, 6 failed | 81 passed, 22 failed | 82 passed, 21 failed |
| model | 39 passed | 21 passed, 18 failed | 21 passed, 18 failed |

The model profile already holds `file-read-data`, so its `data` plant is the
control run of the same line and changes no byte.

The six wallet `file-read-data` failures are profile-text checks, and the
substituted line fails them by construction. Five compare a generated profile
or a document with the committed profile.
`every_did_and_wallet_allow_rule_has_a_registered_removal` instead compares the
committed allow rules with the registered removal entries (`:19125`), and its
panic names the substituted line as a rule no entry removes (452):

- `generated_did_and_wallet_profiles_match_their_committed_oracles`
  (`capsules/wallet-provider/tests/confine.rs:18553`)
- `every_did_and_wallet_allow_rule_traces_to_one_declared_right` (`:18450`)
- `every_did_and_wallet_allow_rule_has_a_registered_removal` (`:19124`)
- `every_confinement_document_lists_its_profiles_allow_rules` (`:19194`)
- `linux_contract_table_check_refuses_each_bad_table` (`:19513`)
- `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
  (`:5546`)

Starts under the committed `confine.sb` pass under `file-read-data`: did 16
passed (244), wallet failed only the six text checks above (732-737), model 39
passed (1697). Under `file-read-metadata` and with the line deleted, the tests
that start the provider under its committed `confine.sb` and wait for an `init`
answer fail at that answer with SIGABRT:

- did, 8 per run at `tests/confine.rs:304` (metadata 255-308, none 339-392):
  `provider did not answer request {... "op":"init"} (the response stream
  ended); child signal: 6 (SIGABRT)` (340).
- wallet, 15 per run at `tests/confine.rs:997` (metadata 756-1102, none
  1150-1494), with the same message (1151).
- model, 10 per run (metadata 1767-1805, none 2027-2065):
  `the provider process exited before answering "init": signal: 6 (SIGABRT)`.

Starts from a generated profile read the fixture row (did and wallet
`file-read*` at `declared-rights.json:25`, model `file-read-data` at `:26`), and
they pass in the metadata and none runs:

- wallet suite: `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host`
  starts did and wallet and requires `get_did` and `status` to answer `ok`
  (`capsules/wallet-provider/tests/confine.rs:4620-4700`); ok at 1080 and 1430.
  `standin_start_runs_under_the_generated_profile_not_the_committed_file`
  requires the wallet's `init` refusal `storage_error` (`:5583`); ok at 1035
  and 1433.
- model suite: `generated_profile_permits_init_and_denies_the_local_offer`
  (`tests/confine/main.rs:3987`; ok at 1750 and 2010) and
  `generated_profile_denies_the_hosted_connect` (`:4200`; ok at 1730 and 1990)
  require `init` to serve. `standin_launch_uses_the_generated_profile`
  (`:4261`; ok at 1927 and 2187) requires `init` to answer
  `journal_access_denied`.
- The did suite holds no generated-profile start. Its ok rows in the none run
  are 346, 367, 371, 372, 377, 389, 390 and 395; none of them requires an
  `init` answer.

The other five model `generated_profile_*` tests fail in those runs at their
allow-line comparison with the committed file, before any start (none
1984-2024).

Launches of the committed `confine.sb` that pass with the line deleted, none of
which requires an `init` answer:

- `unbound_copy_is_refused_under_profile`, did (395) and wallet (1497): it
  starts a copy of the binary under `PROFILE_PATH`
  (`capsules/did-provider/tests/confine.rs:1385`,
  `capsules/wallet-provider/tests/confine.rs:5808`) and requires `sandbox-exec`
  to refuse the exec with exit 71, before the binary runs. model's
  `model_unbound_program_refused_under_profile` (2186,
  `tests/confine/main.rs:3008`) does the same.
- `startup_is_refused_when_the_profile_cannot_be_applied`, did (389), wallet
  (1484) and model (2190): one case binds `PROFILE_PATH` without
  `STORAGE_ROOT` (did `:1314`, wallet `:3922`, model `:3728`). `sandbox-exec`
  runs, cannot apply the profile, and exits 65 before the provider runs (did
  387, wallet 1482: `child exit status: 65`).
- `byte_different_file_at_bound_path_starts`, model (1997): it runs a
  byte-different copy of the binary under `PROFILE_PATH` (`:3338`) and fails
  only on exit 65, or on exit 71 with `execvp()` and `Operation not permitted`
  on stderr (`:3346-3356`). It passes in every model run (1548, 1737, 1997);
  the outcome is still running at 2 seconds under data (1547) and signal 6
  under metadata and none (1729, 1989).

`bound_executable_digest_mismatch_refuses_start` (model, 1975) is not a launch
of the committed profile: the digest check panics on the changed copy of
`/usr/bin/true` at `tests/confine/main.rs:345` (1973-1974), called from
`check_provider_executable` before `sandboxed` loads the profile (`:395-397`).

## Conclusion

With the root line deleted from the committed `confine.sb`:

| Provider | Fails (list) | Passes that start a provider and need an answer |
|---|---|---|
| did | 8 committed-profile starts (400-407) | none |
| wallet | 15 committed-profile starts, 6 text checks (1502-1522) | `standin_c0` (1430), `standin_start_runs_...` (1433) |
| model | 10 committed-profile starts, 5 generated-profile oracle checks, 3 text checks (2195-2212) | the three model starts above (1990, 2010, 2187) |

The narrower conclusion: for starts that load the committed `confine.sb`, run
the provider binary and wait for its `init` answer (did 8, wallet 15, model 10,
listed above), `(allow file-read-data (literal "/"))` is the narrowest measured
form that serves did, wallet and model, and removing the line fails those
starts at `init`, so on those starts the form is needed. The receipt does not
show it needed for the committed-profile launches listed above that pass with
the line deleted, such as `unbound_copy_is_refused_under_profile` in did (395)
and wallet (1497), which expect `sandbox-exec` to refuse a copy before the
binary runs. The generated-profile starts never ran under a candidate; they
show the fixture row works and nothing about narrowing or deleting it. Unmeasured: did and wallet starts from a generated
profile whose root row is `file-read-data`, and any generated-profile start
without a root-read row.

On those init-answer starts, the did and wallet `file-read*` form is broader
than they need, and the metadata rung fails them for all three providers, which
agrees with the model document's sentence.

Proposal for the confinement crate: one platform-baseline row,
`startup-root-directory`, holding `(allow file-read-data (literal "/"))`, and
all three providers render that row. The Runtime keys the rule to the baseline
id, not to a provider name. B0 makes no such change. For did and wallet, B0
measured that row's text only inside the committed `confine.sb`; the row as the
generator renders it is not measured for them.

## Limits

- Measured on one `Darwin 25.5.0 arm64` host (5); the receipt holds no x86-64
  run.
- Each plant ran the whole suite, but the generated-profile starts ran on the
  fixture row in every plant, so they are not results under a candidate form.
- The six text checks named above all fail when the line is substituted:
  under `data` at 446, 453, 457, 476, 505 and 585, under `metadata` at 797, 804,
  808, 833, 862 and 1025. With the line deleted five fail (1190, 1198, 1220,
  1252, 1352) and `every_did_and_wallet_allow_rule_has_a_registered_removal`
  passes (1194); the `data` run's panic names the substituted line as the rule
  no entry removes (452), and deletion leaves no such rule. The deletion run
  also fails `profile_allow_table_check_refuses_each_bad_table` (`left: 4`,
  `right: 5`, 1285-1289) and passes
  `linux_contract_table_covers_every_committed_allow_form` (1279), which the
  `metadata` run fails (864-866). The receipt lists each run's failing set.
- The measurement covers startup and the journeys in the three suites that
  load the committed `confine.sb` and wait for an `init` answer. It does not enumerate the file operations
  the loader performs, so it does not prove the form will serve a future
  provider that reads the root directory differently.
