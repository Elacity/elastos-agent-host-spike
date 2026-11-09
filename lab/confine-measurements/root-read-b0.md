# B0: one macOS root-read baseline for did, wallet and model

Measurement only. This record changes no provider profile and no Runtime code.
Base: `ea80c9ef` on `claude/confine-b0-rootread`. Host: macOS 26.5.2, arm64,
Rust 1.91.0, `/usr/bin/sandbox-exec` present.

The evidence is one receipt,
`~/Sparks/office/evidence/confine-b0-fix/receipt-6676d467.log`, which pins head
`6676d467` and tree `d87a2130` (receipt line 3). Its sha256, recomputed with
`shasum -a 256`, is
`e49a33b6e1d1d30eedc3734b2b063a78b49dfa15675ffc417dbfed492917c608`. The sibling
`receipt-6676d467.sha256` holds two lines because
`~/Sparks/office/receipt-local.sh:32` appends the digest with `tee -a` while
the log itself is overwritten; its second line is current and matches the
recompute, and its first line (`1851b828...`) is an earlier write of the same
path. The log prints the head, tree, toolchain and every command
with its full output and exit.

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
attributes), then no rule. The measured candidates are those four rungs.

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
sets. After the receipt's head the test also exits 7 unless the plant exits 143, so a
plant that finishes and restores on the normal path no longer passes; the
receipt's run meets that check but predates it. No line separates the SIGTERM
line from the exit line (200-201), so the receipt does not show whether the
plant's child-kill branch ran. The remove-restore falsifier fails at its `cmp`
with `falsifier interrupt exit=5` (2223-2227).

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

The six wallet `file-read-data` failures are profile-text checks. They compare a
generated profile or a document with the committed profile, so the substituted
line fails them by construction:

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
- The did suite holds no generated-profile start (passing tests 342-395).

The other five model `generated_profile_*` tests fail in those runs at their
allow-line comparison with the committed file, before any start (none
1984-2024). `byte_different_file_at_bound_path_starts` passes in every model run
(1548, 1737, 1997) because it accepts any exit but 65 and 71; its printed
outcome is signal 6 under metadata and none (1729, 1989).

## Conclusion

With the root line deleted from the committed `confine.sb`:

| Provider | Fails (list) | Passes that start a provider and need an answer |
|---|---|---|
| did | 8 committed-profile starts (400-407) | none (342-395) |
| wallet | 15 committed-profile starts, 6 text checks (1502-1522) | `standin_c0` (1430), `standin_start_runs_...` (1433) |
| model | 10 committed-profile starts, 5 generated-profile oracle checks, 3 text checks (2195-2212) the three model starts above (1990, 2010, 2187) |

The narrower conclusion: for starts that load the committed `confine.sb`,
`(allow file-read-data (literal "/"))` is the narrowest measured form that
serves did, wallet and model, and removing the line fails those starts at
`init`, so on those starts the form is needed. The generated-profile starts
never ran under a candidate; they show the fixture row works and nothing about
narrowing or deleting it. Unmeasured: did and wallet starts from a generated
profile whose root row is `file-read-data`, and any generated-profile start
without a root-read row.

On the committed-profile starts, the did and wallet `file-read*` form is broader
than they need, and the metadata rung fails them for all three providers, which
agrees with the model document's sentence.

Proposal for the confinement crate: one platform-baseline row,
`startup-root-directory`, holding `(allow file-read-data (literal "/"))`, and
all three providers render that row. The Runtime keys the rule to the baseline
id, not to a provider name. B0 makes no such change. For did and wallet, B0
measured that row's text only inside the committed `confine.sb`; the row as the
generator renders it is not measured for them.

## Limits

- Measured on arm64 macOS 26.5.2 only; no x86-64 macOS host was available.
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
  load the committed `confine.sb`. It does not enumerate the file operations
  the loader performs, so it does not prove the form will serve a future
  provider that reads the root directory differently.
