# B0: one macOS root-read baseline for did, wallet and model

Measurement only. This record changes no provider profile and no Runtime code.
Base: `ea80c9ef` on `claude/confine-b0-rootread`. Host: macOS 26.5.2, arm64,
Rust 1.91.0, `/usr/bin/sandbox-exec` present.

The evidence is one receipt at `~/Sparks/office/evidence/confine-b0-fix/`,
named `receipt-<head8>.log` for the head it pins, with its sha256 in the
sibling `.sha256` file. The log prints the head, tree, toolchain and every
command with its full output and exit.

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
unmodified tree: did 16 passed and 1 ignored, wallet 103 passed, model 39 passed.

The tool touches the restored profile after `cp -p`, because the wallet suite
embeds its profile with `include_str!`; an older mtime would keep the planted
copy inside the next test binary. The receipt also runs
`root-read-b0-interrupt-test.sh`, which plants the wallet profile, sends SIGTERM
while the suite is running, and proves the profile and the tree are restored.

Every test in each suite therefore has a recorded result under each candidate
form:

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

Every test that starts a working provider under the committed profile passes
under `file-read-data` for all three providers. In the narrower runs those
starts fail at their start assertion, and the profile-text checks fail as well;
the receipt lists each failing test and its panic:

- did and wallet launch failures:
  `provider did not answer request {... "op":"init"} (the response stream
  ended); child signal: 6 (SIGABRT)`.
- model launch failures:
  `the provider process exited before answering "init": signal: 6 (SIGABRT)`.

## Conclusion

`(allow file-read-data (literal "/"))` is the narrowest measured form that every
working start in the three macOS suites passes. It is sufficient for did, wallet
and model, and its removal fails every measured working-start journey at
startup for each provider, so the form is needed, not merely harmless.

The did and wallet `file-read*` form is broader than necessary. The metadata
rung is too narrow for every provider, which confirms the model document's
sentence by measurement.

Proposal for the confinement crate: one platform-baseline row,
`startup-root-directory`, holding `(allow file-read-data (literal "/"))`, and
all three providers render that row. The Runtime keys the rule to the baseline
id, not to a provider name. B0 makes no such change.

## Limits

- Measured on arm64 macOS 26.5.2 only; no x86-64 macOS host was available.
- Each plant ran the whole suite, so every test in those suites has a result in
  the receipt; no journey in them is unmeasured. The profile-text checks, such
  as the six named above, fail when the plant changes the committed text, and
  the receipt records the exact failing set for each candidate form. The
  control suites ran the same tests on the unmodified tree, and they passed.
- The measurement shows startup and every journey in the three suites. It does
  not enumerate every file operation the loader performs, so it does not prove
  the form will serve a future provider that reads the root directory
  differently.
