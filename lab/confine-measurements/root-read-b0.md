# B0: one macOS root-read baseline for did, wallet and model

Measurement only. This record changes no provider profile and no Runtime code.
Base: `ea80c9ef` on `claude/confine-b0-rootread`. Host: macOS 26.5.2, arm64,
Rust 1.91.0, `/usr/bin/sandbox-exec` present.

The evidence is one receipt at `~/Sparks/office/evidence/confine-b0/`. Its name
and log carry the head of the commit that adds this record; the log prints the
head, tree, toolchain and every command with its full output and exit.

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
deletes it, runs the provider's named macOS tests, restores the profile with
`cp -p`, and proves the restore with `cmp` and `git diff --quiet`.

Control runs the whole confine suite per provider with `--no-fail-fast` on the
unmodified tree: did 16 passed and 1 ignored, wallet 103 passed, model 39 passed.

The tool touches the restored profile after `cp -p`, because the wallet suite
embeds its profile with `include_str!`; an older mtime would keep the planted
copy inside the next test binary.

Each plant runs three named tests: the provider's operations journey and its
two outside-denial tests.

| Provider | Journey and denial tests | `file-read-data` | `file-read-metadata` | no root read |
|---|---|---|---|---|
| did | `confined_provider_serves_did_operations_under_its_root`, `outside_write_denied`, `outside_read_denied` | 3 passed | 3 failed | 3 failed |
| wallet | `confined_provider_serves_wallet_operations_under_its_root`, `confined_outside_write_is_denied`, `confined_outside_read_is_denied` | 3 passed | 3 failed | 3 failed |
| model | `model_provider_ops_under_profile`, `model_outside_write_denied`, `model_outside_read_denied` | 3 passed | 3 failed | 3 failed |

The model profile already holds `file-read-data`, so its `data` plant is the
control run of the same line and changes no byte.

Every failed test fails at its own start assertion, not at a skip or a parse
error:

- did and wallet, both narrower candidates:
  `provider did not answer request {... "op":"init"} (the response stream
  ended); child signal: 6 (SIGABRT)`.
- model, both narrower candidates:
  `the provider process exited before answering "init": signal: 6 (SIGABRT)`.

## Conclusion

`(allow file-read-data (literal "/"))` is the narrowest measured form that all
three macOS journeys pass. It is sufficient for did, wallet and model, and its
removal fails each provider, so the form is needed, not merely harmless.

The did and wallet `file-read*` form is broader than necessary. The metadata
rung is too narrow for every provider, which confirms the model document's
sentence by measurement.

Proposal for the confinement crate: one platform-baseline row,
`startup-root-directory`, holding `(allow file-read-data (literal "/"))`, and
all three providers render that row. The Runtime keys the rule to the baseline
id, not to a provider name. B0 makes no such change.

## Limits

- Measured on arm64 macOS 26.5.2 only; no x86-64 macOS host was available.
- Each plant ran the three named tests above. The rest of each suite pins the
  committed profile text, for example
  `generated_did_and_wallet_profiles_match_their_committed_oracles` and
  `linux_contract_table_covers_every_committed_allow_form`, and fails by
  construction when the profile form changes. The control suites ran those
  tests on the unmodified tree, and they passed.
- The measurement shows startup and the named journeys. It does not enumerate
  every file operation the loader performs, so it does not prove the form will
  serve a future provider that reads the root directory differently.
