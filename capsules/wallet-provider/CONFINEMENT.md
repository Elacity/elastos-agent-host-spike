# wallet-provider confinement

`confine.sb` is the one oracle for the wallet-provider sandbox profile (one
file, P10): the profile the Runtime generates for this provider must match it.
The oracle starts with `(version 1)` then `(deny default)`. Every operation
that no rule grants fails closed with a reason (P11).

## Profile parameters

The generated profile binds these three parameters, and the tests pass them
with `sandbox-exec -D`:

- `PROVIDER_EXECUTABLE` is the provider binary the launch starts.
- `STORAGE_ROOT` is `base_path/ElastOS/SystemServices/Wallet`.
- `STORAGE_PARENT` is its parent, `base_path/ElastOS/SystemServices`.

`../did-provider/` presents the same contract as this oracle: one profile file,
the same three parameter tokens, literal startup access, one state subtree
grant, and a real stdin/stdout process test.

The tests create the shared ancestors before launch, derive both storage
parameters from the same canonical `Init.base_path` and pass the original base
to `Init` (`start_with_profile`); the Runtime half of the bridge change does
the same and is not built. The provider creates the final
`Wallet` directory. Seatbelt grants recursive state access to that wallet
directory alone. Literal read access to its existing parent lets the provider
inspect and synchronize the directory while it creates Wallet. The parent
receives no recursive grant.

## What the profile allows

| Rule | Why the provider needs it |
| --- | --- |
| `(allow process-exec (literal PROVIDER_EXECUTABLE))` | Start only the binary the launch named. |
| `(allow file-read* (literal "/"))` | The kernel resolves every absolute path through the root directory. |
| `(allow sysctl-read)` | The loader and the allocator read kernel facts at startup. |
| `(allow file-read* (literal STORAGE_PARENT))` | Inspect and synchronize the existing parent during wallet directory creation. |
| `(allow file-read* file-write* (subpath STORAGE_ROOT))` | One grant owns all account, key, challenge and approval state under the wallet directory. |

The remaining filesystem and process operations stay under the default denial.

## No network path

Wallet-provider reads line-delimited JSON from stdin and writes one JSON
response per line to stdout. It opens no listener and no socket. The profile
starts from `(deny default)` and adds `(deny network*)`, so every network
operation is refused. `tests/confine.rs` checks that the profile keeps no
network allow rule, so a later change cannot add one without a failing test.

## The Runtime bridge change

The Runtime generates the provider's profile from the provider's approved
declared rights; it does not load a profile that the provider supplies.
`confine.sb` in this folder is the test oracle: the profile the Runtime
generates for this provider must match it, with the same three parameters bound
to the same paths. The test that compares them is the Runtime's half, outside
this lane. The one contract check, `check_profile_contract`, holds every oracle
to these terms, and the generated profile meets them too: `(version 1)` first,
`(deny default)` second, an explicit `(deny network*)`, no `(allow default)`,
no network allow, only the `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and
`STORAGE_PARENT` parameter tokens, and the three shared rules verbatim.
If the profile cannot be applied, because the file is missing, does not parse
or names a parameter the launch does not bind, `sandbox-exec` exits before the
provider starts and gives its reason on standard error; the Runtime then
refuses the start with that reason and never starts the provider another way
(P11).

One generator covers `did-provider`, `wallet-provider` and `model-provider`,
parameterized by the provider's approved declared rights and its storage root,
so the Runtime has one path for a provider's profile (P10). That bridge change
is not built: the Runtime half that generates and enforces the profile is
future work in `elastos/`, outside this lane. The tests launch this provider
under its oracle with `/usr/bin/sandbox-exec -f confine.sb`, and
`startup_is_refused_when_the_profile_cannot_be_applied` proves that a start is
refused when the profile cannot be applied.

## The model provider's inline profile

`elastos/crates/elastos-runtime/src/provider/bridge.rs` builds a third,
pre-existing convention for the model provider. Four facts differ from the
contract above: it starts `(allow default)` instead of `(deny default)`; it
interpolates storage paths into `(regex ...)` rules rather than binding a
`(param ...)` token; it grants an explicit
`(allow network-outbound (literal ...))` socket; and it passes its policy
inline with `sandbox-exec -p` rather than `-f confine.sb`. It does not share
the file-profile contract and this document does not claim it does. Aligning
the model provider is future Runtime work in `elastos/`, outside this lane.
The model provider's own file profile, `../model-provider/confine.sb`,
presents this contract as an oracle, and the shared test requires it; the
generated profile for the model provider must match it too.

## Host-OS status

The confinement tests exercise these oracles on macOS through
`/usr/bin/sandbox-exec`. On macOS a test that cannot run because that tool is
missing fails the gate; it never passes by skipping. On any host OS other than
macOS the `sandbox-exec` integration tests print a skip reason and do not run
when that tool is absent. The gate test
`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` checks that rule: a
missing tool on `macos` is an error that names the OS and the path, a missing
one on `linux` is a skip, and a present one on `macos` runs the test.
The one caller, `sandbox_available`, fails the test on that error;
`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` calls it
with `macos` and a missing path and expects the failure.
This contract has no Linux enforcement or tests yet. A provider-status claim
needs host-specific test evidence and the Runtime acceptance step, so no status
document records `did-provider` or `wallet-provider` as confined on Linux until
that test exists (P10, P11). The status change lands when the Runtime side
does.

Future Linux enforcement tests for this lab contract are designed in
`CONFINEMENT-LINUX.md`: it is the one Linux mapping, its tests do not exist
yet, and it claims no current behaviour. The existing source-only check
`both_file_profiles_bind_one_storage_parameter_contract` reads the three
oracles and supplies contract evidence, not Linux execution evidence.

## Tests

`tests/confine.rs` builds the provider and runs it under this profile:

- `confined_provider_serves_wallet_operations_under_its_root` drives `Init`,
  `status`, `CreateManagedAccount` and `ListAccounts` over the real protocol and
  checks that the account and storage key land under the wallet root.
- `confined_outside_write_is_denied` sends `Init` for an unrelated base,
  `base_path/sibling`, and a sibling service under `ElastOS/SystemServices`.
  The provider answers `storage_error`, answers the next `status`, and can
  reinitialize its allowed root. Each attempted wallet directory stays absent.
- `confined_outside_read_is_denied` plants a complete key in a sibling wallet.
  It adds literal fixture directory reads and file metadata reads to a copy
  of the single profile source. These grants let `Init` reach the key open;
  the test asserts that this open is the refused operation. The fixture adds
  neither file-content reads nor writes outside the wallet grant.
- `profile_denies_network` checks that the profile has `(deny default)` and no
  network allow or `(allow default)` rule, including one appended after denial.
- `startup_denial_reports_its_reason` covers the failure path. It starts the
  provider under a fixture profile that holds `(version 1)` and `(deny default)`,
  so `sandbox-exec` cannot exec it, waits for that child to exit, and sends
  `init`. The one harness failure names the request, the child's exit status and
  `sandbox-exec`'s own `execvp()` denial of the provider binary, `Operation not
  permitted`, from standard error, so another denial cannot stand in for the exec
  denial. A second fixture child reads one request and exits without answering,
  so the response-stream branch reports the same three facts. An answer that is
  not JSON fails with its own message, which names the request, the parse error
  and the answer, and does not say the provider did not answer;
  `invalid_json_answer_names_the_request_and_the_parse_error` checks it. The
  harness drains standard error on its own thread while the child runs, so a
  child that fills the pipe still reaches its own exit.
  `stderr_is_drained_before_wait` writes 128 KiB to standard error and expects
  every byte plus the child's own exit status; it fails when the drainer starts
  only after the wait, because the child then never exits within the deadline.
  The startup case skips with its printed reason when `sandbox-exec` is absent on
  a host OS other than macOS.
- `startup_is_refused_when_the_profile_cannot_be_applied` starts the provider
  under a profile that cannot be applied: a path that does not exist, a copy of
  `confine.sb` with its last `)` removed, and the real profile with every
  parameter bound except `STORAGE_ROOT`. `sandbox-exec` exits with a status
  other than 0 in each case, no wallet directory is created, and the harness
  failure names the request, the exit status and `sandbox-exec`'s own line on
  standard error. That failure also shows that `sandbox-exec` refused the
  profile before any exec.
- `both_file_profiles_bind_one_storage_parameter_contract` lives in
  `../wallet-provider/tests/confine.rs`. One check function holds the
  contract: `(version 1)` first, `(deny default)` second, an explicit
  `(deny network*)`, no network allow, the same `PROVIDER_EXECUTABLE` /
  `STORAGE_ROOT` / `STORAGE_PARENT` parameter tokens, no `(allow default)`
  rule, and the three shared rules verbatim. One list function runs that check over
  `capsules/did-provider/confine.sb`, `capsules/wallet-provider/confine.sb`
  and `capsules/model-provider/confine.sb`. All three profiles are required,
  and a missing or unreadable profile fails the check with a reason that names
  its path. The test runs on every platform because it reads files and starts
  no process.
- `every_did_and_wallet_allow_rule_has_a_registered_removal` runs one removal
  check over the did and wallet profiles and over both of their committed
  falsifier lists. A top-level allow form counts as removed only when an entry
  expects a catch, names that profile's `confine.sb` by the runner's path rule,
  holds the form in its edit `old` and not in its `new`. A form that no entry
  removes fails the test by name, with the instruction to register a removal
  falsifier or delete the rule. The model profile is not read here; its
  allow-rule removals live in `../model-provider/confine-falsifiers.json` under
  that lane's own list. The test reads files and starts no process.
- `allow_rule_removal_check_reports_an_unremoved_rule` builds a fixture
  profile and fixture entries in the test. An entry whose `new` still holds the
  form, whose `expect` is not `caught`, whose edit names the other provider's
  `confine.sb`, or whose `old` does not hold the form removes nothing, so only
  the process-exec rule comes back; one complete entry for each form leaves
  nothing. The test reads no file.
- `allow_rule_removal_check_rejects_bad_inputs` checks the one source reader.
  A missing profile, a profile that does not parse, a missing list, a list that
  is not JSON and a document without a `falsifiers` list each fail with a
  reason that names that path, and there is no skip path. The fixtures are
  built in the test and no process starts.
- `file_profile_contract_rejects_a_profile_without_deny_network` builds a
  minimal profile from the contract's own head forms and shared rules inside
  the test. The check accepts it, then refuses the same profile without
  `(deny network*)` with a reason that names that rule. The test reads no
  file.
- `file_profile_contract_rejects_a_network_allow` builds the same passing
  fixture and appends `(allow network*)`, then
  `(allow network-outbound (remote ip "localhost:*"))`. The check refuses each
  profile with a reason that names `fixture-provider` and the refused form.
  The test reads no file.
- `file_profile_contract_rejects_an_allow_default` builds the same passing
  fixture and appends `(allow default)` after the default denial. The check
  refuses it with a reason that names `fixture-provider` and
  `must reject (allow default)`. The test reads no file.
- `file_profile_contract_rejects_a_non_canonical_token` builds the same
  passing fixture and appends
  `(allow file-read* (literal (param "READ_FIXTURE_KEY")))`. The check refuses
  it with a reason that names `fixture-provider` and
  `non-canonical parameter token READ_FIXTURE_KEY`. The test reads no file.
- `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  builds the passing fixture and appends
  `(deny file-read* (literal "/x;")) (allow default)` and
  `(deny file-read* (literal "/))"))`. The check refuses it with a reason that
  names `fixture-provider` and `must reject (allow default)`, because the
  parser reads the `;` and the parentheses inside those strings as text. The
  same test checks that the two lines hold three forms with `(allow default)`
  second, that a `;` outside a string comments out the rest of its line, that
  an escaped quote and an escaped backslash stay inside their string, that
  whitespace inside a string is kept and outside it collapses, and that a form
  after a comment's newline still loads. The test reads no file and starts no
  process.
- `a_comment_inside_a_form_keeps_its_tokens_apart` reads a form whose tokens
  a comment splits and expects both tokens back: `(allow;x`, a newline, then
  `default)` gives `(allow default)`, and the network form gives
  `(allow network*)`. The one check refuses the passing fixture with either
  form appended, with the exact `must reject (allow default)` and
  `network allow is refused` reasons. The test reads no file and starts no
  process.
- `a_space_after_the_opening_parenthesis_still_names_its_rule` reads a form
  whose head a space or a comment separates from its first symbol:
  `( allow default)` and `(;x`, a newline, then `allow default)` both give
  `(allow default)`, and the network forms give `(allow network*)`. The one
  check refuses the passing fixture with each of those appended, with the
  exact `must reject (allow default)` and `network allow is refused` reasons.
  The test reads no file and starts no process.
- `a_bare_top_level_value_is_its_own_form` reads a bare value outside every
  form as its own form: `1`, a newline, then `(allow default)` gives `1` and
  `(allow default)`, and so do `1(allow default)` and `"x" (allow default)`; a
  bare value at the end of the profile is a form too. The one check refuses
  the passing fixture with each of those appended, and with
  `1 (allow network*)`, with the exact `must reject (allow default)` and
  `network allow is refused` reasons. The test reads no file and starts no
  process.
- `the_bare_value_fixture_loads_under_sandbox_exec` writes
  `(version 1)(deny default) 1 (allow default)` to a temporary file and runs
  `/usr/bin/sandbox-exec -f <file> /usr/bin/true`, which exits 0. Under
  `(deny default)` alone that program cannot start, so the exit shows that
  `sandbox-exec` reads the `1` as its own form and applies the
  `(allow default)` after it. It checks that test's premise, not a rule, and
  carries no falsifier entry.
- `the_string_fixture_loads_under_sandbox_exec` writes `(version 1)`,
  `(deny default)` and those two lines to a temporary file and runs
  `/usr/bin/sandbox-exec -f <file> /usr/bin/true`, which exits 0. Under
  `(deny default)` alone that program cannot start, so the exit shows that
  `sandbox-exec` reads the `;` and the parentheses as text and applies the
  `(allow default)`. It checks the fixture's premise, not a rule, and carries
  no falsifier entry.
- `profile_forms_rejects_unclosed_string` reads an unclosed string and expects
  the existing "the profile must not end early" reason with `unclosed string`
  in it. The test reads no file and starts no process.
- `profile_forms_rejects_unclosed_form` reads an unclosed form and expects the
  same reason with `unclosed form` in it, and a closed form then loads. The
  test reads no file and starts no process.
- `file_profile_contract_checks_the_model_profile_when_present` runs the same
  list function over a temporary `capsules/` directory that holds the passing
  fixture for all three required profiles. It checks exactly did-provider,
  wallet-provider and model-provider, in that order; a model profile without
  `(deny network*)` fails, naming the model provider and that rule; a removed
  model profile fails, naming model-provider and its path; a model profile
  that is a directory fails as a read error naming its path; and a missing did
  profile fails, naming did-provider.

When a request goes unanswered, the harness failure names the request, the
child's exit status or the deadline that ended the wait, and all the child
wrote to standard error.

The tests skip with a printed reason when `/usr/bin/sandbox-exec` is absent on
a host OS other than macOS.

`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` checks the gate
itself without starting a process: a missing `sandbox-exec` on `macos` is an
error that names the OS and the path, a missing one on `linux` is a skip, and
a present one on `macos` runs the test. It runs on every supported build
target.

`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` checks the
one caller without starting a process: with `macos` and a missing
`sandbox-exec` it fails the test with the gate's reason, and with `macos` and
a present one it returns `true`. It runs on every supported build target.

Falsifier procedure (run against a temporary edit, then restore the profile):

- Rename `STORAGE_ROOT` to `WALLET_STORAGE_ROOT` in this profile (WP22):
  `both_file_profiles_bind_one_storage_parameter_contract` fails on the
  non-canonical token.
- `(allow default)` in place of `(deny default)` (WP04) makes the outside
  `Init` succeed, so the outside tests fail.
- Append `(allow file-read* (literal (param "READ_FIXTURE_KEY")))` (WP24):
  `confined_outside_read_is_denied` fails because reading the planted key
  lets `Init` succeed, and
  `both_file_profiles_bind_one_storage_parameter_contract` fails because the
  token is non-canonical.
- `(allow network*)` (WP05) makes `profile_denies_network` and
  `both_file_profiles_bind_one_storage_parameter_contract` fail.
- Append `(allow default)` after `(deny network*)` (WP20):
  `profile_denies_network` fails because `is_default_allow` matches the
  appended rule, `both_file_profiles_bind_one_storage_parameter_contract` fails
  because the one check refuses the rule, and
  `confined_outside_read_is_denied` and `confined_outside_write_is_denied` fail
  because the outside reads and writes then succeed.
- Removing the storage-root write rule (WP18) makes `Init` fail inside the
  root, so the operations and outside-write tests fail, and the shared contract
  check fails.
- Remove `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` (WP14):
  the operations and outside tests fail because the provider cannot start, and
  the shared contract check fails because the rule is pinned.
- Remove `(allow file-read* (literal "/"))` (WP15): the operations and outside
  tests fail because the provider cannot resolve its program path.
- Remove `(allow sysctl-read)` (WP16): the operations and outside tests fail
  because the loader cannot read the kernel facts it needs.
- Remove `(allow file-read* (literal (param "STORAGE_PARENT")))` (WP17): `Init`
  cannot inspect the parent, so the operations and outside-write tests fail,
  and the shared contract check fails.
- Start the provider directly when its profile file is missing (WP28):
  `startup_is_refused_when_the_profile_cannot_be_applied` fails on case (a) at
  the bounded wait, because the provider is still running when the deadline
  kills it.
- Drop the child's standard error from the one harness failure (WP29):
  `startup_is_refused_when_the_profile_cannot_be_applied` fails because every
  failure lacks `sandbox-exec`'s line.
- Return `false` from the error arm of `sandbox_available` instead of failing
  the test (WP30): `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing`
  fails because a missing `sandbox-exec` on `macos` returns instead of failing.
- Cut each line at its first `;` and count parentheses in every token again
  (WP31): `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  fails because the hidden `(allow default)` then passes the check, and
  `profile_forms_rejects_unclosed_string` fails because the cut reads no
  string to refuse.
- Let an escaped character end its string (WP32):
  `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  fails because the escaped quote closes the string and the profile ends
  early.
- Drop whitespace that sits inside a string (WP33): the same test fails
  because the spaced in-string form loses its two spaces.
- Keep whitespace outside strings instead of collapsing it (WP34): the same
  test fails because the passing fixture no longer parses into the contract's
  forms.
- Run a comment to the end of the profile instead of its line (WP35): the
  same test fails because the form after the comment's newline is lost.
- Drop the unclosed-string refusal (WP36):
  `profile_forms_rejects_unclosed_string` fails because the profile then ends
  as an unclosed form.
- Drop the unclosed-form refusal (WP37): `profile_forms_rejects_unclosed_form`
  fails because the incomplete profile returns no refusal.
- Drop the newline that ends a comment (WP38):
  `a_comment_inside_a_form_keeps_its_tokens_apart` fails because
  `(allow;x\ndefault)` reads as `(allowdefault)` and passes the check.
- Drop the split outside every form (WP39):
  `a_bare_top_level_value_is_its_own_form` fails because `1`, a newline, then
  `(allow default)` reads as the one form `1 (allow default)` and passes the
  check.
- Add the separator space after an opening parenthesis (WP40):
  `a_space_after_the_opening_parenthesis_still_names_its_rule` fails because
  `( allow default)` reads as its own form and passes the check.
- Start the drainer only after `wait_for_exit` has returned (WP41):
  `stderr_is_drained_before_wait` fails on its exit assertion because the
  child blocks on a full pipe and never exits within the deadline.
- Use a fixed `Operation not permitted` instead of the child's standard error
  in `unanswered` (WP42): `startup_denial_reports_its_reason` fails on its
  `execvp()` assertion because the fixed text names no exec denial.
- Return the shared unanswered message from the invalid-JSON branch (WP43):
  `invalid_json_answer_names_the_request_and_the_parse_error` fails because the
  answer loses its parse error and says the provider did not answer.
- Append `(allow file-read* (literal "/etc"))` to the did profile (WP44):
  `every_did_and_wallet_allow_rule_has_a_registered_removal` fails because no
  entry removes that form.
- Drop the `expect`, profile-path, `old` or `new` condition from the removal
  check (WP45 to WP48):
  `allow_rule_removal_check_reports_an_unremoved_rule` fails because the
  bypassing entry then counts as a removal.
- Turn the unreadable-profile, unparsable-profile, unreadable-list, not-JSON or
  missing-list refusal into a skip (WP49 to WP53):
  `allow_rule_removal_check_rejects_bad_inputs` fails because the refusal does
  not come.

Task 016 removed these allow forms because no named confinement test needed
them on macOS 26.5.2 arm64:

- `(allow file-read* (literal (param "PROVIDER_EXECUTABLE")))` removed: no
  confinement test needed it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/usr/lib"))` removed: no confinement test needed
  it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/System/Library"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/Library/Apple"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.
- `(allow file-read* (literal "/dev/urandom"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.

A host that needs one of the removed grants receives a sandbox denial for the
affected access, so that operation fails closed with a reason. The grant comes
back only together with a named test that needs it.

Run `cargo test --locked --manifest-path capsules/wallet-provider/Cargo.toml`
from the repository root. The existing 102 unit tests remain part of this gate.

The one runner applies and restores each registered falsifier with
`python3 -I examples/agent-host/falsify.py --from capsules/wallet-provider/falsifiers.json`
from the repository root; the list's edit paths are relative to
`examples/agent-host`, and the sandbox entries need `/usr/bin/sandbox-exec`.

A run of the list is evidence only where the sandbox tests run: on macOS
without `/usr/bin/sandbox-exec` each sandbox test fails at the gate whatever
the edit, and the runner runs no unmutated baseline, so a `CAUGHT` there proves
nothing, while where the sandbox tests skip an entry that names one reads
`SURVIVED`. A call site that passes a fixed `"linux"` for the OS is not caught
by a run on a Mac where `/usr/bin/sandbox-exec` exists, because a present tool
runs the test before the OS is read, so that run is no evidence for the OS
argument.
