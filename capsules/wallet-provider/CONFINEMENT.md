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

These profiles are enforced on macOS through `/usr/bin/sandbox-exec`. On macOS
a confinement test that cannot run because `/usr/bin/sandbox-exec` is missing
fails the gate; it never passes by skipping. On Linux the providers are not
confined yet; there, and on any host OS other than macOS, the `sandbox-exec`
integration tests print a skip reason and do not run. The rule for
provider-status documents is that a provider is marked "confined" only for a
host OS where a test proves its profile, so no status document records
`did-provider` or `wallet-provider` as confined on Linux until that test
exists (P10, P11). The status change lands when the Runtime side does.

The Linux design for the same one contract is `CONFINEMENT-LINUX.md`: it is a
design whose Linux tests do not exist yet, and it claims no current behaviour.

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
`SURVIVED`.
