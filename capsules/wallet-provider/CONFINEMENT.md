# wallet-provider confinement

`confine.sb` is the one source for the wallet-provider sandbox profile (P10).
The profile starts with `(version 1)` then `(deny default)`. Every operation
that no rule grants fails closed with a reason (P11).

## Profile parameters

The Runtime passes resolved paths with `sandbox-exec -D`:

- `PROVIDER_EXECUTABLE` is the signed provider binary that the Runtime starts.
- `STORAGE_ROOT` is `base_path/ElastOS/SystemServices/Wallet`.
- `STORAGE_PARENT` is its parent, `base_path/ElastOS/SystemServices`.

The Runtime creates the shared ancestors before launch, derives both storage
parameters from the same canonical `Init.base_path`, and passes the original
base to `Init`. The provider creates the final `Wallet` directory. Seatbelt
grants recursive state access to that wallet directory alone. Literal read
access to its existing parent lets the provider inspect and synchronize the
directory while it creates Wallet. The parent receives no recursive grant.

## What the profile allows

| Rule | Why the provider needs it |
| --- | --- |
| `(allow process-exec (literal PROVIDER_EXECUTABLE))` | Start only the binary the Runtime named. |
| `(allow file-read* (literal PROVIDER_EXECUTABLE))` | Read that one program image. |
| `(allow file-read* (literal "/"))` | The kernel resolves every absolute path through the root directory. |
| `(allow file-read* (subpath "/usr/lib") ... "/System/Library" ... "/Library/Apple")` | dyld reads the system shared cache and system libraries. |
| `(allow sysctl-read)` | The loader and the allocator read kernel facts at startup. |
| `(allow file-read* (literal "/dev/urandom"))` | Startup entropy for the storage key. |
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

The Runtime bridge starts this provider under `/usr/bin/sandbox-exec -f
confine.sb` and binds the storage root to the `STORAGE_ROOT` parameter and its
parent to `STORAGE_PARENT`; `PROVIDER_EXECUTABLE` names the binary. The same
bridge work, parameterized by the profile path and the storage root, starts
`did-provider` and `wallet-provider`, so the Runtime has one path for starting
a provider under its profile (P10). The Runtime loads `confine.sb` only from
the signed provider bundle, checks its hash, refuses any profile with
`(allow default)` or a network allow, and fails closed with a reason; the
provider proposes, the Runtime checks (P4, P11).

`../did-provider/` presents the same contract: one profile file, the same three
parameter tokens, literal startup access, one state subtree grant, and a real
stdin/stdout process test.

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

## Host-OS status

These profiles are enforced on macOS through `/usr/bin/sandbox-exec`. On Linux
the providers are not confined yet; the `sandbox-exec` integration tests print
a skip reason and do not run. The rule for provider-status documents is that a
provider is marked "confined" only for a host OS where a test proves its
profile, so no status document records `did-provider` or `wallet-provider` as
confined on Linux until that test exists (P10, P11). The status change lands
when the Runtime side does.

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
- `both_file_profiles_bind_one_storage_parameter_contract` lives in
  `../wallet-provider/tests/confine.rs`. One check function holds the
  contract: `(version 1)` first, `(deny default)` second, an explicit
  `(deny network*)`, the same `PROVIDER_EXECUTABLE` / `STORAGE_ROOT` /
  `STORAGE_PARENT` parameter tokens, no `(allow default)` rule, and the three
  shared rules verbatim. One list function runs that check over
  `capsules/did-provider/confine.sb`, `capsules/wallet-provider/confine.sb`
  and `capsules/model-provider/confine.sb`: the did and wallet profiles are
  required, and the model profile is checked whenever that file exists and
  skipped with a printed reason while it is absent. The test runs on every
  platform because it reads files and starts no process. It does not claim
  that the model provider meets the contract today.
- `file_profile_contract_rejects_a_profile_without_deny_network` builds a
  minimal profile from the contract's own head forms and shared rules inside
  the test. The check accepts it, then refuses the same profile without
  `(deny network*)` with a reason that names that rule. The test reads no
  file.
- `file_profile_contract_checks_the_model_profile_when_present` runs the same
  list function over a temporary `capsules/` directory. With no model
  profile it checks exactly the two required profiles; a model profile
  without `(deny network*)` fails, naming the model provider and that rule; a
  passing one is checked; a model profile that is a directory fails as a read
  error naming its path; and a missing did profile fails, naming did-provider.
- `file_profile_contract_reports_absent_model` runs the list function in a
  child harness over a `capsules/` directory without a model profile and
  requires the printed skip reason to name the model profile and the absent
  file.

The tests skip with a printed reason when `/usr/bin/sandbox-exec` is absent.

Falsifier procedure (run against a temporary edit, then restore the profile):

- Rename `STORAGE_ROOT` to `WALLET_STORAGE_ROOT` in this profile:
  `both_file_profiles_bind_one_storage_parameter_contract` fails on the
  non-canonical token.
- `(allow default)` in place of `(deny default)` makes the outside `Init`
  succeed, so the outside tests fail.
- Append `(allow file-read* (literal (param "READ_FIXTURE_KEY")))` and run
  `confined_outside_read_is_denied`: reading the planted key makes `Init`
  succeed and the test fail.
- `(allow network*)` makes `profile_denies_network` fail.
- Appending `(allow default)` also makes `profile_denies_network` fail.
- Removing the storage-root write rule makes `Init` fail inside the root, so
  the operation test fails.

Run `cargo test --locked --manifest-path capsules/wallet-provider/Cargo.toml`
from the repository root. The existing 102 unit tests remain part of this gate.
