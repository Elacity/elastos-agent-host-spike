# wallet-provider confinement

`confine.sb` is the one source for the wallet-provider sandbox profile (P10).
The profile starts with `(version 1)` then `(deny default)`. Every operation
that no rule grants fails closed with a reason (P11).

## Profile parameters

The Runtime passes resolved paths with `sandbox-exec -D`:

- `PROVIDER_EXECUTABLE` is the signed provider binary that the Runtime starts.
- `WALLET_STORAGE_ROOT` is `base_path/ElastOS/SystemServices/Wallet`.
- `WALLET_STORAGE_PARENT` is its parent, `base_path/ElastOS/SystemServices`.

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
| `(allow file-read* (literal WALLET_STORAGE_PARENT))` | Inspect and synchronize the existing parent during wallet directory creation. |
| `(allow file-read* file-write* (subpath WALLET_STORAGE_ROOT))` | One grant owns all account, key, challenge and approval state under the wallet directory. |

The remaining filesystem and process operations stay under the default denial.

## No network path

Wallet-provider reads line-delimited JSON from stdin and writes one JSON
response per line to stdout. It opens no listener and no socket. The profile
denies every network operation by default. `tests/confine.rs` checks that the
profile keeps no network allow rule, so a later change cannot add one without
a failing test.

## The Runtime half

The Runtime owns the profile — it loads `confine.sb` only from the signed
provider bundle, checks its hash, refuses any profile with `(allow default)` or
a network allow, and fails closed with a reason; the provider proposes, the
Runtime checks (P4, P11). The bridge integration loads this
bundle file and binds the parameters above when it starts the provider. This
document specifies that integration; the implementation stays with Runtime.

The DID reference is in `../did-provider/confine.sb`,
`../did-provider/tests/confine.rs`, and `../did-provider/CONFINEMENT.md`.
Both providers use one profile file, literal startup access, one state subtree
grant, and a real stdin/stdout process test.

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

The tests skip with a printed reason when `/usr/bin/sandbox-exec` is absent.

Falsifier procedure (run against a temporary edit, then restore the profile):

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
