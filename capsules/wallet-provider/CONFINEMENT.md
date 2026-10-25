# wallet-provider confinement

`confine.sb` is the one source for the wallet-provider sandbox profile (P10).
The profile starts with `(version 1)` then `(deny default)`. Every operation
that no rule grants fails closed with a reason (P11).

## Profile parameters

The Runtime passes two resolved paths with `sandbox-exec -D`:

- `PROVIDER_EXECUTABLE` is the signed provider binary that the Runtime starts.
- `WALLET_STORAGE_ROOT` is the wallet data root that the Runtime also sends to
  `Init` as `base_path`.

The provider derives `ElastOS/SystemServices/Wallet` under that root. Seatbelt
matches resolved paths, so the Runtime passes the canonical path of each
parameter.

## What the profile allows

| Rule | Why the provider needs it |
| --- | --- |
| `(allow process-exec (literal PROVIDER_EXECUTABLE))` | Start only the binary the Runtime named. |
| `(allow file-read* (literal PROVIDER_EXECUTABLE))` | Read that one program image. |
| `(allow file-read* (literal "/"))` | The kernel resolves every absolute path through the root directory. |
| `(allow file-read* (subpath "/usr/lib") ... "/System/Library" ... "/Library/Apple")` | dyld reads the system shared cache and system libraries. |
| `(allow sysctl-read)` | The loader and the allocator read kernel facts at startup. |
| `(allow file-read* (literal "/dev/urandom"))` | Startup entropy for the storage key. |
| `(allow file-read* (subpath WALLET_STORAGE_ROOT))` | Read account, key, challenge and approval state under the wallet root. |
| `(allow file-write* (subpath WALLET_STORAGE_ROOT))` | Write that state under the wallet root. |

No rule grants network, devices other than `/dev/urandom`, other programs, or
any file outside the two paths above.

## No network path

Wallet-provider reads line-delimited JSON from stdin and writes one JSON
response per line to stdout. It opens no listener and no socket. The profile
denies every network operation by default. `tests/confine.rs` checks that the
profile keeps no network allow rule, so a later change cannot add one without
a failing test.

## The Runtime half

The Runtime owns the profile. It loads `confine.sb` only from the signed
provider bundle, checks its hash, refuses any profile with `(allow default)` or
a network allow, and fails closed with a reason. The provider proposes its
profile; the Runtime checks it (P4, P11). This document describes the Runtime
half only; this task changes nothing under `elastos/`.

## Tests

`tests/confine.rs` builds the provider and runs it under this profile:

- `confined_provider_serves_wallet_operations_under_its_root` drives `Init`,
  `status`, `CreateManagedAccount` and `ListAccounts` over the real protocol and
  checks that the account and storage key land under the wallet root.
- `confined_outside_write_is_denied` sends `Init` for a root outside the
  parameter. The profile denies the write, the provider answers
  `storage_error`, and the next `status` request still succeeds.
- `confined_outside_read_is_denied` plants a complete key file outside the
  parameter. The profile denies the read, so the provider refuses that root.
- `profile_denies_network` checks that the profile has `(deny default)` and no
  network allow rule.

The tests skip with a printed reason when `/usr/bin/sandbox-exec` is absent.

Falsifiers, each run once and observed:

- `(allow default)` in place of `(deny default)` makes the outside `Init`
  succeed, so the outside tests fail.
- A sibling-file read allowance makes the outside read test fail.
- `(allow network*)` makes `profile_denies_network` fail.
- Removing the storage-root write rule makes `Init` fail inside the root, so
  the operation test fails.
