# did-provider confinement

`confine.sb` is the macOS Seatbelt profile for the native `did-provider`
binary. The Runtime starts the provider as:

```sh
/usr/bin/sandbox-exec -f confine.sb \
  -D STORAGE_ROOT=<canonical absolute storage root> \
  -D PROVIDER_BINARY=<installed did-provider binary> \
  <installed did-provider binary>
```

`STORAGE_ROOT` is the same `base_path` value the Runtime already sends in
`Init`. Pass the canonical path: Seatbelt resolves symlinks before matching a
subpath, so `/var/...` must be passed as `/private/var/...` on macOS.

## What the profile allows

The profile starts with `(deny default)` and `(deny network*)`; every other
line is an explicit grant.

| Grant | Reason |
| --- | --- |
| `process-exec` on `PROVIDER_BINARY` | The provider process is the only program the profile may launch. |
| `file-read*` on `PROVIDER_BINARY` | Exec and dyld map the provider binary itself. |
| `sysctl-read` | The Rust runtime reads kernel facts to size stack guard pages. |
| `file-read*` on `/` | Absolute path lookup starts at the filesystem root; only the root directory entry is readable. |
| `file-read*` on `/usr/lib`, `/System/Library`, `/Library/Apple/System/Library` | dyld maps libSystem and libiconv from the system library directories. |
| `file-read-data` on `/dev/urandom` | Identity and persona key generation read kernel randomness. |
| `file-read-data` / `file-write-data` on `/dev/null`, `/dev/zero` | Diagnostics and inherited null streams. |
| `file-read* file-write*` on `STORAGE_ROOT` | The single mutable boundary: device-derived identity state, nickname and persona keys under the root the Runtime names. |

No other path, network endpoint, Mach service or process is reachable. A write
or read reached through a symlink that resolves outside `STORAGE_ROOT` is
denied by the kernel (EPERM); the provider reports `storage_error` or a
`key_error` naming the failed operation and keeps serving.

## The one Runtime bridge change

`ProviderBridge::spawn` currently starts the provider binary directly. It needs
one confined startup path for did-provider that wraps the same command:

```rust
let mut command = Command::new("/usr/bin/sandbox-exec");
command
    .arg("-f")
    .arg(profile_path)
    .arg("-D")
    .arg(format!("STORAGE_ROOT={}", config.base_path))
    .arg("-D")
    .arg(format!("PROVIDER_BINARY={}", binary_path.display()))
    .arg(binary_path);
```

The profile travels with the installed capsule
(`capsules/did-provider/confine.sb`) and must be admitted and hash-bound by the
same component verification path as the provider binary. The did-provider call
site in `elastos-server` then uses this confined path instead of the generic
spawn. That is the only Runtime-side change; the provider protocol, storage
layout and `capsule.json` stay as they are.

## Network criterion

`did-provider` has no network operation and no test hook for a socket connect;
all of its operations are line-delimited JSON requests. Network access is
denied by `(deny default)` and the explicit `(deny network*)`, but no runtime
connect attempt is exercised. Adding a network hook would add a provider
behavior that the capsule contract does not have, so this criterion is skipped
and recorded here.

## Tests

`tests/confine.rs` runs the real binary under this profile with a temporary
storage root:

- `all_operations_under_profile` drives every `capsule.json` operation and
  requires each to succeed; `verify` and `verify_did_recovery` must return
  `valid: true` for genuine signatures and `valid: false` for tampered ones.
- `outside_write_denied` initializes the provider, then links `did/nickname.enc` to a file outside the root,
  requires `storage_error` with a permission-denial reason, an unchanged
  outside file and a successful follow-up request.
- `outside_read_denied` moves an existing persona key outside the root and
  links it back in. Its fixture profile grants metadata for that outside
  directory, so the refusal must name `Read failed` and the permission error.
  The outside key stays unchanged and the provider keeps serving.
- `outside_persona_metadata_denied` uses the original profile and requires
  `Metadata lookup failed`, before the provider can create a key.
- `persona_write_refusals_keep_their_reasons` checks directory creation and
  key persistence denials separately, with each exact permission error.
- `outside_nickname_metadata_denied` and `outside_nickname_read_denied` check
  the two nickname refusals separately. Both `Init` and the next `get_nickname`
  return the exact storage error. Restoring the file and repeating `Init`
  restores normal nickname access.

`read_optional_file` owns presence and read errors for nickname and persona
files. It checks presence once and reads the file; only confirmed absence
returns an empty result. The nickname loader decodes those bytes directly.
The identity library's path loader remains a compatibility reference in tests.
A metadata denial reports `Metadata lookup failed: ...`; a nickname read
denial reports the OS reason under `did-provider: failed to load nickname: ...`.
The byte decoder preserves the identity envelope, encryption, UTF-8 conversion,
trimming and empty-value rules. Unit tests compare exact errors for seven
malformed fixtures and values for plain, padded, Unicode and empty nicknames
against `elastos_identity::load_nickname_with_device_key`.

`nickname_metadata_change_reports_storage_error` runs the unit-test binary
under the same profile. A test-only callback changes the nickname path to an
outside symlink immediately after the reader's successful metadata lookup.
The test confirms that the next metadata lookup returns EPERM, then requires
both `Init` and `get_nickname` to return the exact `storage_error` from the
data read. It also checks recovery after the permitted file is restored and
confirms that the outside file stays unchanged. The callback exists only in
the test build. `nickname_reload_clears_previous_value_when_absent` requires a
later `Init` with empty storage to clear the previous nickname.

The tests write skip reasons directly to stderr when `/usr/bin/sandbox-exec`
is unavailable, so ordinary successful `cargo test` output shows which
confinement checks were skipped.

## Falsifier runs

Executed on 2026-10-25 from this worktree. Each mutation was restored before
the next run. Items 1–5 record the earlier runs; items 6–8 cover the metadata,
nickname-reset and path-change rules added to this record.

1. Replaced `(deny default)` with `(allow default)`, keeping `(version 1)`
   first. The profile loaded, the provider printed
   `did-provider: starting v0.1.0 (did:key)`, and `outside_write_denied` failed
   at `expected an error response, got {"data":{"nickname":"alice"},"status":"ok"}`
   because the outside write succeeded.
2. Added `(allow file-read-data (subpath (param "FIXTURE_METADATA_ROOT")))` to
   the read fixture. The profile loaded and `outside_read_denied` failed at
   `expected an error response, got {"data":{"did":"did:key:z6Mk...","name":"bot",...},"status":"ok"}`
   because the outside persona key was returned.
3. Replaced the positive `verify` signature with a tampered one. The profile
   loaded and the provider started; `all_operations_under_profile` failed at
   `genuine signature must verify` (`left: Bool(false)`, `right: true`).
4. Replaced the positive `verify_did_recovery` signature with a tampered one.
   The profile loaded and the provider started; `all_operations_under_profile`
   failed at `genuine recovery proof must verify` (`left: Bool(false)`,
   `right: true`).
5. Replaced the identity library refusal with a provider-invented reason.
   `nickname_load_refusals_keep_their_reasons` failed with
   `left: "did-provider: failed to load nickname: rejected"`,
   `right: "did-provider: failed to load nickname: EOF while parsing an object at line 1 column 1"`,
   proving the provider must return the library's refusal.
6. Changed the metadata-error branch in `read_optional_file` to `Ok(None)`.
   `cargo test --manifest-path capsules/did-provider/Cargo.toml --locked --offline --test confine _metadata_denied -- --nocapture`
   failed both metadata tests. `outside_nickname_metadata_denied` received
   successful `Init` instead of `storage_error`.
   `outside_persona_metadata_denied` received `Failed to persist persona key:
   Operation not permitted (os error 1)` instead of `Metadata lookup failed:
   Operation not permitted (os error 1)`.
7. Changed nickname reload to assign state only when the loaded value is
   `Some`. `cargo test --manifest-path capsules/did-provider/Cargo.toml --locked --offline --bin did-provider tests::nickname_reload_clears_previous_value_when_absent -- --nocapture`
   failed with `Expected an absent nickname, got Ok` and nickname `alice`.
   This confirms that successful reload from empty storage clears the old value.
8. Added `if !path.exists() { return Ok(None); }` after the successful metadata
   lookup in `read_optional_file`.
   `cargo test --manifest-path capsules/did-provider/Cargo.toml --locked --offline --bin did-provider tests::nickname_metadata_change_reports_storage_error -- --nocapture`
   failed after the controlled symlink change: `Init` returned `Ok` instead of
   `did-provider: failed to load nickname: Operation not permitted (os error 1)`.
   The profile loaded and the test confirmed EPERM before the response assertion.
