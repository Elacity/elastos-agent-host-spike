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

The provider reads nickname bytes once after a fallible metadata lookup. It
decodes the existing identity JSON envelope with the same key derivation and
encryption. Lookup, read, envelope, nonce, ciphertext, decryption and UTF-8
errors retain distinct reasons. Unit tests check those reasons and the existing
identity-library compatibility tests check the storage format.

The tests write skip reasons directly to stderr when `/usr/bin/sandbox-exec`
is unavailable, so ordinary successful `cargo test` output shows which
confinement checks were skipped.

To check the falsifiers, replace `(deny default)` with `(allow default)` while
keeping `(version 1)` first: `outside_write_denied` must fail because
`set_nickname` succeeds. Granting `file-read-data` on `FIXTURE_METADATA_ROOT`
in the read fixture must make `outside_read_denied` fail because the existing
persona is returned. Separately tamper the positive `verify` and
`verify_did_recovery` requests: `all_operations_under_profile` must fail at
`genuine signature must verify` and `genuine recovery proof must verify`,
respectively. Restore each mutation before running the next check.
