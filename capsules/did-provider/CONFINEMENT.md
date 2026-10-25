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

The profile starts with `(version 1)`, then `(deny default)` and
`(deny network*)`; every other line is an explicit grant.

| Grant | Reason |
| --- | --- |
| `process-exec` on `PROVIDER_BINARY` | The provider process is the only program the profile may launch. |
| `file-read*` on `PROVIDER_BINARY` | Exec and dyld map the provider binary itself. |
| `sysctl-read` | The Rust runtime reads kernel facts to size stack guard pages. |
| `file-read*` on `/` | Absolute path lookup starts at the filesystem root; only the root directory entry is readable. |
| `file-read*` on `/usr/lib`, `/System/Library`, `/Library/Apple/System/Library` | dyld maps libSystem and libiconv from the system library directories. |
| `file-read-data` on `/dev/urandom` | Identity and persona key generation read kernel randomness. |
| `file-read-data` on `/dev/null`, `/dev/zero` | Diagnostics and inherited null streams. |
| `file-write-data` on `/dev/null` | Diagnostics are discarded rather than persisted. |
| `file-read* file-write*` on `STORAGE_ROOT` | The single mutable boundary: device-derived identity state, nickname and persona keys under the root the Runtime names. |

No other path, network endpoint, Mach service or process is reachable. A write
or read reached through a symlink that resolves outside `STORAGE_ROOT` is
denied by the kernel (EPERM). The provider reports `storage_error` or
`key_error` naming the failed operation and keeps serving.

## Network

`did-provider` has no network operation. Every request arrives as one
line-delimited JSON line on inherited stdin, and every answer leaves on
stdout; the provider opens no socket. The profile states this with
`(deny network*)` on top of `(deny default)`. No TCP probe runs: the provider
exposes no socket hook, and adding one would add a provider behavior the
capsule contract does not have. The tests record this criterion and skip the
probe rather than invent a second path.

## Storage reads

`read_optional_file` owns presence and read errors for persona files. Only a
confirmed missing file permits key creation; a denied metadata lookup reports
`Metadata lookup failed: ...` and a denied data read reports
`Read failed: ...`.

Nickname loading stays with `elastos-identity`: the identity library owns the
nickname location, presence, read and decode rules, so the provider keeps one
path and one decoder. The provider adds its context
(`did-provider: failed to load nickname: ...`) and caches that refusal, so
`get_nickname` repeats the same reason instead of reporting an unset nickname.

Prerequisite, outside this task's paths:
`elastos/crates/elastos-identity/src/store.rs` must replace `Path::exists()`
in `load_nickname_with_device_key` with `try_exists()` so a denied metadata
lookup is an error rather than absence. The provider then reports that error
through the same single call; until the change lands, the provider reports
what the loader returns.

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

## Tests

`tests/confine.rs` runs the real binary under this profile with a temporary
storage root:

- `all_operations_under_profile` drives `Init`, `set_nickname`,
  `get_nickname`, `get_did`, `get_persona_did`, `resolve`,
  `sign_chat_message` and `verify`, and requires each to return `ok`. The
  manifest comparison names `verify_did_recovery` as task 007, not dropped.
- `chat_signature_roundtrip` (inside the operations test) feeds the
  provider-returned payload and signature back to `verify` unchanged, requires
  `valid: true`, then flips one character of that same signature and requires
  `valid: false`. The test builds no signature and no signing payload.
- `outside_write_denied` initializes the provider, links `did/nickname.enc` to
  a file outside the root, requires the exact
  `did-provider: failed to save nickname: Operation not permitted (os error 1)`,
  an unchanged outside file and a successful follow-up request.
- `outside_read_denied` moves an existing persona key outside the root and
  links it back in. Its fixture profile grants metadata for that outside
  directory, so the refusal must name `Read failed` and the permission error.
  The outside key stays unchanged and the provider keeps serving.
- `outside_persona_metadata_denied` uses the original profile and requires
  `Metadata lookup failed`, before the provider can create a key.
- `persona_write_refusals_keep_their_reasons` checks directory creation and
  key persistence denials separately, each with its exact operation name and
  permission error.
- `outside_nickname_read_denied` moves the stored nickname outside the root
  and links it back in. Its fixture profile grants metadata, so the refusal
  happens at the data read. Both `Init` and the next `get_nickname` return the
  exact `did-provider: failed to load nickname: Operation not permitted
  (os error 1)`. Restoring the file and repeating `Init` restores normal
  nickname access.

`nickname_load_refusal_reaches_init_and_get_nickname` writes a malformed
nickname file and requires the identity library's own refusal, wrapped once as
`did-provider: failed to load nickname: ...`, from both `Init` and
`get_nickname`, while `get_did` keeps working. It needs no sandbox.

The tests write skip reasons directly to stderr when `/usr/bin/sandbox-exec`
is unavailable, so ordinary successful `cargo test` output shows which
confinement checks were skipped.

## Falsifier runs

Executed on 2026-10-25 from this worktree. Each mutation was restored before
the next run; every restored profile and test passes.

1. Replaced `(deny default)` with `(allow default)`, keeping `(version 1)`
   first. `outside_write_denied` failed at `expected an error response, got
   {"data":{"nickname":"alice"},"status":"ok"}` because the outside write
   succeeded. Restored, it passes.
2. Added `(allow file-read-data (subpath (param "OUTSIDE_ROOT")))` to the read
   fixture. `outside_read_denied` failed at `expected an error response, got
   {"data":{"did":"did:key:...","name":"bot",...},"status":"ok"}` because the
   outside persona key was returned.
3. Changed the metadata branch in `read_optional_file` to `Ok(None)`.
   `outside_persona_metadata_denied` failed with
   `Failed to persist persona key: Operation not permitted (os error 1)`
   instead of `Metadata lookup failed: Operation not permitted (os error 1)`.
4. Swallowed the loader error in `try_load_nickname` with `unwrap_or(None)`.
   `nickname_load_refusal_reaches_init_and_get_nickname` failed because `Init`
   returned `Ok` instead of `did-provider: failed to load nickname: EOF while
   parsing an object at line 1 column 1`; `outside_nickname_read_denied`
   failed at the same point.
5. Removed the cached refusal from `get_nickname`. Both tests failed at
   `get_nickname`: `left: "not_set"`, `right: "storage_error"`.
6. Replaced the save reason with a generic
   `did-provider: failed to save nickname`. `outside_write_denied` failed at
   `left: "did-provider: failed to save nickname"`.
7. Replaced the persona read reason with a generic `Read failed`.
   `outside_read_denied` failed at `left: "Read failed"`.
8. Replaced the persona create reason with a generic `Failed to create dir`,
   then the persist reason with a generic `Failed to persist persona key`.
   `persona_write_refusals_keep_their_reasons` failed once per mutation at
   `left: "Failed to create dir"` and `left: "Failed to persist persona key"`.
9. Corrupted one character of the returned `payload_hex` in
   `sign_chat_message`. `all_operations_under_profile` failed at `the
   provider's own signature must verify against the payload it returned`
   (`left: Bool(false)`, `right: true`).
