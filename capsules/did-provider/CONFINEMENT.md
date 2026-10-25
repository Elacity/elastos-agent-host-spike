# did-provider confinement

`capsules/did-provider/confine.sb` is the single confinement profile for this
provider. It starts with `(version 1)` and `(deny default)`, and it denies every
network operation. The process reads line-delimited JSON from stdin and writes
one JSON response per line to stdout; it opens no listener or socket.

The Runtime owns the profile: it loads `confine.sb` only from the signed
provider bundle, checks its hash, refuses any profile with `(allow default)` or
a network allow, and fails closed with a reason; the provider proposes, the
Runtime checks (P4, P11). The bridge integration loads this file and binds its
parameters when it launches the provider. This document specifies the Runtime
half; the reference files exercise the provider directly.

Runtime binds three parameters and creates the base before launch:

- `PROVIDER_EXECUTABLE`: the canonical provider binary path.
- `STORAGE_ROOT`: `Init.base_path/did`.
- `STORAGE_PARENT`: `Init.base_path`.

## What the profile allows

- Exec and read the program selected through `PROVIDER_EXECUTABLE`; the
  Runtime chooses the binary and the provider starts from it.
- Read `/` to resolve the absolute program path.
- Read `/usr/lib`, `/System/Library` and `/Library/Apple`; dyld loads system
  libraries and the shared cache from there.
- Read kernel facts through `sysctl-read`; the loader and allocator request
  them at startup.
- Read and write `/dev/null`; the Runtime may bind child streams to the null
  device.
- Read `/dev/urandom`; the encryption code takes its nonce entropy there.
- Read `STORAGE_PARENT`; the provider inspects the existing parent while it
  creates the identity directory.
- Read and write under `STORAGE_ROOT`; one grant covers encrypted nickname and
  persona state.

Every other file read, file write, process and network operation falls to
`(deny default)`.

## Tests

`tests/confine.rs` runs the real binary under `/usr/bin/sandbox-exec` with a
temporary absolute storage root and speaks the normal line-delimited JSON
protocol. It covers `Init`, `get_did`, `get_persona_did`, `get_nickname`,
`set_nickname` (the reload returns the stored value), and `resolve` of the
provider's own DID.

For message signing the test calls `sign_chat_message`, which returns the
payload it signed next to the signature. The test feeds both back to `verify`
unchanged and expects `valid: true`, then flips one character of the provider's
signature and expects `valid: false`. The test renders no signing payload and
constructs no signature.

`verify_did_recovery_under_profile` covers the recovery operation. No provider
operation produces a recovery proof, so the case builds none: it would copy the
signing path into the test (P10). It sends a complete request with valid
bindings and timestamps and a signature that is not hex, and expects
`invalid_signature` with an `Invalid hex sig:` reason from the running confined
provider, then a further `get_did` to prove the refusal left the service up.
Genuine-proof correctness is covered by the in-process unit tests in
`src/main.rs`.

Two symlink cases check the boundary. `outside_write_denied` points the granted
nickname file at an unrelated directory and expects `storage_error`, no file
outside the root, and a later write under the root to succeed.
`outside_read_denied` points the same path at real encrypted nickname state
outside the root and expects `Init` to refuse with the nickname-read reason,
the outside file to stay unchanged, the provider to report no nickname for its
own root, and a normal request to succeed after the link is removed. Both cases
fail when `(deny default)` becomes `(allow default)`.

`profile_denies_network` reads the profile and requires `(version 1)` first,
`(deny default)`, and an explicit `(deny network*)`, with no network grant and
no default grant. It runs on every platform, and removing `(deny network*)`
makes it fail. The test runs no TCP probe: the provider has no network path, so
a probe would test the host network stack while the profile rule is the
property that must hold.

Run `cargo test --locked --manifest-path capsules/did-provider/Cargo.toml` from
the repository root. When `/usr/bin/sandbox-exec` is absent the native tests
print a skip reason; a present sandbox that refuses to launch the child fails
the test.

## Falsifiers

- Replace `(deny default)` with `(allow default)`, keeping `(version 1)` first:
  both outside cases fail because the symlinked write and read succeed.
- Remove `(deny network*)`: `profile_denies_network` fails.
- Restore the `if let Ok(Some(nick))` swallow in `try_load_nickname`:
  `outside_read_denied` fails because the denied read becomes "no nickname".
- Panic in the `hex::decode(sig_hex)` error branch of `verify_did_recovery` in
  `src/main.rs`: `verify_did_recovery_under_profile` fails because the confined
  process dies without a response.
- Return `parse_error` instead of the signature refusal: the same case fails
  because the response does not name `invalid_signature`.

The wallet provider keeps its own profile and tests in `../wallet-provider/`
with the same launch and subtree-grant pattern.
