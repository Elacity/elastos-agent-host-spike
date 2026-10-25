# did-provider confinement

`capsules/did-provider/confine.sb` is the single confinement profile for this
provider. It starts with `(version 1)` and `(deny default)`, and it denies every
network operation. The process reads line-delimited JSON from stdin and writes
one JSON response per line to stdout; it opens no listener or socket.

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

Runtime binds three parameters and creates the base before launch:

- `PROVIDER_EXECUTABLE`: the canonical provider binary path.
- `STORAGE_ROOT`: `Init.base_path/did`.
- `STORAGE_PARENT`: `Init.base_path`.

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

## What the profile allows

- `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))`: start only the
  binary the Runtime named.
- `(allow file-read* (literal "/"))`: resolve the absolute program path through
  the root directory.
- `(allow sysctl-read)`: the loader and the allocator read kernel facts at
  startup.
- `(allow file-read* (literal (param "STORAGE_PARENT")))`: bind the one shared
  file-profile contract. No did confinement test needs this grant; the profile
  keeps it because the wallet profile and the Runtime bridge bind the same
  parameter (P10).
- `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`: one grant
  covers encrypted nickname and persona state.

`process-exec`, the `STORAGE_PARENT` read and the `STORAGE_ROOT` grant are the
three shared contract rules pinned verbatim by
`both_file_profiles_bind_one_storage_parameter_contract`; the `STORAGE_PARENT`
read is the one of them that did-provider keeps only for that contract.

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

`both_file_profiles_bind_one_storage_parameter_contract` lives in
`../wallet-provider/tests/confine.rs`. One check function holds the
contract: `(version 1)` first, `(deny default)` second, an explicit
`(deny network*)`, no network allow, the same `PROVIDER_EXECUTABLE` /
`STORAGE_ROOT` / `STORAGE_PARENT` parameter tokens, no `(allow default)` rule,
and the three shared rules verbatim. One list function runs that check over
`capsules/did-provider/confine.sb`, `capsules/wallet-provider/confine.sb`
and `capsules/model-provider/confine.sb`: the did and wallet profiles are
required, and the model profile is checked whenever that file exists and
skipped with a printed reason while it is absent. The test runs on every
platform because it reads files and starts no process. It does not claim
that the model provider meets the contract today.

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
- Rename `STORAGE_ROOT` to `DID_STORAGE_ROOT` in either provider's `confine.sb`:
  `both_file_profiles_bind_one_storage_parameter_contract` fails on the
  non-canonical token.
- Remove `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` (DID07):
  `confined_provider_serves_did_operations_under_its_root`,
  `outside_read_denied`, `outside_write_denied` and
  `verify_did_recovery_under_profile` fail because the provider cannot start.
- Remove `(allow file-read* (literal "/"))` (DID08): the same four cases fail.
- Remove `(allow sysctl-read)` (DID09): the same four cases fail.
- Remove the `STORAGE_ROOT` grant (DID10):
  `confined_provider_serves_did_operations_under_its_root` and
  `outside_write_denied` fail because the identity write is denied.
- Remove `(allow file-read* (literal (param "STORAGE_PARENT")))`: WP11 in
  `../wallet-provider/falsifiers.json` records it, and
  `both_file_profiles_bind_one_storage_parameter_contract` fails. No did
  confinement test fails, so did keeps this grant only for the one contract.

Task 015 removed these allow forms because no named confinement test needed
them on macOS 26.5.2 arm64:

- `(allow file-read* (literal (param "PROVIDER_EXECUTABLE")))` removed: no
  confinement test needed it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/usr/lib"))` removed: no confinement test needed
  it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/System/Library"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/Library/Apple"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.
- `(allow file-read* file-write* (literal "/dev/null"))` removed: no
  confinement test needed it on macOS 26.5.2 arm64.
- `(allow file-read* (literal "/dev/urandom"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.

A host that needs one of the removed grants receives a sandbox denial for the
affected access, so that operation fails closed with a reason. The grant comes
back only together with a named test that needs it.

The wallet provider keeps its own profile and tests in `../wallet-provider/`.
Both providers present the same file-based contract to the Runtime bridge:
`(version 1)`, `(deny default)`, `(deny network*)`, the `STORAGE_ROOT` /
`STORAGE_PARENT` / `PROVIDER_EXECUTABLE` parameter tokens, and the
`/usr/bin/sandbox-exec -f confine.sb` launch shape.
