# did-provider confinement

`capsules/did-provider/confine.sb` is the one oracle for this provider's
confinement profile (one file, P10): the profile the Runtime generates for this
provider must match it. It starts with `(version 1)` and `(deny default)`, and
it denies every network operation. The process reads line-delimited JSON from
stdin and writes one JSON response per line to stdout; it opens no listener or
socket.

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

## Profile parameters

The generated profile binds three parameters, which the tests pass with
`sandbox-exec -D`:

- `PROVIDER_EXECUTABLE`: the canonical provider binary path.
- `STORAGE_ROOT`: `Init.base_path/did`.
- `STORAGE_PARENT`: `Init.base_path`.

The tests pass a temporary base and bind all three parameters before launch;
the Runtime half of the bridge change does the same and is not built.

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
The one caller, `sandbox_available`, fails the test on that
error; `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` calls
it with `macos` and a missing path and expects the failure.
This contract has no Linux enforcement or tests yet. A provider-status claim
needs host-specific test evidence and the Runtime acceptance step, so no status
document records `did-provider` or `wallet-provider` as confined on Linux until
that test exists (P10, P11). The status change lands when the Runtime side
does.

Future Linux enforcement tests for this lab contract are designed in
`../wallet-provider/CONFINEMENT-LINUX.md`: it is the one Linux mapping, its
tests do not exist yet, and it claims no current behaviour. The existing
source-only check `both_file_profiles_bind_one_storage_parameter_contract`,
in `../wallet-provider/tests/confine.rs`, reads the three oracles and supplies
contract evidence, not Linux execution evidence.

## What the profile allows

- `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))`: start only the
  binary the launch named.
- `(allow file-read* (literal "/"))`: resolve the absolute program path through
  the root directory.
- `(allow sysctl-read)`: the loader and the allocator read kernel facts at
  startup.
- `(allow file-read* (literal (param "STORAGE_PARENT")))`: bind the one shared
  file-profile contract. No did confinement test needs this grant; the profile
  keeps it because the wallet profile and the generated profile bind the same
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
outside the root, and a later write under the root to succeed. It repeats that
link case for `nickname.enc` in a sibling directory under the same base, beside
`did/`, and gets the same refusal, so the write grant stops at
`Init.base_path/did`.
`outside_read_denied` points the same path at real encrypted nickname state
outside the root and expects `Init` to refuse with the nickname-read reason,
the outside file to stay unchanged, the provider to report no nickname for its
own root, and a normal request to succeed after the link is removed. Both cases
fail when `(deny default)` becomes `(allow default)`.

`startup_denial_reports_its_reason` covers the failure path. It starts the
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

`startup_is_refused_when_the_profile_cannot_be_applied` covers a profile that
never loads. It launches the provider through the one builder three ways: a
profile path that does not exist, a copy of `confine.sb` with its last `)`
removed, and the real profile with every parameter bound except
`STORAGE_ROOT`. In each case `sandbox-exec` exits with a status other than 0
before it reaches the exec, the child exits within the deadline with a status
other than 0, the one harness failure names the request, that exit status and
the profile's reason from standard error, and nothing lands under the storage
root. The failure never names `execvp`, so the exec was never attempted. The
case skips with its printed reason when `sandbox-exec` is absent on a host OS
other than macOS.

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
and `capsules/model-provider/confine.sb`. All three profiles are required,
and a missing or unreadable profile fails the check with a reason that names
its path. The test runs on every platform because it reads files and starts
no process.

`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` checks the gate
itself without starting a process: a missing `sandbox-exec` on `macos` is an
error that names the OS and the path, a missing one on `linux` is a skip, and
a present one on `macos` runs the test. It runs on every supported build
target.

`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` checks the
one caller without starting a process: with `macos` and a missing
`sandbox-exec` it fails the test with the gate's reason, and with `macos` and
a present one it returns `true`. It runs on every supported build target.

Run `cargo test --locked --manifest-path capsules/did-provider/Cargo.toml` from
the repository root. When `/usr/bin/sandbox-exec` is absent on a host OS other
than macOS the native tests print a skip reason; on macOS a missing
`sandbox-exec` fails the gate, as does a present sandbox that refuses to
launch the child.

The one runner applies and restores each registered falsifier with
`python3 -I examples/agent-host/falsify.py --from capsules/did-provider/falsifiers.json`
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

## Falsifiers

- Restore the temp-directory fallback for a missing or empty storage root
  (DID01): `tests::init_requires_storage_without_key` and
  `tests::empty_storage_path_is_refused` fail because a missing or empty root
  returns a path instead of refusing.
- Drop the absolute-path check in `base_dir` (DID02):
  `tests::relative_storage_is_refused` fails because a relative root is
  accepted.
- Replace the nickname read error with `.ok().flatten()` in
  `try_load_nickname` (DID03): `tests::init_reports_nickname_read_error` and
  `outside_read_denied` fail because a denied or failed read becomes no
  nickname.
- Replace `(deny default)` with `(allow default)`, keeping `(version 1)` first
  (DID04): `outside_write_denied` and `outside_read_denied` fail because the
  symlinked write and read succeed.
- Replace `(deny network*)` with `(allow network*)` (DID05):
  `profile_denies_network` fails on the missing explicit denial.
- Panic in the `hex::decode(sig_hex)` error branch of `verify_did_recovery` in
  `src/main.rs` (DID06): `verify_did_recovery_under_profile` fails because the
  confined process dies without a response.
- Return `parse_error` instead of the signature refusal in the non-hex branch
  of `verify_did_recovery` (DID11): `verify_did_recovery_under_profile` fails
  because the response does not name `invalid_signature`.
- Rename `STORAGE_ROOT` to `DID_STORAGE_ROOT` in
  `capsules/did-provider/confine.sb` (WP23 in
  `../wallet-provider/falsifiers.json`):
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
- Drop the child's standard error from the harness failure (DID12):
  `startup_denial_reports_its_reason` fails because the failure no longer
  carries `sandbox-exec`'s `Operation not permitted`.
- Drop the stderr pipe instead of draining it (DID13):
  `stderr_is_drained_before_wait` fails because only `dd` dies on the closed
  pipe; the shell still exits 7, and the collected text is empty, so the test
  fails on its byte count, `left: 0, right: 131072`.
- Omit the request from the harness failure (DID14):
  `startup_denial_reports_its_reason` fails because the failure does not name
  the `init` request.
- Omit the exit status from the harness failure (DID15):
  `startup_denial_reports_its_reason` fails because the failure does not name
  the child's exit status.
- Return a fixed message from the failed-write branch instead of the shared
  diagnostic (DID16): `startup_denial_reports_its_reason` fails because the
  denied-provider failure names no request, exit status or standard error.
- Return a fixed message from the response-stream branch instead of the shared
  diagnostic (DID17): `startup_denial_reports_its_reason` fails because the
  response-stream failure names no request, exit status or standard error.
- Widen the write grant from `STORAGE_ROOT` to `STORAGE_PARENT` (DID18):
  `outside_write_denied` fails on its sibling target because that write
  succeeds.
- Start the provider binary directly when the profile file does not exist
  (DID21): `startup_is_refused_when_the_profile_cannot_be_applied` fails on
  its missing-profile case because the provider starts and stays alive instead
  of being refused.
- Return `false` from the error arm of `sandbox_available` instead of failing
  the test (DID22): `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing`
  fails because a missing `sandbox-exec` on `macos` returns instead of failing.
- Start the drainer only after `wait_for_exit` has returned (DID23):
  `stderr_is_drained_before_wait` fails on its exit assertion because the
  child blocks on a full pipe and never exits within the deadline.
- Use a fixed `Operation not permitted` instead of the child's standard error
  in `unanswered` (DID24): `startup_denial_reports_its_reason` fails on its
  `execvp()` assertion because the fixed text names no exec denial.
- Return the shared unanswered message from the invalid-JSON branch (DID25):
  `invalid_json_answer_names_the_request_and_the_parse_error` fails because the
  answer loses its parse error and says the provider did not answer.

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
affected access, so that operation fails closed with a reason. In the
confinement tests the failure of the request the provider never answered names
the request and the provider's exit status. When the profile denies the exec
itself (DID07), the failure also carries `sandbox-exec`'s `Operation not
permitted` from standard error. When the loader runs and a later read is denied
(DID08, DID09), standard error is empty and the failure shows only the signal,
`signal: 6 (SIGABRT)`. The grant comes back only together with a named test
that needs it.

The wallet provider keeps its own oracle and tests in `../wallet-provider/`.
did-provider, wallet-provider and model-provider present one contract as
oracles: `(version 1)`, `(deny default)`, `(deny network*)`, the `STORAGE_ROOT`
/ `STORAGE_PARENT` / `PROVIDER_EXECUTABLE` parameter tokens, and the three
shared rules. The tests launch each oracle with
`/usr/bin/sandbox-exec -f confine.sb`; that launch is the tests', and the
Runtime half that generates and compares the profile is future work.
