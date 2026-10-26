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
no network allow, exactly one `process-exec` allow, the shared exec rule, only
the `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and `STORAGE_PARENT` parameter
tokens, and the three shared rules verbatim. An exec added later, such as a
model engine's, is its own named rule with its own falsifier and removal
condition, agreed with Sasha and Rong like the network grant, and never widens
what `PROVIDER_EXECUTABLE` binds.
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

`every_did_and_wallet_allow_rule_traces_to_one_declared_right` reads
`capsules/did-provider/tests/fixtures/confine/declared-rights.json`. That file
is a lab stand-in for the Runtime generator's input and not a manifest field.
Every top-level allow rule of the did profile traces to exactly one right the
shared contract names, or to one observed startup need. The profile rules are
evidence for Anders to review and not accepted rights. The startup label says
"observed startup needs, not approved rights; Anders decides". The generator
stays the Runtime's.

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

## Operations and the rights they need

Each operation the provider answers is one row. The inputs are the operation's
top-level JSON names. An ok answer is `status` plus `data`. An error answer is
`status`, `code` and `message`. The keys of `data` are the keys of the value
the handler returns. A right, an effect, a macOS rule or a test is written only
where a named test in `tests/confine.rs` shows it. Where no named test shows
one, the cell says "no named test shows this". A citation is a backtick span
that holds a file relative to this folder, two colons and a function name. The
check `every_operations_table_cites_existing_tests` in
`../wallet-provider/tests/confine.rs` finds `fn <fn>(` in that file and does
not decide whether the function is a `#[test]`. A refusal under `(deny
default)` is a denial, not a grant, and no row writes it as a right. The
startup grants stay in "What the profile allows".

M1 check B4 stays open: this table records the macOS half of its permission
model. Linux stays designed, not enforced, and this section claims no current
Linux behaviour. The design is `../wallet-provider/CONFINEMENT-LINUX.md`; its
tests do not exist yet. A JSON parse failure answers `parse_error`; it is not
an operation and gets no row.

| Operation | Inputs | Outputs | Right | Effect | macOS rule and test | Linux |
| --- | --- | --- | --- | --- | --- | --- |
| init | `op`, `config` | ok: `status`, `data` (`protocol_version`, `provider`). error: `status`, `code`, `message`. | `storage` | reads `did/nickname.enc` under `STORAGE_ROOT`; `tests/confine.rs::outside_read_denied` shows the read refused with `storage_error` when that path resolves outside. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`; removing it is DID10 and `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` fails. | designed, not enforced |
| get_did | `op` | ok: `status`, `data` (`did`). error: `status`, `code`, `message`. | no named test shows this | derives the DID from the device key in memory; no named test shows a file read or write for this call. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the answer; no named test shows a storage rule for this call. | designed, not enforced |
| resolve | `op`, `did` | ok: `status`, `data` (`public_key`, `document`). error: `status`, `code`, `message`. | no named test shows this | builds the document from the DID in memory; no named test shows a file read or write for this call. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the document id; no named test shows a storage rule for this call. | designed, not enforced |
| sign_chat_message | `op`, `sender_id`, `ts`, `content` | ok: `status`, `data` (`payload`, `signature`). error: `status`, `code`, `message`. | no named test shows this | signs the rendered payload in memory; no named test shows a file read or write for this call. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the payload and the signature; no named test shows a storage rule for this call. | designed, not enforced |
| verify | `op`, `did`, `data`, `signature` | ok: `status`, `data` (`valid`). error: `status`, `code`, `message`. | no named test shows this | verifies the payload in memory; no named test shows a file read or write for this call. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows `valid: true` and `valid: false` for a flipped signature; no named test shows a storage rule for this call. | designed, not enforced |
| verify_did_recovery | `op`, `did`, `principal_id`, `localhost_root`, `protector_id`, `data_key_id`, `nonce`, `issued_at`, `expires_at`, `signature` | ok: `status`, `data` (`schema`, `valid`, `did`, `principal_id`, `localhost_root`, `protector_id`, `data_key_id`, `payload_sha256`, `verified_at`). error: `status`, `code`, `message`. | no named test shows this | refuses a non-hex signature with `invalid_signature` and stays in service; genuine-proof correctness is the in-process unit tests in `src/main.rs`. | `tests/confine.rs::verify_did_recovery_under_profile` shows the refusal and the later `get_did`; no named test shows a storage rule for this call. | designed, not enforced |
| get_nickname | `op` | ok: `status`, `data` (`nickname`). error: `status`, `code`, `message`. | no named test shows this | returns the cached nickname; the file read belongs to `init`, and no named test shows a read for this call. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the nickname after a restart; the read is `init`'s. | designed, not enforced |
| set_nickname | `op`, `nickname` | ok: `status`, `data` (`nickname`). error: `status`, `code`, `message`. | `storage` | writes `did/nickname.enc` under `STORAGE_ROOT`; `tests/confine.rs::outside_write_denied` shows the write refused with `storage_error` outside the root. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`; removing it is DID10 and `tests/confine.rs::outside_write_denied` fails. | designed, not enforced |
| get_persona_did | `op`, `name` | ok: `status`, `data` (`did`, `owner_did`, `name`). error: `status`, `code`, `message`. | `storage` | reads or writes `did/personas/<name>.enc` under `STORAGE_ROOT`; `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the file after the call and the same persona after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`; removing it is DID10 and `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` fails. | designed, not enforced |
| shutdown | `op` | ok: `status`, `data` (`message`). error: `status`, `code`, `message`. | no named test shows this | answers and exits; no named test shows a file read or write for this call. | `tests/confine.rs::bound_copy_serves_under_profile` shows the answer and a clean exit; no named test shows a storage rule for this call. | designed, not enforced |

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
  binary the launch named. `unbound_copy_is_refused_under_profile` shows that a
  byte-identical copy of the binary under `STORAGE_ROOT` is refused with exit 71
  and the `execvp()` `Operation not permitted` line, and
  `bound_copy_serves_under_profile` is its control.
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

`planted_file_beneath_storage_parent_is_neither_read_nor_written` plants real
encrypted nickname state in a sibling directory beneath `STORAGE_PARENT` and
outside `STORAGE_ROOT`, then points the granted nickname path at it. Under the
real profile `init` refuses the read with `storage_error` and the nickname-read
reason, and the planted bytes stay unchanged. After the link is removed `init`
answers ok, `get_nickname` answers `not_set` and `set_nickname` serves the
provider's own root. With the link made again, `set_nickname` refuses the write
with `storage_error`, the nickname-save reason and unchanged planted bytes. The
parent read grants the directory itself only, so widening it to `subpath`, or
granting writes on the parent, makes this test fail.

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

`unbound_copy_is_refused_under_profile` and `bound_copy_serves_under_profile`
split the exec rule into its two halves under the real profile, with no fixture
rule. The first binds the real binary as `PROVIDER_EXECUTABLE` and starts a
byte-identical copy stored under `STORAGE_ROOT`; `sandbox-exec` applies the
profile before the exec, so the copy is refused with exit 71 and the `execvp()`
`Operation not permitted` line, the `init` request gets no answer, and the
storage root keeps only the copy with its bytes unchanged. The second is its
control: the same fixture with `PROVIDER_EXECUTABLE` bound to the copy and the
copy started answers `init` and `get_did` and exits 0 after `shutdown`, and,
like the refused run, leaves the copy's bytes unchanged: the test reads them
before the spawn and checks them again after `shutdown`, so the binding is the
only difference between the two runs.

`profile_denies_network` reads the profile and requires `(version 1)` first,
`(deny default)`, and an explicit `(deny network*)`, with no network grant and
no default grant. It runs on every platform, and removing `(deny network*)`
makes it fail. The test runs no TCP probe: the provider has no network path, so
a probe would test the host network stack while the profile rule is the
property that must hold.

`both_file_profiles_bind_one_storage_parameter_contract` lives in
`../wallet-provider/tests/confine.rs`. One check function holds the
contract: `(version 1)` first, `(deny default)` second, an explicit
`(deny network*)`, no network allow, exactly one `process-exec` allow, the
shared exec rule, the same `PROVIDER_EXECUTABLE` / `STORAGE_ROOT` /
`STORAGE_PARENT` parameter tokens, no `(allow default)` rule, and the three
shared rules verbatim. One list function runs that check over
`capsules/did-provider/confine.sb`, `capsules/wallet-provider/confine.sb`
and `capsules/model-provider/confine.sb`. All three profiles are required,
and a missing or unreadable profile fails the check with a reason that names
its path. The test runs on every platform because it reads files and starts
no process.

`every_did_and_wallet_allow_rule_has_a_registered_removal` in the same file
requires a registered removal falsifier for every top-level allow rule of did's
profile.

`every_falsifier_id_is_named_in_its_confinement_document` in the same file
reads this document, `../wallet-provider/CONFINEMENT.md` and both falsifier
lists, and fails when a registered id is not named in its own document's
`## Falsifiers` section or the section names an id that neither list
registers. It reads files and starts no process.

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

A run of the list is evidence only where the sandbox tests run: the runner runs
every chosen named test once on the unmutated tree before its first edit, so on
macOS without `/usr/bin/sandbox-exec` each sandbox test fails at the gate and
its entry reads `NOT RUN` instead of `CAUGHT`, while where the sandbox tests
skip an entry that names one reads `SURVIVED`. A call site that passes a fixed
`"linux"` for the OS is not caught by a run on a Mac where
`/usr/bin/sandbox-exec` exists, because a present tool runs the test before the
OS is read, so that run is no evidence for the OS argument.

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
- Resolve the honesty test's edit paths from the repository root again (DID19):
  `tests::falsifiers_list_is_honest` and
  `tests::falsifiers_list_rejects_a_repository_relative_path` fail.
- Return `Ok(false)` from the sandbox gate's declared-OS branch (DID20):
  `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` fails.
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
- Append a second, unpinned `(allow process-exec)` after the exec rule (DID26):
  `unbound_copy_is_refused_under_profile` fails on its deadline assertion
  because the copy under `STORAGE_ROOT` starts instead of being refused.
- Widen the parent read from `literal` to `subpath` (DID27):
  `planted_file_beneath_storage_parent_is_neither_read_nor_written` fails on
  its read half because the planted file loads and `init` answers ok.
- Append a write grant on `STORAGE_PARENT` after the storage-root rule (DID28):
  `planted_file_beneath_storage_parent_is_neither_read_nor_written` fails on
  its write half because that `set_nickname` succeeds; the read half passes.
- Append one byte to the provider's own executable in the `Shutdown` arm when
  it lies beneath the storage root (DID29):
  `bound_copy_serves_under_profile` fails on its bytes assertion because the
  served run changes the copy under `STORAGE_ROOT`.

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
