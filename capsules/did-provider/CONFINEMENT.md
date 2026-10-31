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
to the same paths. A lab generator, `generate_profile` in
`capsules/wallet-provider/tests/common/profile_generator.rs`, builds this
profile from the declared-rights file and the contract head, and
`generated_did_and_wallet_profiles_match_their_committed_oracles` requires it
to equal this oracle; the Runtime's own generator and its comparison are not
built and stay in `elastos/`, outside this lane.
The lab generator and writer are test code only, and
`lab_generator_is_named_only_in_test_code` fails if a file outside test code
names either, so the Runtime keeps one profile generator (P10).
The one contract check, `check_profile_contract`, holds every oracle
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
The lab writer `write_generated_profile` writes no did-provider profile when
the declared-rights file names an id the shared contract does not name. The
wallet crate's `generator_refuses_an_unnamed_right_and_the_start_is_refused`
feeds did-provider's own declared-rights file with an unnamed id and shows
the refusal and that no did-provider profile is written; it shows the start
refusal under the unwritten path with the wallet binary only, because the did
harness cannot run the generator. The Runtime's own refusal is not built.

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
shared contract names, or to one platform-baseline rule. In the did profile,
each allow rule is claimed by the one id the contract names for it, and no id or
rule is declared twice. The profile rules are evidence for Anders to review and
not accepted rights. Its status label says "Runtime platform baseline for the
did-provider executable on macOS, not approved rights". The model provider's
`capsules/model-provider/tests/fixtures/confine/declared-rights.json` uses the
same template, and `model_declared_rights_read_on_the_did_and_wallet_template`
reads it. The lab generator is test code, and the Runtime's own generator is
not built. Each platform-baseline rule in this provider's
`tests/fixtures/confine/declared-rights.json` gives one
justification that starts with the did-provider executable prefix,
`macOS did-provider executable bound as PROVIDER_EXECUTABLE:`, and gives a
reason; the `startup-root-directory` justification uses this document's
root-directory sentence, and a justification with another provider's prefix or
no reason is refused.

## Profile parameters

The generated profile binds three parameters, which the tests pass with
`sandbox-exec -D`:

- `PROVIDER_EXECUTABLE`: the canonical provider binary path.
- `STORAGE_ROOT`: `Init.base_path/did`.
- `STORAGE_PARENT`: `Init.base_path`.

One rule, `profile_parameter_section_problems`, under the test
`every_confinement_document_states_its_bindings_from_the_one_derivation`,
holds these three names and the two storage layouts to the one derivation the
launch uses, and it does not check a path for `PROVIDER_EXECUTABLE`.

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
not decide whether the function is a `#[test]`. The check
`every_operations_table_row_matches_its_provider_and_the_contract` holds every
row to four rules: the row set follows the provider's own dispatch, a Right
cell names a declared id or `none: needs no declared right`, a right row cites
both sides, and every Linux cell stays `designed, not enforced`. A fifth rule,
beside those four row rules, holds the capsule's own `capsule.json`, and
`operations_table_row_check_refuses_each_bad_table` refuses a manifest that
breaks it, because a manifest declares only operations the provider answers and
a provider may own operations its manifest does not name. The same check
reads each ordinary row's Inputs cell against the fields its `Request` arm
declares, in declaration order, and reads a `wallet_contract` row. This table
has none. The same check reads each row's Outputs cell against what its handler
answers: the error side is the `Response` serde tag and its `Error` fields, and
`data`'s children are the keys of that handler's one `json!`, in declaration
order. `operations_table_row_check_refuses_each_bad_table`, in
`../wallet-provider/tests/confine.rs`, refuses an Outputs cell that leaves a
key out, adds one, or writes another error name. The check also reads a
declared-right row's macOS cell for an allow form of that right, and a
`none: needs no declared right` row quotes none, so
`operations_table_row_check_refuses_each_bad_table` refuses a bad quote. The same
check holds each row's Effect cell against the right the row declares and the
dispatch class the contract's `class()` gives its kind: a
`none: needs no declared right` row names no canonical parameter and quotes no
allow form, and a `storage` row names `STORAGE_ROOT`. This table has no
`wallet_contract` row, so the class half of that rule has nothing to read here.
The rule reads the cells against that declared class; it does not show that a
handler writes only what its cell names.
`operations_table_row_check_refuses_each_bad_table` refuses a bad Effect cell. A
refusal under `(deny default)` is a denial, not a grant, and no row writes it
as a right. The
startup grants stay in "What the profile allows". A `storage` row cites both
sides of its right: `permitted:` names the test that shows the operation under
`STORAGE_ROOT`, and `nearest outside refused:` names the test that shows the
same file beneath `STORAGE_PARENT` refused, each with its falsifier ids. A row
whose Right is "no named test shows this" or `none: needs no declared right`
names no granted resource, so it has no outside case, and its cell cites only
the test that shows the answer and that test's falsifier.

M1 check B4 stays open: this table records the macOS half of its permission
model. Linux stays designed, not enforced, and this section claims no current
Linux behaviour. The design is `../wallet-provider/CONFINEMENT-LINUX.md`; its
tests do not exist yet. A JSON parse failure answers `parse_error`; it is not
an operation and gets no row.

| Operation | Inputs | Outputs | Right | Effect | macOS rule and test | Linux |
| --- | --- | --- | --- | --- | --- | --- |
| init | `op`, `config` | ok: `status`, `data` (`protocol_version`, `provider`). error: `status`, `code`, `message`. | `storage` | reads `did/nickname.enc` under `STORAGE_ROOT`; `tests/confine.rs::outside_read_denied` shows the read refused with `storage_error` when that path resolves outside. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows this call reading `did/nickname.enc` under `STORAGE_ROOT`, and its removal is DID10. nearest outside refused: the read half of `tests/confine.rs::planted_file_beneath_storage_parent_is_neither_read_nor_written` shows the same file beneath `STORAGE_PARENT` refused with `storage_error`, and the widened parent read is DID27. | designed, not enforced |
| get_did | `op` | ok: `status`, `data` (`did`). error: `status`, `code`, `message`. | none: needs no declared right | derives the DID from the device key in memory; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the answer; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call, and `DID31` is the plant that reaches this call. | designed, not enforced |
| resolve | `op`, `did` | ok: `status`, `data` (`public_key`, `document`). error: `status`, `code`, `message`. | none: needs no declared right | builds the document from the DID in memory; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the document id; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call. The only registered plants for this test are `DID31` in `get_did` and `DID32` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| sign_chat_message | `op`, `sender_id`, `ts`, `content` | ok: `status`, `data` (`payload`, `signature`). error: `status`, `code`, `message`. | none: needs no declared right | signs the rendered payload in memory; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the payload and the signature; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call. The only registered plants for this test are `DID31` in `get_did` and `DID32` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| verify | `op`, `did`, `data`, `signature` | ok: `status`, `data` (`valid`). error: `status`, `code`, `message`. | none: needs no declared right | verifies the payload in memory; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows `valid: true` and `valid: false` for a flipped signature; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call. The only registered plants for this test are `DID31` in `get_did` and `DID32` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| verify_did_recovery | `op`, `did`, `principal_id`, `localhost_root`, `protector_id`, `data_key_id`, `nonce`, `issued_at`, `expires_at`, `signature` | ok: `status`, `data` (`schema`, `valid`, `did`, `principal_id`, `localhost_root`, `protector_id`, `data_key_id`, `payload_sha256`, `verified_at`). error: `status`, `code`, `message`. | none: needs no declared right | refuses a non-hex signature with `invalid_signature` and stays in service; genuine-proof correctness is the in-process unit tests in `src/main.rs`; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::verify_did_recovery_under_profile` shows the refusal and the later `get_did`; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call. The only registered plants for this test are `DID31` in `get_did` and `DID32` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| get_nickname | `op` | ok: `status`, `data` (`nickname`). error: `status`, `code`, `message`. | none: needs no declared right | returns the cached nickname; the file read belongs to `init`, and `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the nickname after a restart; the read is `init`'s; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call. The only registered plants for this test are `DID31` in `get_did` and `DID32` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| set_nickname | `op`, `nickname` | ok: `status`, `data` (`nickname`). error: `status`, `code`, `message`. | `storage` | writes `did/nickname.enc` under `STORAGE_ROOT`; `tests/confine.rs::outside_write_denied` shows the write refused with `storage_error` outside the root. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the nickname written under `STORAGE_ROOT` and read back after a restart, and its removal is DID10. nearest outside refused: the write half of `tests/confine.rs::planted_file_beneath_storage_parent_is_neither_read_nor_written` shows the same file beneath `STORAGE_PARENT` refused with `storage_error`, and the appended parent write is DID28. | designed, not enforced |
| get_persona_did | `op`, `name` | ok: `status`, `data` (`did`, `owner_did`, `name`). error: `status`, `code`, `message`. | `storage` | reads or writes `did/personas/<name>.enc` under `STORAGE_ROOT`; `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows the file after the call and the same persona after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::confined_provider_serves_did_operations_under_its_root` shows `did/personas/fixture.enc` under `STORAGE_ROOT` after the call and the same persona after a restart, and its removal is DID10. nearest outside refused: `tests/confine.rs::persona_key_beneath_storage_parent_is_not_adopted` shows a persona key beneath `STORAGE_PARENT` refused with `key_error`, and the appended parent read is DID30. | designed, not enforced |
| shutdown | `op` | ok: `status`, `data` (`message`). error: `status`, `code`, `message`. | none: needs no declared right | answers and exits; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the call leaves the names under `did/` and the bytes of `did/nickname.enc` exactly as `init` and `set_nickname` left them. | `tests/confine.rs::bound_copy_serves_under_profile` shows the answer and a clean exit; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the storage tree after `init` and `set_nickname` is the same after this call, and `DID32` is the plant that reaches this call. | designed, not enforced |

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
This contract has no Linux enforcement of its file rows. A provider-status claim
needs host-specific test evidence and the Runtime acceptance step, so no status
document records `did-provider` or `wallet-provider` as confined on Linux (P10,
P11). The status change lands when the Runtime side does.

The shared seccomp journey has a did caller,
`linux_did_journey_runs_under_the_seccomp_allow_list`, in
`../wallet-provider/tests/confine.rs`. It builds did's list from did's own
committed declared-rights file through the one builder and requires the same
program as wallet. It starts did through the shared stand-in and installer and
requires `init`, `get_did` with a `did:key:` value, `resolve`, `set_nickname`,
`get_nickname` and `get_persona_did` to answer under that filter.
The did seccomp row awaits the shared policy owner's decision: the recorded
`spark1.local` run (`aarch64`, Ubuntu 24.04.4, kernel `6.17.0-1029-nvidia`)
needed `fchmodat` to save the nickname. The earlier successful run added that
permission to wallet's policy too. The shared table now preserves wallet's
policy, and the did test retains all its assertions. A fresh Linux run after the
policy decision is required for did acceptance.

No contract file row is enforced on Linux: a seccomp filter reads syscall numbers
and not paths, so the file rows stay open, and `linux` stays out of
`DECLARED_CONFINED_OS`. Namespaces, Landlock and capability dropping stay
unbuilt. The one Linux mapping is `../wallet-provider/CONFINEMENT-LINUX.md`, which
records the seccomp row, its host and its measured launch set; this document
claims no other Linux behaviour. The existing source-only check
`both_file_profiles_bind_one_storage_parameter_contract`, in
`../wallet-provider/tests/confine.rs`, reads the three oracles and supplies
contract evidence, not Linux execution evidence.

The file row has a did caller, `linux_did_file_row_is_refused_outside_storage_root`,
which is `linux_wallet_file_row_is_refused_outside_storage_root`'s one body with
did's own binary, did's own declared rights, did's own bindings and
`did_standin_permitted_operations` driven whole. `landlock_probe_paths_follow_the_bound_parameters`
holds on every OS that did's probe reads `<base>/did`, `<base>` and did's own
binary. The did half of that row is GAP. Task 160 ran it on `spark1.local`
(`aarch64`, Ubuntu 24.04.4, kernel `6.17.0-1029-nvidia`, Landlock ABI 7) and
recorded the cause in `../wallet-provider/CONFINEMENT-LINUX.md`: a launch needs
`READ_FILE` on `PROVIDER_EXECUTABLE` as well as `EXECUTE`, and the journey
requires the read of that file to be refused, so the shipped row starts
neither provider. Did's loader measurement against the one list is GAP too.

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

One rule, `profile_allow_table_problems`, under the test
`every_confinement_document_lists_its_profiles_allow_rules`, holds the listed
forms to `confine.sb`, and the reason column is not checked.

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

`persona_key_beneath_storage_parent_is_not_adopted` plants the provider's own
persona state at `<base>/sibling/did/personas/fixture.enc` through a confined
provider rooted at that sibling, so the planted key comes from the provider's
one path and no forged key enters the test. It then points
`<base>/did/personas/fixture.enc` at that file. Under the real profile the
parent read denies the planted file's stat, so `get_persona_did` answers
`key_error` with the failed-persist reason for the write through the link, and
neither the planted DID nor a change to the planted bytes comes back. After
the link is removed the same call creates the provider's own persona, a
different DID, and a following `get_did` answers ok. Appending a read grant on
`STORAGE_PARENT` makes this test fail because the planted key loads.

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

In the lab, did-provider also starts through the stand-in launcher in
`../wallet-provider/tests/confine.rs`.
`standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host` runs,
for did and then for wallet, that provider's macOS start and outside-write
journey and then that provider's host and process refusals, before the next
provider starts.
`standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
holds M1 check B3 for did first and then wallet: it reads the provider's
committed declared-rights file, starts the binary through the stand-in into a
fresh profile directory, reads the one generated profile the stand-in launched,
and compares that launched profile and the provider's permitted and denied
suite with the provider's committed `confine.sb`, case by case. did's suite
holds both targets of `outside_write_denied`, so the sibling write beneath the
same base separates a write grant on `did/` from one on its parent in the
comparison too.

The stand-in's input is one host report, not a bare OS name. The report holds
the OS name and which of Landlock, user namespaces or the seccomp filter it
reports unavailable. A host that reports a missing primitive is refused
whatever its OS. Each refusal starts
`{name} start on {os} is refused:` and carries only its own case's words: an OS
with no confinement design names that OS and the list where the stand-in
applies confinement; a host with a missing primitive carries
the design's exact words for it from
`../wallet-provider/CONFINEMENT-LINUX.md`; and a simulated Linux host that
reports nothing missing says Linux is designed, not enforced, in this lab, so
`linux` is not in `DECLARED_CONFINED_OS`. Those Linux rows are simulated host
reports and not a Linux run, so no test here probes a kernel or claims Linux
enforcement. The stand-in is test code and not the Runtime.

## M1 acceptance summary: C0 and B3

This section records the lab evidence for M1 checks C0 and B3 for
`did-provider`. It states what the evidence is and gives no verdict; cc-redteam
judges C0 and B3.

Pins: `e31f0f517a3364c6067b1989c1c985c21f823312` is a fixed commit on this lane; every `confine.rs` line number in this section is read with `git show e31f0f517a3364c6067b1989c1c985c21f823312:capsules/wallet-provider/tests/confine.rs`, each wallet `falsifiers.json` entry line in this section is read with `git show e31f0f517a3364c6067b1989c1c985c21f823312:capsules/wallet-provider/falsifiers.json`, and each file pin below is a commit that holds the file, read with `git show <commit>:<path>`.

Gap (#309, routed to Flint): draft PR #309 at 513988ebd names no provider-launch ask, so this launcher has no RA route to copy, and M1-R for C0 and B3 waits on that ask.

Launcher copy: `standin_spawn_confined_provider` is still a lane copy in `capsules/wallet-provider/tests/confine.rs`. Flint and Rong (2026-10-27 19:25) ruled the copy not acceptable; it is to move under the one shared stand-in, `lab/agent-conformance/standin-runtime/`, owned by cx-agent-conformance. The evidence here runs through the copy, and the move is not done.

### C0 part

Written sentence: One C0 journey starts `did-provider` and `wallet-provider`
confined through the lab stand-in on macOS, or the stand-in refuses each host
and process it cannot confine with its own reason and starts no provider.

Counting rule, as `lab/redteam/acceptance/C8.md` words it: a complete journey, a
refusal with a reason, a CAUGHT falsifier, and reviews that pass.

Journey test: `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host`
in `capsules/wallet-provider/tests/confine.rs` at
`16c4997d20b332d5e5f82999a10a035fcee6a3ab` (line 4165). It runs did first and
then wallet. Its macOS leg is `standin_confined_journey` (line 3999): it starts
the provider under the stand-in's generated profile, refuses one outside write
with nothing created, keeps the root answering, and exits 0 on `shutdown`. Its
refusal rows call `standin_refusals_for` (line 3657), which reads one host
report through `standin_host_refusal` (line 904) and the launch through
`standin_spawn_confined_provider` (line 971).

Files at their commits:

- `capsules/wallet-provider/tests/confine.rs` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`, the journey test and the stand-in.
- `capsules/did-provider/tests/fixtures/confine/declared-rights.json` at
  `7c5a31a956bec77db60c9d03c77d05ce6704852a`.
- `capsules/wallet-provider/tests/fixtures/confine/declared-rights.json` at
  `9bb0e9ba4debac4a78b512156841f1594d9bb8a4`.
- `capsules/wallet-provider/falsifiers.json` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`.
- `lab/agent-conformance/standin-runtime/README.md` at
  `cccbd8ceb2fde5c2c3eda59ff932d09b33fc1592` answers the stand-in's routes and
  names no provider-launch route.

Refusals, with the reason the code produces and what the journey row checks for
`did-provider`. The wallet leg checks the same strings with `wallet-provider` in
place of `did-provider`. The first eight rows, `standin_refusals_for`'s cases
(a) to (c2), check the `{name} start on {os} is refused: ` prefix and the named
parts, and require the forbidden parts absent (lines 3776-3790); cases (c3),
(e) and (f) check no prefix.

- plan9 row: the code produces `did-provider start on plan9 is refused: plan9 has no confinement design, and the lab stand-in applies confinement only on macos`; the row checks the prefix and the parts `plan9`, `has no confinement design` and `macos`, and requires none of `linux is designed, not enforced`, `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: user namespaces are turned off` or `linux confinement refused: the seccomp filter cannot be installed`.
- Linux without Landlock: the code produces `did-provider start on linux is refused: linux confinement refused: the kernel has no Landlock`; the row checks the prefix and that part, and requires none of `linux confinement refused: user namespaces are turned off`, `linux confinement refused: the seccomp filter cannot be installed`, `linux is designed, not enforced` or `has no confinement design`.
- Linux without user namespaces: the code produces `did-provider start on linux is refused: linux confinement refused: user namespaces are turned off`; the row checks the prefix and that part, and requires none of `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: the seccomp filter cannot be installed`, `linux is designed, not enforced` or `has no confinement design`.
- Linux without the seccomp filter: the code produces `did-provider start on linux is refused: linux confinement refused: the seccomp filter cannot be installed`; the row checks the prefix and that part, and requires none of `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: user namespaces are turned off`, `linux is designed, not enforced` or `has no confinement design`.
- Linux with every primitive reported present: the code produces `did-provider start on linux is refused: linux is designed, not enforced, in this lab, so linux is not in DECLARED_CONFINED_OS (macos)`; the row checks the prefix and the parts `linux is designed, not enforced` and `not in DECLARED_CONFINED_OS`, and requires none of `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: user namespaces are turned off`, `linux confinement refused: the seccomp filter cannot be installed` or `has no confinement design`.
- macOS whose report leaves Landlock unavailable: the code produces `did-provider start on macos is refused: linux confinement refused: the kernel has no Landlock`; the row checks the prefix and the parts `linux confinement refused: the kernel has no Landlock` and `on macos`, and requires none of `linux confinement refused: user namespaces are turned off`, `linux confinement refused: the seccomp filter cannot be installed`, `linux is designed, not enforced` or `has no confinement design`.
- macOS without the tool: the code produces `did-provider start on macos is refused: the confinement tool <capsules/wallet-provider/tests/absent-sandbox-exec> is absent`; the row checks the prefix and the parts `on macos`, `is absent` and that path, and requires that the reason holds no `/usr/bin/sandbox-exec`.
- macOS with another tool: the code produces `did-provider start on macos is refused: the confinement tool <the test executable path> is not /usr/bin/sandbox-exec, which is the one the stand-in runs`; the row checks the prefix and the parts `on macos`, that path and `/usr/bin/sandbox-exec`.
- A binary path that is not a file: the code produces `did-provider start is refused: the provider binary <capsules/wallet-provider/tests/absent-provider-binary> is not a file`; the row checks the provider name and that path in the reason and requires no `must resolve` (lines 3835-3841), and it checks no prefix.
- An unnamed right: the code produces `did-provider declares unnamed-right, which the shared contract does not name`; the row compares the whole string exactly (lines 3882-3886).
- A profile the launch cannot apply: the code produces `did-provider start is refused: <failure>`; the row checks that the failure carries `exit status:` and `invalid data type of path filter` and requires no `execvp` (lines 3932-3942), and it checks no prefix.
- An `init` answer that is not ok: the code produces `did-provider start is refused: init answered <answer>`; the row checks that the reason carries `init answered` and `"status":"error"` (lines 3970-3976), and it checks no prefix.

CAUGHT falsifiers. Each entry is in `capsules/wallet-provider/falsifiers.json`
at `16c4997d20b332d5e5f82999a10a035fcee6a3ab`; wallet's crate holds the stand-in
and its list. The gate logs of PR #561, PR #607, PR #643, PR #692 and PR #710
are not part of this tree, so this summary quotes no raw `CAUGHT` line for those
runs. One hand run of `examples/agent-host/falsify.py --from
capsules/wallet-provider/falsifiers.json WP132 WP135 WP136 WP137` at
`606956b3dded92b183c56472b447b96fe0204a61` printed `CAUGHT` for all four; the
other entries were not rerun. The evidence read for each entry is its `expect`
of `caught`, its only named test
`standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host`, and the
plant named on its line.

- `WP112` (entry line 1798, PR #561, not rerun): starts the binary bare in the
  host refusal, so case (a) returns Started.
- `WP113` (entry line 1814, PR #561, not rerun): starts the binary bare after a
  failed `init`, so case (e) returns Started.
- `WP114` (entry line 1830, PR #561, not rerun): starts the binary without the
  generator and `sandbox-exec`, so the macOS leg succeeds at the outside write.
- `WP115` (entry line 1846, PR #561, not rerun): ignores the writer's refusal
  and starts under the committed `confine.sb`, so case (d) returns Started.
- `WP118` (entry line 1894, PR #607, not rerun): removes the check that the
  tool is `SANDBOX_EXEC`, so case (c2) is Started.
- `WP119` (entry line 1910, PR #607, not rerun): removes the binary-file check,
  so case (c3) panics in `resolved`.
- `WP120` (entry line 1926, PR #607, not rerun): answers `Ok(provider)` for an
  `init` that is not `ok`, so case (f) is Started.
- `WP125` (entry line 2006, PR #643, not rerun): makes the absent-tool check
  never fire, so case (c) reads the wrong-tool reason.
- `WP126` (entry line 2022, PR #643, not rerun): drops the OS from the
  wrong-tool reason, so case (c2) loses `on macos`.
- `WP131` (entry line 2102, PR #692, not rerun): starts the binary bare on a
  simulated Linux host that reports a missing primitive, so did's Landlock row
  returns Started.
- `WP132` (entry line 2118, PR #692, re-anchored by PR #710, rerun at
  `606956b3d`): returns one fixed reason that names no primitive, so did's
  Landlock row loses the design's exact words. The hand run printed
  `WP132  CAUGHT                             2s  the missing-primitive refusal returns one fixed reason that names no primitive`.
- `WP135` (entry line 2166, PR #710, rerun at `606956b3d`): moves the
  `DECLARED_CONFINED_OS` lookup above the missing-primitive check, so did's
  `macos` Landlock row returns Started where `sandbox-exec` exists.
- `WP136` (entry line 2182, PR #710, rerun at `606956b3d`): prefixes the
  missing-primitive reason with `linux has no confinement design; `, so did's
  Landlock row carries the forbidden words.
- `WP137` (entry line 2198, PR #710, rerun at `606956b3d`): drops the `{name}
  start on {os} is refused: ` prefix, so the plan9 row lacks it.

Reviews. Read with `gh pr view <number> --repo
Elacity/elastos-agent-host-spike --json body,mergeCommit`; each merge commit is
an ancestor of `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. Each PASS line is
the pull request body, which states the reviews as passed; no reviewed SHA is
recorded in it.

- PR #561, https://github.com/Elacity/elastos-agent-host-spike/pull/561, merge
  `fc9cefc40a0d1ac29de5b985d53c54c96972b104`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #607, https://github.com/Elacity/elastos-agent-host-spike/pull/607, merge
  `aca346f10c47812aa8bbed616a7b1b1b7ac2accf`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #643, https://github.com/Elacity/elastos-agent-host-spike/pull/643, merge
  `5d8ba7997d598d952b432f7cd1adf9b0c38bb04e`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #672 (task 102; WP127's records say where it fails), https://github.com/Elacity/elastos-agent-host-spike/pull/672, merge `652cf3bd5c41fd080508662550005ead562512d4`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`
- PR #692, https://github.com/Elacity/elastos-agent-host-spike/pull/692, merge
  `705e4fbbdfaef640a51f5c707069a4a5e7564c5b`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #710, https://github.com/Elacity/elastos-agent-host-spike/pull/710, merge
  `b7ade04219ceb5d5affc567bd745a3a1cbe73006`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #725 (task 109), https://github.com/Elacity/elastos-agent-host-spike/pull/725, merge `606956b3dded92b183c56472b447b96fe0204a61`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`

What this part is not: it is lab stand-in evidence, not the Runtime. The Linux
rows are simulated host reports, not a Linux run. M1-R is not met because #309
has no provider-launch ask.

### B3 part

Written sentence: One B3 journey starts each provider from its committed
declared-rights file through the lab stand-in into a fresh profile directory,
reads the one file the stand-in wrote there, and requires that launched profile
and the provider's permitted and denied suite to match the provider's committed
`confine.sb`, case by case.

Counting rule, as `lab/redteam/acceptance/C8.md` words it: a complete journey, a
refusal with a reason, a CAUGHT falsifier, and reviews that pass.

Journey test: `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
in the same file at `16c4997d20b332d5e5f82999a10a035fcee6a3ab` (line 4875). Its
leg is `standin_b3_journey` (line 4780). The launched-profile checks are
`check_profile_contract` (line 5564), `check_declared_rights` (line 5686) and
`compare_profile_to_its_oracle` (line 6604). The suite comparison is
`assert_suite_outcomes` (line 4676) and `assert_standin_matches_oracle` (line
4716). It runs did first and then wallet.

Files at their commits:

- `capsules/wallet-provider/tests/confine.rs` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`, the journey test and the
  comparison body.
- `capsules/did-provider/confine.sb` at
  `959b104022bd0e8ae55636f69f6f06b8eb028e2b`.
- `capsules/wallet-provider/confine.sb` at
  `959b104022bd0e8ae55636f69f6f06b8eb028e2b`.
- `capsules/did-provider/tests/fixtures/confine/declared-rights.json` at
  `7c5a31a956bec77db60c9d03c77d05ce6704852a`.
- `capsules/wallet-provider/tests/fixtures/confine/declared-rights.json` at
  `9bb0e9ba4debac4a78b512156841f1594d9bb8a4`.
- `capsules/wallet-provider/falsifiers.json` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`.

Refusals, with the message the code writes for `did-provider`: each quoted line
is the panic's own message, and the panic prints it with Rust's frame. The
`assert_eq!` rows (order or class, case count, entry, extra entries) print it
after Rust's ``assertion `left == right` failed: `` and before the left/right
lines. `assert_suite_outcomes` checks the record under the committed
`confine.sb` with the label `<name>'s committed confine.sb` first (lines
4826-4830), so a change that breaks both records panics with that label in place
of `<name>'s stand-in launched profile`; the stand-in label (lines 4831-4835),
which the lines below quote, shows when only the launched profile differs. The
wallet leg asserts the same strings with `wallet-provider` in place of
`did-provider`.

- Launched-profile mismatch, contract check: `did-provider B3 journey: the launched profile must pass the contract check: did-provider must deny the network explicitly with (deny network*)`.
- Launched-profile mismatch, declared-rights check: `did-provider B3 journey: the launched profile must trace to its declared rights: did-provider allow rule has no declared right and no platform-baseline rule: <appended allow form>`.
- Launched-profile mismatch, oracle comparison: `did-provider B3 journey: the launched profile and its oracle disagree: did-provider generated profile differs from its committed oracle: only in generated <forms>, only in committed <forms>`.
- Suite mismatch, case count: `did-provider stand-in start must record as many cases as the committed confine.sb: committed <count>, stand-in <count>`.
- Suite mismatch, entry: `did-provider stand-in start differs from the committed confine.sb on case "<case>": committed <outcome>, stand-in <outcome>`.
- Suite mismatch, short record: `did-provider's stand-in launched profile suite must record case "<case>" as <class>: the record holds N entries`, where N is the record's length (lines 4679-4682).
- Suite mismatch, order or class: `did-provider's stand-in launched profile must record case "<case>" as <class>` (lines 4684-4688).
- Suite mismatch, permitted case not `ok`: `did-provider's stand-in launched profile must permit case "<case>": <outcome>` (lines 4690-4695).
- Suite mismatch, denied case not refused: `did-provider's stand-in launched profile must refuse case "<case>": <outcome>` (lines 4696-4701).
- Suite mismatch, extra entries: `did-provider's stand-in launched profile suite must record no case beyond Some("<case>")` (lines 4704-4709), where `cases.last()` is an `Option`, so `{:?}` prints `Some("<case>")`.

CAUGHT falsifiers. Each entry is in `capsules/wallet-provider/falsifiers.json`
at `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. The gate logs of PR #593, PR
#624, PR #635, PR #655, PR #704 and PR #718 are not part of this tree, so this
summary quotes no raw `CAUGHT` line and did not rerun a plant. The evidence read
for each entry is its `expect` of `caught`, its only named test
`standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`, and
the plant named on its line. Each line cites the check that catches it, as the
merged words of PR #718 say.

- `WP116` (entry line 1862, PR #593, not rerun): binds the stand-in's
  `STORAGE_ROOT` to the base; the widened grant permits did's sibling write, so
  the suite step fails there.
- `WP121` (entry line 1942, PR #624, not rerun): removes the planted-key push,
  so wallet's record holds eight entries where `SUITE_CASES` holds nine.
- `WP124` (entry line 1990, PR #635, not rerun): uses wallet's root layout for a
  did start, so did's first `init` is refused.
- `WP127` (entry line 2038, PR #655, not rerun): appends `(allow file-write* (subpath (param "STORAGE_PARENT")))` to did's launched profile; `check_declared_rights` catches it at did's launched-profile check, and the suite never starts.
- `WP133` (entry line 2134, PR #704, not rerun): appends `(allow file-read* (literal "/private/etc/hosts"))` to the launched profile; `check_declared_rights` catches it at that same check, and no suite case reads that path.
- `WP134` (entry line 2150, PR #704, not rerun): removes `(deny network*)` from the launched profile; `check_profile_contract` catches it at that same check.
- `WP138` (entry line 2214, PR #718, not rerun): appends `(deny file-write* (literal "/private/var/cc-confine-launched"))` after the writer; only `compare_profile_to_its_oracle` catches it, because the head keeps its order and neither contract check reads a deny form.

Reviews. Read with `gh pr view <number> --repo
Elacity/elastos-agent-host-spike --json body,mergeCommit`; each merge commit is
an ancestor of `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. Each PASS line is
the pull request body, which states the reviews as passed; no reviewed SHA is
recorded in it.

- PR #593, https://github.com/Elacity/elastos-agent-host-spike/pull/593, merge
  `693c3681db472d565a2ce07abc9ec2c9a7e0b7e0`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #624, https://github.com/Elacity/elastos-agent-host-spike/pull/624, merge
  `eb92d432778dcdeb5476e35e10f822dd74c6ab9b`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #635, https://github.com/Elacity/elastos-agent-host-spike/pull/635, merge
  `3bfc39b026c86f0bf549fa2b8b53965c955418c2`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #655, https://github.com/Elacity/elastos-agent-host-spike/pull/655, merge
  `62eac8742bb84ec1106159a6c1e5bba988476d9a`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #672 (task 102; WP127's records say where it fails), https://github.com/Elacity/elastos-agent-host-spike/pull/672, merge `652cf3bd5c41fd080508662550005ead562512d4`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`
- PR #704, https://github.com/Elacity/elastos-agent-host-spike/pull/704, merge
  `978873050f6dc3884cef117e39d4345e38d7fb2c`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #718, https://github.com/Elacity/elastos-agent-host-spike/pull/718, merge
  `345697ee3a954e140700033775bad1349587c513`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #725 (task 109), https://github.com/Elacity/elastos-agent-host-spike/pull/725, merge `606956b3dded92b183c56472b447b96fe0204a61`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`

What this part is not: it is lab stand-in evidence, not the Runtime. The Linux
rows are simulated host reports, not a Linux run. M1-R is not met because #309
has no provider-launch ask.

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
  `confined_provider_serves_did_operations_under_its_root`,
  `outside_write_denied` and
  `persona_key_beneath_storage_parent_is_not_adopted` fail because the
  identity write is denied; the persona case fails when the first provider
  cannot persist its own persona key.
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
- Append a read grant on `STORAGE_PARENT` after the storage-root rule (DID30):
  `persona_key_beneath_storage_parent_is_not_adopted` fails on its refusal
  assertion because the planted persona key loads and answers ok with the
  planted DID.
- Read `/etc/hosts`, outside every grant, in `get_did`'s ok arm and answer
  `storage_error` when that read is denied (DID31): the `storage_error`
  refusal replaces the ok answer, so
  `no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged`
  fails on its first answer.
- Write one file into the provider's own storage root in the `Request::Shutdown`
  arm of `fn handle` before it answers (DID32):
  `no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged`
  fails on its final compare after `shutdown`, because the root holds a name
  that `init` and `set_nickname` did not leave.

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
