# model-provider confinement

`confine.sb` is the one oracle for the model provider's confinement profile
(one file, P10): the profile the Runtime generates for this provider must match
it. That Runtime half is not built. It starts with `(version 1)`, then
`(deny default)`, then `(deny network*)`. The provider reads line-delimited
JSON on stdin and writes one JSON answer per line on stdout. The profile
grants it no socket and no listener. Every operation that no rule grants is
refused (P3, P11).

## Parameters

This file uses only the three parameter tokens every file profile binds. The
generated profile binds the same three, and the tests pass them with
`sandbox-exec -D`. The Runtime half that binds them is not built.

- `PROVIDER_EXECUTABLE`: the canonical path of the provider binary.
- `STORAGE_ROOT`: the model journal root. That is
  `Init.base_path/providers/model-provider`, or the configured absolute
  `journal_dir`.
- `STORAGE_PARENT`: the parent of `STORAGE_ROOT`. The tests create it before
  launch. `model_provider_ops_under_profile` shows the provider then creates
  `STORAGE_ROOT` itself at its first `init`. The Runtime half does the same
  before launch and is not built.

All three are resolved paths. The sandbox matches the resolved path, so a
path through a link (macOS `/var` is `/private/var`) would match nothing.

## The Runtime half

The model provider presents the same file-profile contract as `did-provider`
and `wallet-provider`, as an oracle: one profile file, the same head forms,
the same three parameter tokens and the same three shared rules. Its Runtime
half is "The Runtime bridge change" in `../did-provider/CONFINEMENT.md` and
`../wallet-provider/CONFINEMENT.md`: the Runtime generates each provider's
profile from its approved declared rights, one generator covers
`model-provider` too, and the profile it generates for this provider must
match this file, with the same three parameters bound to the same paths. The
test that compares them is the Runtime's half. That half is not built. The
model provider needs nothing from the Runtime beyond that one generator and
that comparing test, and there is no separate Runtime proposal for the model
provider (P10). The `sandbox-exec -f confine.sb` launch is the tests' launch
(see "Tests"), not the Runtime's.

## What the profile allows

Each rule is load-bearing: removing it alone makes
`model_provider_ops_under_profile` fail, as the named falsifier shows.

| Rule | Why the provider needs it | Without it |
| --- | --- | --- |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | Start only the binary bound as `PROVIDER_EXECUTABLE`; see "Starting other programs". | F-cc1-rm-exec: `sandbox-exec` cannot execute the binary and exits 71. |
| `(allow file-read-data (literal "/"))` | Process startup reads the root directory before `main` runs; `/bin/echo` aborts the same way without it, so this is not provider code. A metadata-only grant is not enough. | F-cc1-rm-rootdir: the process aborts (SIGABRT) before its first answer, with no output. |
| `(allow sysctl-read)` | At startup the Rust runtime reads the page size to place its stack guard page. These are read-only kernel facts. | F-cc1-rm-sysctl: the runtime panics with "failed to allocate a guard page" before `main` and the process aborts (SIGABRT). |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | `init` inspects the existing parent before it creates the journal root. The grant is literal: the parent directory itself, nothing below it. | F-cc1-rm-parent: `init` answers `journal_corrupt`; the provider logs EPERM for the parent. |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | One grant covers the journal root, `runs/` and every run record under it. | F-cc1-rm-storage: `init` answers `journal_access_denied` (provider task 012); the provider logs EPERM creating the journal root. |

There is no `(allow default)`, no network allow, no unfiltered `file-read*`
and no `(subpath "/")`.

The did and wallet profiles were the starting set. These startup grants from
that set are not in this profile, because the provider starts and serves
`init`, `status` and `offers_list` without them, and
`model_provider_ops_under_profile` passes: a read of the provider binary
itself, reads under `/usr/lib`, `/System/Library` and `/Library/Apple`, and
access to `/dev/null` and `/dev/urandom`. The root directory read is narrowed
from the starting set's `file-read*` to `file-read-data`, the one class that
startup needs.

`(deny network*)` is held by the shared contract check, not by a behaviour
test here (see Tests): F-cc12a removes it, and that check fails (see
Falsifiers). With that one form removed, `(deny default)` still
refuses the hosted run's connect, and
`model_hosted_run_fails_closed_under_profile` still passes. The profile's
refusal of a network operation is now also shown by behaviour: that test and
F-cc10b, which turns `(deny network*)` into `(allow network*)` (see "What the
profile does not grant").

## Reads outside the storage root

Outside `STORAGE_ROOT` the profile allows only the startup reads (the root
directory `/` and kernel facts) and the `STORAGE_PARENT` directory itself,
nothing below it. `(deny default)` refuses every other read, including the
contents of every file outside the root. So the provider cannot adopt or
disclose state it was not granted (P3, P11). A run record outside the root can
be neither read nor returned. An outside journal root cannot even be inspected
(`model_outside_write_denied`).

`model_outside_read_denied` proves this with the provider's run read,
`runs_get`. `RunJournal::load_run` in `src/journal.rs` serves it. It first
checks that the run record exists and is a private regular file, then opens
the record and reads its contents.

- A first launch under `confine.sb` stores one run of the hosted offer with
  `runs_create` and reads it back with `runs_get`. The binary refuses hosted
  dispatch before any socket, so the run is stored as failed and needs no
  backend. This is a real content read inside the root.
- A second launch runs a test-time copy of `confine.sb` with one fixture
  rule: `file-read-metadata` of the record at its outside path. Under the real
  profile even that metadata is refused. The rule lets `runs_get` pass its
  existence checks, so the refused operation is the open that reads the
  record. The fixture adds no content read and no write.
- After `init`, the test moves `STORAGE_ROOT/runs` to
  `STORAGE_PARENT/outside/runs`, under `outside`, a sibling of the journal
  root, and links `STORAGE_ROOT/runs` to it. The record's path still names a
  place inside the root, but it leads outside. The link comes after `init`
  because the provider itself refuses a symlinked run directory at `init`; the
  test needs the sandbox to decide.
- The same `runs_get` answers `journal_corrupt` with no run data. The provider
  logs `failed to open model run journal: Operation not permitted`. The
  outside sibling keeps its entries and bytes, and the provider still answers
  `offers_list`. With the link removed and the directory moved back,
  `runs_get` returns the stored run again.

This test has no unconfined control. F-cc1c (see Falsifiers) is the evidence
that the profile refuses the read: with the `STORAGE_PARENT` read widened to
its subtree, the same `runs_get` returns the run.

## Writes outside the storage root

The profile grants writes only under `STORAGE_ROOT`. Two confined tests send
the same redirected `init`: `STORAGE_ROOT/escape` is a link to
`STORAGE_PARENT/outside`, a sibling of the journal root, and the journal path
`STORAGE_ROOT/escape/inner` leads to the existing directory `outside/inner`.
`RunJournal::open` in `src/journal.rs` inspects the journal root and then
`runs/`, and creates a missing `runs/`. Each test watches one refused step:

- The profile refuses the metadata inspect of the outside path, before any
  write. `init` answers `journal_corrupt`. Test: `model_outside_write_denied`.
- When only a metadata read of the outside path is added, the sandbox refuses
  the journal create, and the provider reports `journal_access_denied`
  (provider task 012). It logs the create of `<journal_dir>/runs` with
  `Operation not permitted`. Test:
  `model_outside_create_reports_access_denied`.

The second test runs a test-time copy of `confine.sb` with one fixture grant:
`file-read-metadata` of `outside/inner`, bound as a resolved path. It is
metadata only. The fixture adds no content read and no write. The inspect of
`runs/`, which does not exist yet, needs no grant: the sandbox answers it with
not-found. The test also checks that the outside sibling keeps its entries,
modes and bytes, and that a later normal `init` on `STORAGE_ROOT` succeeds.

`redirect_journal_materializes_outside_when_unconfined` is the control for
both tests: the same fixture and request without a profile create the journal
under the outside sibling. F-cc8c (see Falsifiers) keeps `(deny default)` and
every rule, and adds only a write grant on `STORAGE_PARENT`. The create then
succeeds and `runs/` appears under the outside sibling, so the second test
fails: it watches the write grant itself. `model_outside_write_denied` still
passes under F-cc8c, because it is refused at a read.

## Starting other programs

The exec rule, `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))`,
lets the process execute only the path bound as `PROVIDER_EXECUTABLE`.
`sandbox-exec` applies the profile to its own process before it executes the
program it was given. So the same rule checks that first exec and any exec by
the confined provider, and a test can check the rule without the provider
creating a process.

`model_unbound_program_refused_under_profile` runs under `confine.sb` itself,
with no fixture rule. It creates `STORAGE_ROOT` owner-only and copies the
provider binary into it, the one place the profile lets the provider write.
The copy has the same SHA-256 as the binary. The test binds the real binary as
`PROVIDER_EXECUTABLE`, binds the two storage parameters as usual, and starts
the copy. The profile refuses the exec:

- `init` gets no answer;
- `sandbox-exec` exits with status 71 and logs
  `sandbox-exec: execvp() of '<copy>' failed: Operation not permitted`;
- nothing is written: `STORAGE_ROOT` holds only the copy, with the same mode
  and bytes, and there is no `runs/`.

A missing program also exits 71, but with `No such file or directory`, so the
test checks the EPERM line.

`model_bound_copy_serves_under_profile` is the control. It makes the copy the
same way, at the same place under `STORAGE_ROOT`, binds it as
`PROVIDER_EXECUTABLE` and starts it under the same profile. The copy answers
`init` with its offer ready, creates `runs/` beside itself, and exits cleanly
after `shutdown`. The binding is the only difference between the two runs. So
a program in the provider's own storage cannot run, and only the bound path
runs. Which binary is bound is the Runtime half (see "The Runtime half");
these tests do not check it.

F-cc14b adds one line, `(allow process-exec)`, after the exec rule, and F-cc14c
adds `(allow process-exec (subpath (param "STORAGE_ROOT")))`. Both keep the
exec rule word for word, so both pass the one shape check,
`both_file_profiles_bind_one_storage_parameter_contract`: it requires the exec
rule, but it does not refuse a second, wider exec rule. Under each, the copy
starts and answers `init`, and of the `confine` tests only
`model_unbound_program_refused_under_profile` fails. So this test is the check
that holds the limit. F-cc14a, `(allow default)`, fails it the same way.

## When the profile cannot be applied

`startup_is_refused_when_the_profile_cannot_be_applied` starts the provider
through the one launcher in three cases: a profile path that does not exist,
a copy of `confine.sb` with its last `)` removed, and `confine.sb` itself
with every parameter bound except `STORAGE_ROOT`. In each case
`sandbox-exec` exits 65 before it executes the provider and gives its reason
in one stderr line:

- `sandbox-exec: <path>: No such file or directory`
- `sandbox-exec: syntax error: expecting ')'`
- `sandbox-exec: invalid data type of path filter; expected pattern, got boolean`

`init` gets no answer, and nothing is written. `STORAGE_PARENT` stays empty,
because the provider never creates `STORAGE_ROOT`.

Exit 65 means the profile never applied. Exit 71, in "Starting other
programs", means the profile applied and refused the exec.

The launcher starts the provider no other way, as F-cc19a shows. The reason
reaches the test through the launcher's stderr channel, as F-cc19b shows.
For the Runtime's refusal of such a start, see "The Runtime bridge change"
in `../did-provider/CONFINEMENT.md`. That bridge change is not built: the
Runtime half that generates and enforces the profile is future work in
`elastos/`, outside this lane.

## What the profile does not grant

### The local engine

A local model run needs three things, and this profile grants none of them:

- Reads of the engine and model files under `base_path`, outside
  `STORAGE_ROOT`. The `init` check reads them (`src/config.rs:815`), and so
  does the run's hash (`src/config.rs:858`).
- Executing the configured engine. `PROVIDER_EXECUTABLE` covers the guard,
  which re-executes the provider binary (`src/local_llama.rs:550`), but not
  the engine itself.
- The engine transport: a loopback port the provider reserves for each start
  (`src/local_llama.rs:704`), or the Unix socket an init config passes in
  `runtime_local_sockets`.

The first step the profile refuses is `init`, so no run, engine start or port
is ever reached. The `init` check resolves `base_path` before it reads either
file, and the profile grants no read of `base_path` or of the directories
above it. `init` answers `status: error`, `code: internal_error`,
`message: model provider failed`, and the provider logs
`[model-provider] internal_error: invalid model provider init config: base_path is unavailable`.
The check runs before the journal opens, so nothing is written, not even
`STORAGE_ROOT`. The provider stays in service: a later `init` with the hosted
offer succeeds.

- `model_local_offer_fails_closed_under_profile` proves this under the
  profile. It also checks that the engine and model folders keep their
  entries and bytes.
- `model_local_offer_accepted_when_unconfined` is the control: the same
  `init` without the profile answers `status: ok` with the offer ready.

The provider drops the OS error at that step, so the log line carries no
EPERM. Three things show that the sandbox refused, not a bad fixture: the
control, F-cc7a (`(allow default)`) and F-cc7b, which keeps `(deny default)`
and adds only `(allow file-read*)`. Under each falsifier the same `init`
answers `ok`. So the first engine need this profile does not grant is a read.

The storage operations work under this profile; a configuration with a local
model offer does not. Do not use this profile for a provider configured with a
local model offer.

Granting the engine is an open decision for Sasha and Rong. A grant that lets
a local run complete changes the shared file-profile contract: its one check,
`both_file_profiles_bind_one_storage_parameter_contract` (see Tests), and its
Runtime half, "The Runtime bridge change" in `../did-provider/CONFINEMENT.md`.
The Runtime half of any extension is Anders's (P4). Until the decision lands,
this profile has no engine grant, and
`model_local_offer_fails_closed_under_profile` holds the edge closed.

### The hosted transport

On macOS a hosted run goes ahead only when the init config names the
Runtime-owned Unix socket in `runtime_hosted_socket`
(`src/config.rs:111-113`). Without it, the provider refuses every hosted
adapter itself, before any socket (`require_external_http_containment`,
`src/adapters.rs:111-128`, and
`production_provider_refuses_every_external_adapter_before_socket_and_after_restart`
in `tests/process.rs`). That refusal is the provider's, not the sandbox's.
With the socket named, the run sends its effect request,
`POST /v1/hosted-effect` with the `x-elastos-*` headers, over that socket
(`effect_request` and `backend_client_with_socket`,
`src/adapters.rs:45-100`). The profile refuses that connect.

The run fails closed. `runs_create` answers `status: ok`, and the run then
settles as `status: failed` with `code: transport_interrupted`,
`message: model backend transport was interrupted` (`map_reqwest_failure`,
`src/adapters.rs:2773-2785`). It settles within `FIXTURE_EVENT_TIMEOUT`, so it
does not hang. The one wait loop holds that bound. It checks the deadline
after every reply, terminal or not, before it returns the run, and it gives
each poll only the time left, on the one receive of the request path.
`hosted_run_wait_fails_a_reply_after_its_deadline` and
`hosted_run_wait_times_out_without_a_reply` prove it (see Tests). Nothing
reaches the socket, and the provider stays in service:
`offers_list` answers and `shutdown` exits cleanly. The provider logs no
adapter fault, so the evidence is the run's terminal error, the socket's
count of connections and the control.

- `model_hosted_run_fails_closed_under_profile` proves this under
  `confine.sb` itself, with no fixture rule and the three parameters bound.
  The socket is a stand-in that the test binds under `/tmp`: the
  provider refuses a socket path of 104 bytes or more
  (`src/config.rs:163-167`), and a path under the test's temporary root comes
  close to that. The stand-in counts every connection when it accepts it,
  before it reads anything, and it reads each request on that connection's
  own thread, so a connection that sends nothing holds up no other. After
  the run settles, the test's final read first takes every connection still
  queued on the listener. On macOS a Unix socket `connect` returns once the
  connection is queued, so by then each connection the provider made is
  counted, as long as no `accept` failed. A failed `accept`, as for a
  connection that gave up before it was accepted, counts nothing and ends
  that pass. Under the profile the count is zero.
- `model_hosted_run_reaches_runtime_socket_when_unconfined` is the control:
  the same fixture and requests without the profile. The stand-in counts one
  connection, and its one request line starts with
  `POST /v1/hosted-effect `. The stand-in answers `403` with
  `X-Elastos-Hosted-Access: refused`, which the provider reads as the
  Runtime's refusal before dispatch (`map_effect_http_status`,
  `src/adapters.rs:2799-2834`), and the run settles as
  `hosted_effect_refused`. Off macOS the provider refuses every hosted run
  itself, so there the control prints a skip reason.

F-cc10b turns `(deny network*)` into `(allow network*)` and changes nothing
else. The request then reaches the stand-in, and the confined test fails. So
the network denial alone holds this edge; it is the widening a hosted grant
would add. F-cc10a, `(allow default)` with `(deny network*)` removed, fails
the test the same way. `(allow default)` alone does not, because
`(deny network*)` still refuses the connect.

Three tests check the stand-in's count itself, with no provider and no
sandbox (see Tests):

- `runtime_socket_stand_in_counts_a_silent_connection` counts a client that
  sends nothing (F-cc15a).
- `runtime_socket_stand_in_drains_queued_connections` stops the accept loop
  before its two clients connect, so only the final read can take them, and
  it counts both (F-cc15b).
- `runtime_socket_stand_in_accepts_behind_a_silent_connection` shows that a
  silent connection does not hold up the next one (F-cc15c).

With any one of those three edits applied,
`model_hosted_run_fails_closed_under_profile` and its control still pass, so
these three tests are the checks that hold the count.

With this profile no model run completes, local or hosted. Only the storage
operations work.

Granting this transport is part of the same open decision for Sasha and Rong
as the local engine. It touches the same two places: the shared check,
`both_file_profiles_bind_one_storage_parameter_contract` (see Tests), and "The
Runtime bridge change" in `../did-provider/CONFINEMENT.md`. The Runtime half
of any extension is Anders's (P4). Hosted routing is not decided here. Until
the decision lands, this profile has no network grant, and
`model_hosted_run_fails_closed_under_profile` holds the edge closed.

## Host-OS status

The confinement tests exercise this oracle on macOS through
`/usr/bin/sandbox-exec`. On macOS a confinement
test that cannot run because `/usr/bin/sandbox-exec` is missing fails the
gate; it never passes by skipping. The caller that fails the test is
`sandbox_available`, and
`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` calls it with
`macos` and a missing path. On any other host OS, when `sandbox-exec` is
missing, the confined tests print a skip reason and return.

Future Linux enforcement tests for this lab contract are designed in
`../wallet-provider/CONFINEMENT-LINUX.md`: it is the one Linux mapping, its
tests do not exist yet, and it claims no current behaviour. The existing
source-only check `both_file_profiles_bind_one_storage_parameter_contract`,
in `../wallet-provider/tests/confine.rs`, reads the three oracles and supplies
contract evidence, not Linux execution evidence.

## Tests

`tests/confine/main.rs` (the cargo test target `confine`) holds this crate's
one sandboxed launcher. It runs the built binary under
`/usr/bin/sandbox-exec -f confine.sb`, binds the three parameters to resolved
paths, and speaks the normal stdin/stdout protocol. `sandbox-exec` reads
`confine.sb` from `CARGO_MANIFEST_DIR` at every launch, so an edit to the
profile takes effect without a rebuild. A fixture launch runs a test-time copy
of `confine.sb` with fixture rules appended. The copy is read from the same
source, so a profile edit reaches it too. The `init` config carries one hosted
offer, which touches no file at `init`. A local engine offer reads files
outside `STORAGE_ROOT`, and this profile does not grant them: see "What the
profile does not grant".

- `model_provider_ops_under_profile`: `STORAGE_PARENT` exists at launch and
  `STORAGE_ROOT` does not. The test drives `init`, `status` and `offers_list`,
  checks each answer, and checks that `init` created `runs/` under
  `STORAGE_ROOT`. It then shuts the provider down and requires a clean exit.
- `model_outside_write_denied`: the fixture creates `STORAGE_ROOT` to hold a
  link: `STORAGE_ROOT/escape` is a symlink to `STORAGE_PARENT/outside`, a
  sibling of the journal root. `init` names the journal path
  `STORAGE_ROOT/escape/inner`, so the path looks inside the root but leads
  outside. The link is an intermediate because the provider refuses a
  symlinked journal root, run directory or run file. `outside/inner` already
  exists because the provider also refuses to create a directory under a
  symlinked parent. The test requires:
  - the answer `status: error`, `code: journal_corrupt`;
  - the provider's stderr line
    `[model-provider] journal_corrupt: ... <journal path>: Operation not permitted`;
  - the outside sibling unchanged: the same entries, modes and bytes;
  - a later normal `init` on `STORAGE_ROOT` succeeds.
- `redirect_journal_materializes_outside_when_unconfined`: the control. The
  same fixture and the same request, without the profile, answer `status: ok`
  and create the journal (`outside/inner/runs`) under the outside sibling.
- `model_outside_read_denied`: a stored run reads back from `STORAGE_ROOT`,
  and the same `runs_get` is refused once the record lives in a sibling of the
  root. See "Reads outside the storage root".
- `model_outside_create_reports_access_denied`: the same redirected `init`
  under a test-time copy of `confine.sb` that adds only a metadata read of the
  outside journal root. The sandbox refuses the journal create, and the
  answer is `journal_access_denied`. Its control is
  `redirect_journal_materializes_outside_when_unconfined`. See "Writes
  outside the storage root".
- `model_local_offer_fails_closed_under_profile`: an `init` whose one offer is
  a local engine offer fails closed under the profile, writes nothing, and
  leaves the provider in service. See "What the profile does not grant".
- `model_local_offer_accepted_when_unconfined`: the control. The same fixture
  and the same `init`, without the profile, answer `status: ok` with the offer
  ready. It sends no `runs_create`, so no engine starts.
- `model_hosted_run_fails_closed_under_profile`: the `init` config names a
  stand-in for the Runtime socket in `runtime_hosted_socket`. Under the
  profile the hosted run's connect to it is refused: the run settles as
  `transport_interrupted`, the stand-in's final read counts no connection,
  and the provider stays in service. See "What the profile does not grant".
- `model_hosted_run_reaches_runtime_socket_when_unconfined`: the control. The
  same fixture and requests, without the profile: the stand-in counts one
  connection, the run's one request reaches it, and the stand-in's refusal
  settles the run as `hosted_effect_refused`.
- `runtime_socket_stand_in_counts_a_silent_connection`: one client connects
  to the stand-in, sends nothing and stays open. The final read counts one
  connection with no request line, and it returns in less than half of
  `FIXTURE_EVENT_TIMEOUT`, so it waits for no request. It needs no provider
  and no sandbox.
- `runtime_socket_stand_in_drains_queued_connections`: the stand-in's accept
  loop is stopped, then two clients connect and stay queued. The final read
  takes and counts both. It needs no provider and no sandbox.
- `runtime_socket_stand_in_accepts_behind_a_silent_connection`: a first
  client stays silent, and a second sends a whole request. The second gets
  the stand-in's whole `403` answer within half of `FIXTURE_EVENT_TIMEOUT`,
  and the final read counts both connections and the second one's request
  line. It needs no provider and no sandbox.
- `hosted_run_wait_fails_a_reply_after_its_deadline`: the hosted run's wait
  loop gets a deadline 50 ms ahead and a poll that records the wait it was
  given, sleeps 100 ms and returns a terminal run. The loop fails with the
  deadline message, and the first poll was given no more than 50 ms. It needs
  no provider and no sandbox.
- `hosted_run_wait_times_out_without_a_reply`: the same loop, with a deadline
  50 ms ahead, sends its `runs_get` through the one receive to `/bin/sleep`
  on the provider's pipes, which never answers. The loop fails with the
  deadline message, and the wait is shorter than half of
  `FIXTURE_EVENT_TIMEOUT`. It does not start the provider binary and it needs
  no sandbox.
- `model_unbound_program_refused_under_profile`: a byte-identical copy of the
  provider binary under `STORAGE_ROOT`, started with the real binary bound as
  `PROVIDER_EXECUTABLE`, never answers `init`. `sandbox-exec` exits 71 and logs
  the refused `execvp()` with `Operation not permitted`, and nothing is
  written. See "Starting other programs".
- `model_bound_copy_serves_under_profile`: the control. A copy made the same
  way, bound as `PROVIDER_EXECUTABLE` and started under the same profile,
  answers `init`, creates `runs/` and exits cleanly after `shutdown`.
- `startup_is_refused_when_the_profile_cannot_be_applied`: a missing profile,
  a copy of `confine.sb` with its last `)` removed, and `confine.sb` with
  `STORAGE_ROOT` unbound each refuse the start. It runs under
  `sandbox-exec`, as the other confined tests do. See "When the profile
  cannot be applied".
- `sandbox_gate_fails_instead_of_skipping_on_a_declared_os`: a missing
  `sandbox-exec` on `macos` is a refusal that names the OS and the path, a
  missing one on `linux` is a skip, and a present one on `macos` runs. It
  needs no sandbox.
- `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing`: calls
  `sandbox_available` with `macos` and a missing path, and that call fails
  the test with the gate's reason. A present path on `macos` returns true.
  It needs no sandbox.

`journal_corrupt` is the provider's existing code for an unavailable journal,
and `journal_access_denied` is its code for a refused journal create or write
(provider task 012). The JSON answer carries only the code and its fixed
message. The detail goes to stderr only.
EPERM (`Operation not permitted`) on the redirected path is how the macOS
sandbox refuses; a corrupt journal or a bad request logs a different detail.
The control shows that the same request succeeds without the profile, so the
profile is the only difference between the two runs.

The confined tests print a skip reason and return when `/usr/bin/sandbox-exec`
is absent on a host OS other than macOS. On macOS a missing `sandbox-exec`
fails the gate. When it is present and the sandbox refuses to launch the bound
binary, they fail. The unconfined controls need no sandbox and run on every
Unix host, except `model_hosted_run_reaches_runtime_socket_when_unconfined`:
off macOS the provider refuses every hosted run before any socket, so that
control prints a skip reason there and returns.
`model_bound_copy_serves_under_profile` is a control that runs under the
profile, so when `sandbox-exec` is missing on a host OS other than macOS it
prints a skip reason and returns, as the confined tests do. The three
`runtime_socket_stand_in_*` tests and
`hosted_run_wait_fails_a_reply_after_its_deadline` start no provider and need
no sandbox, so they run on every Unix host.
`hosted_run_wait_times_out_without_a_reply` starts `/bin/sleep` and does not
start the provider binary. It needs no sandbox.
`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` and
`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` start no
process and need no sandbox, so they run on every Unix host.

The profile shape has one check (P10):
`both_file_profiles_bind_one_storage_parameter_contract` in
`../wallet-provider/tests/confine.rs` requires this file and fails when it is
missing or unreadable.
It requires `(version 1)` first, `(deny default)` second, `(deny network*)`,
no network allow, only the three parameter tokens, the three shared rules
verbatim, and no `(allow default)`. This crate adds no second shape test.

Run from the repository root:

```bash
cargo test --locked --manifest-path capsules/model-provider/Cargo.toml --test confine
cargo test --locked --manifest-path capsules/wallet-provider/Cargo.toml --test confine
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/confine-falsifiers.json
```

## Falsifiers

`confine-falsifiers.json` holds this profile's falsifiers for the shared
runner. Every entry uses `expect: caught`. F-cc12a uses command `wallet`,
because the one shape check is in the wallet crate, and every other entry
uses command `provider`. Each mutates `confine.sb` only, except the twelve
entries that edit `tests/confine/main.rs`: F-cc1e removes the outside-read
fixture rule, F-cc8-rm-journal removes the outside-create fixture grant,
F-cc15a, F-cc15b and F-cc15c each undo one part of how the Runtime socket
stand-in counts connections, F-cc16a, F-cc16b and F-cc16c each undo one
part of how the hosted run's wait loop holds its deadline, F-cc17a returns
`Ok(false)` from the declared-OS branch of `sandbox_gate`, F-cc17b
returns `false` from the error arm of `sandbox_available`, F-cc19a starts
the program directly when the profile file does not exist, and F-cc19b
keeps none of the stderr lines `Provider::ended` reads.

| Id | Mutation | Named test | Why the test fails |
| --- | --- | --- | --- |
| F-cc1a | `(deny default)` becomes `(allow default)`; `(version 1)` stays first | `model_outside_write_denied` | The redirected `init` answers `ok`. |
| F-cc1b | The `STORAGE_ROOT` read/write grant's subpath becomes `STORAGE_PARENT` | `model_outside_write_denied` | The redirected `init` answers `ok`, so the test checks the boundary itself. |
| F-cc1-rm-exec | Remove the `process-exec` rule | `model_provider_ops_under_profile` | No answer to `init`: exit status 71. |
| F-cc1-rm-rootdir | Remove the root directory read | `model_provider_ops_under_profile` | No answer to `init`: SIGABRT. |
| F-cc1-rm-sysctl | Remove `(allow sysctl-read)` | `model_provider_ops_under_profile` | No answer to `init`: SIGABRT. |
| F-cc1-rm-parent | Remove the `STORAGE_PARENT` read | `model_provider_ops_under_profile` | `init` answers `journal_corrupt`. |
| F-cc1-rm-storage | Remove the `STORAGE_ROOT` read/write grant | `model_provider_ops_under_profile` | `init` answers `journal_access_denied` (provider task 012). |
| F-cc1c | The `STORAGE_PARENT` read becomes `subpath`, so it covers the parent's whole subtree | `model_outside_read_denied` | The outside `runs_get` answers `ok` with the run: the record outside the root is read and returned. |
| F-cc1d | The `STORAGE_ROOT` grant keeps `file-write*` and loses `file-read*` | `model_outside_read_denied` | The first `init` answers `journal_corrupt`: the provider cannot inspect its own journal root, so the test fails before its in-root read. |
| F-cc1e | Remove the outside-read fixture rule from the test | `model_outside_read_denied` | `runs_get` stops at the record's existence check (`model run is unreadable`), before the open, so the check for EPERM on the open fails. |
| F-cc7a | `(deny default)` becomes `(allow default)`; `(version 1)` stays first | `model_local_offer_fails_closed_under_profile` | The local offer's `init` answers `ok`. `(deny network*)` stays, so no run could complete; the test sends none. |
| F-cc7b | One line, `(allow file-read*)`, is added after the last rule; `(deny default)` and every other rule stay | `model_local_offer_fails_closed_under_profile` | With reads alone added, the same `init` answers `ok`. So the test watches the profile's read boundary at `base_path`, not only `(deny default)`. |
| F-cc8a | `(deny default)` becomes `(allow default)`; `(version 1)` stays first | `model_outside_create_reports_access_denied` | The redirected `init` answers `ok`. |
| F-cc8c | One line, `(allow file-write* (subpath (param "STORAGE_PARENT")))`, is added after the `STORAGE_ROOT` rule; `(deny default)` and every other rule stay | `model_outside_create_reports_access_denied` | The create succeeds and `runs/` appears under the outside sibling. The provider's next inspect, of the new `runs/`, is refused, so `init` answers `journal_corrupt`, not `journal_access_denied`. So the test watches the write grant itself. |
| F-cc8-rm-journal | Remove the outside-create fixture grant from the test | `model_outside_create_reports_access_denied` | The sandbox refuses the inspect of the outside journal root before the create, so `init` answers `journal_corrupt`. |
| F-cc10a | `(deny default)` becomes `(allow default)` and `(deny network*)` is removed; `(version 1)` stays first | `model_hosted_run_fails_closed_under_profile` | The hosted run's request reaches the Runtime socket stand-in. `(allow default)` alone is not enough: `(deny network*)` still refuses the connect. |
| F-cc10b | `(deny network*)` becomes `(allow network*)`; nothing else changes | `model_hosted_run_fails_closed_under_profile` | The request reaches the stand-in, so the network denial alone holds this edge. This is the widening a hosted grant would add. |
| F-cc12a | Remove `(deny network*)`; nothing else changes | `both_file_profiles_bind_one_storage_parameter_contract` (wallet crate) | The one shape check refuses the model profile with "model-provider must deny the network explicitly with (deny network*)". |
| F-cc14a | `(deny default)` becomes `(allow default)`; `(version 1)` stays first | `model_unbound_program_refused_under_profile` | The copy under `STORAGE_ROOT` starts and answers `init`. |
| F-cc14b | One line, `(allow process-exec)`, is added after the exec rule; the exec rule stays word for word | `model_unbound_program_refused_under_profile` | The copy starts and answers `init`. The one shape check still passes, so this test holds the exec limit. |
| F-cc14c | One line, `(allow process-exec (subpath (param "STORAGE_ROOT")))`, is added after the exec rule; the exec rule stays word for word | `model_unbound_program_refused_under_profile` | The copy starts and answers `init`, so a program in the provider's own storage would run. The one shape check still passes. |
| F-cc15a | In the test, the stand-in's count moves from the accept to after the request has been read | `runtime_socket_stand_in_counts_a_silent_connection` | The final read counts no connection: the silent client would be counted only once its read ends. |
| F-cc15b | In the test, the final read no longer takes the connections still queued | `runtime_socket_stand_in_drains_queued_connections` | The final read counts neither queued client. |
| F-cc15c | In the test, the stand-in serves each connection on its accept loop instead of on the connection's own thread | `runtime_socket_stand_in_accepts_behind_a_silent_connection` | The second client gets no answer within half of `FIXTURE_EVENT_TIMEOUT`: the accept loop waits on the silent connection's read. |
| F-cc16a | In the test, the wait loop returns a terminal reply before it checks the deadline | `hosted_run_wait_fails_a_reply_after_its_deadline` | The loop returns the terminal run that came after the deadline instead of failing. |
| F-cc16b | In the test, the wait loop gives each poll `FIXTURE_EVENT_TIMEOUT` instead of the time left | `hosted_run_wait_fails_a_reply_after_its_deadline` | The first poll is given more than the 50 ms left, so a poll may wait past the deadline. |
| F-cc16c | In the test, the request path's one receive waits `FIXTURE_EVENT_TIMEOUT` instead of the wait it is given | `hosted_run_wait_times_out_without_a_reply` | The `runs_get` that gets no answer waits all of `FIXTURE_EVENT_TIMEOUT`, not the time left, before the loop fails. |
| F-cc17a | In the test, the declared-OS branch of `sandbox_gate` returns `Ok(false)` | `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` | The `macos` case with the missing path is no longer `Err`. |
| F-cc17b | In the test, the error arm of `sandbox_available` returns `false` instead of failing the test | `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` | A missing `sandbox-exec` on macos returns, and a confined test would pass; this test fails because the call returned `false`. |
| F-cc19a | When the profile file does not exist, `sandboxed` starts the program directly, without `sandbox-exec` | `startup_is_refused_when_the_profile_cannot_be_applied` | Case (a)'s launch starts the provider unconfined, it answers `init`, and the test fails at its first check. |
| F-cc19b | `Provider::ended` keeps none of the stderr lines it reads | `startup_is_refused_when_the_profile_cannot_be_applied` | Case (a) still exits 65, but no line gives `sandbox-exec`'s reason. |

F-cc1e proves that the fixture rule is needed, so the refusal the test
observes is the content open, not a precursor stat. F-cc8-rm-journal does the
same for the outside-create grant: the refusal that test observes is the
create, not the inspect before it. The runner rebuilds the test for both, and
for the F-cc15, F-cc16, F-cc17 and F-cc19 entries. Its startup recovery restores
`tests/confine/main.rs` after a killed run (provider task 015), as it restores
`confine.sb`.

The list is a Mac gate. On a Mac without `/usr/bin/sandbox-exec` the unmutated
suite fails, so a list run there is no evidence. Off macOS, when
`sandbox-exec` is missing, the confined tests skip and pass, so each sandbox
entry reads SURVIVED there. The entries whose tests need no sandbox (F-cc12a,
F-cc15a, F-cc15b, F-cc15c, F-cc16a, F-cc16b, F-cc16c, F-cc17a and F-cc17b) are
CAUGHT on any host that builds their crate. F-cc12a reads the profile files
and is CAUGHT on any host that builds the wallet crate. The model-provider
entries among them are CAUGHT on any Unix host where `tests/confine/main.rs`
builds and runs. A call site that passes a fixed `"linux"` is not caught by a
list run on a Mac where `/usr/bin/sandbox-exec` exists, so that run is no
evidence for the OS argument.

F-cc12a registers the removal of `(deny network*)`: the runner applies it
with the `wallet` command and restores `confine.sb` afterwards, or at its
next start after a killed run. WP06 in `../wallet-provider/falsifiers.json`
guards the check's own `(deny network*)` requirement: it deletes that
requirement from the check.
