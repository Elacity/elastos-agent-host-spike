# model-provider confinement

`confine.sb` is the one source of the model provider's confinement profile
(P10). It starts with `(version 1)`, then `(deny default)`, then
`(deny network*)`. The provider reads line-delimited JSON on stdin and writes
one JSON answer per line on stdout. The profile grants it no socket and no
listener. Every operation that no rule grants is refused (P3, P11).

## Parameters

The profile uses only the three parameter tokens every file profile binds:

- `PROVIDER_EXECUTABLE`: the canonical path of the provider binary.
- `STORAGE_ROOT`: the model journal root. That is
  `Init.base_path/providers/model-provider`, or the configured absolute
  `journal_dir`.
- `STORAGE_PARENT`: the parent of `STORAGE_ROOT`. Under the shared contract the
  Runtime creates it before launch. The provider creates `STORAGE_ROOT` itself
  at its first `init`.

All three are resolved paths. The sandbox matches the resolved path, so a
path through a link (macOS `/var` is `/private/var`) would match nothing.

## The Runtime half

The model provider presents the same file-profile contract as `did-provider`
and `wallet-provider`: one profile file, the same head forms, the same three
parameter tokens and the same three shared rules. The Runtime half of that
contract is "The Runtime bridge change" in `../did-provider/CONFINEMENT.md` and
`../wallet-provider/CONFINEMENT.md`. The model provider needs nothing from the
Runtime beyond that one parameterized launch and that one profile check. There
is no separate Runtime proposal for the model provider (P10).

## What the profile allows

Each rule is load-bearing: removing it alone makes
`model_provider_ops_under_profile` fail, as the named falsifier shows.

| Rule | Why the provider needs it | Without it |
| --- | --- | --- |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | Start only the binary bound as `PROVIDER_EXECUTABLE`. | F-cc1-rm-exec: `sandbox-exec` cannot execute the binary and exits 71. |
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
test here (see Tests).

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

## What the profile does not grant: the local engine

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
profile does not grant: the local engine".

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
- `model_local_offer_fails_closed_under_profile`: an `init` whose one offer is
  a local engine offer fails closed under the profile, writes nothing, and
  leaves the provider in service. See "What the profile does not grant: the
  local engine".
- `model_local_offer_accepted_when_unconfined`: the control. The same fixture
  and the same `init`, without the profile, answer `status: ok` with the offer
  ready. It sends no `runs_create`, so no engine starts.

`journal_corrupt` is the provider's existing code for an unavailable journal,
and the JSON answer carries only that code. The detail goes to stderr only.
EPERM (`Operation not permitted`) on the redirected path is how the macOS
sandbox refuses; a corrupt journal or a bad request logs a different detail.
The control shows that the same request succeeds without the profile, so the
profile is the only difference between the two runs.

The confined tests print a skip reason and return when `/usr/bin/sandbox-exec`
is absent. When it is present and the sandbox refuses to launch the binary,
they fail. The controls need no sandbox and run on every Unix host.

The profile shape has one check (P10):
`both_file_profiles_bind_one_storage_parameter_contract` in
`../wallet-provider/tests/confine.rs` runs over this file whenever it exists.
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
runner. Every entry uses command `provider` and `expect: caught`. Each
mutates `confine.sb` only, except F-cc1e, which removes the outside-read
fixture rule from `tests/confine/main.rs`.

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

F-cc1e proves that the fixture rule is needed, so the refusal the test
observes is the content open, not a precursor stat. The runner rebuilds the
test for it. The runner's startup recovery does not restore
`tests/confine/main.rs`. A run killed during F-cc1e leaves the edited test and
its `.falsify-original` backup in place. Until the backup is moved back by
hand, the next F-cc1e run stops with `NO MATCH` and `model_outside_read_denied`
fails. Adding the file to the runner's recovery list is a change to
`examples/agent-host/falsify.py`, which the provider lane owns.

The list is a Mac gate. Without `/usr/bin/sandbox-exec` the confined tests
skip and pass, so the runner reports each entry as SURVIVED there.

The runner's `provider` command runs only this crate, so the `(deny network*)`
falsifier is applied by hand: delete `(deny network*)` from `confine.sb` and
run the wallet command above.
`both_file_profiles_bind_one_storage_parameter_contract` then fails with
"model-provider must deny the network explicitly with (deny network*)".
Restore the file and it passes. The check itself is guarded by WP06 in
`../wallet-provider/falsifiers.json`, which deletes the `(deny network*)`
requirement from the check.
