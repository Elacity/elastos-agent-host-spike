# Agent conformance checks

From the repository root on the Mac, with the shared heavy-build lease held, run:

```sh
lab/agent-conformance/run.sh
```

The command uses cached dependencies, the pinned Rust toolchain and its
`wasm32-unknown-unknown` target and the macOS `shasum` tool. Reserve 12 GiB for
builds plus 2 GiB free. The
lease procedure is in [scripts/README.md](../../scripts/README.md#local-pre-push-gate).
The command prints typed `version identity: {...}` observations above one table
from Cargo's test inventory and result lines. Native records identify `elastos`
and `localhost-provider` by SHA-256. Probe records carry the component SHA-256
and complete bundle lab CID, with separate `build_only` and `launched` kinds.
Cargo's `--show-output` supplies these records from this invocation. The existing
build helpers hash the native binaries; the staging path names the exact probe
manifest and payload through `capsule_identity::checked_bundle`.
`ok` becomes PASS. `ignored, blocked: <reason>` becomes BLOCKED with each
semicolon-separated part trimmed and kept whole, joined by `; `.
An empty reason or part gives FAIL.
A failure, missing result, repeated result, ignored test without a blocker ID,
or Cargo error gives FAIL and a non-zero command exit status. BLOCKED rows
remain open in [GAPS.md](GAPS.md).
BLOCKED requires exactly one `GAPS.md` row with the test name, matching blocker IDs and a Runtime change.
A missing or conflicting row, an unreadable `GAPS.md`, or a listed test that passes gives FAIL and a fixed reason.

- `home_is_throwaway`: checks the Mac data path, fresh root, path guard, symlink refusals and removal after success.
- `launch_env_is_only_the_throwaway_home`: checks the four allowed environment entries, including `ELASTOS_CARRIER_MDNS=0`, null stdin, exit status and both output streams.
- `launch_stops_a_child_past_its_bound`: checks that a one-second bound stops a three-second sleep with the exact timeout reason.
- `run_without_operator_is_refused_with_reason`: runs the probe through the bounded launch primitive in a fresh Home and requires a nonzero exit with `This command requires a running runtime.` on stderr.
- `runtime_data_dir_is_under_throwaway_home`: places a dummy coordinates file in the guarded data directory and requires Runtime to remove it and return the same refusal reason. Its documentation-address URL is rejected before any network call.
- `run_by_cid_without_content_provider_is_refused`: runs `--cid` with an encoder-produced synthetic lab CID in a fresh Home; requires a nonzero exit, `ipfs-provider not found`, and zero materialized capsule entries in TMPDIR.
- `run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash`: stamps a different byte string's SHA-256 on the installed marker script; requires the complete checksum refusal on one stderr line, an absent marker, and zero materialized capsule entries.
- `capsule_named_by_hash`: BLOCKED (AC-025-CID). The full journey will stage the probe, make its CID available offline, run `--cid`, and require the directory launch's activation result. The verdict and changes needed are in [GAPS.md](GAPS.md#launch-by-bundle-cid-025).
- `serve_refuses_provider_whose_bytes_differ_from_its_hash`: installs the provider and its hash, appends one byte to the copy, and requires a nonzero `serve` exit with `localhost-provider` and `failed checksum verification` on stderr. It also checks that storage exists inside the root and the readiness file is absent.
- `run_table_requires_cargo_results`: checks PASS, BLOCKED and FAIL grading against Cargo-format result fixtures.
- `run_table_grades_blocker_lists_by_one_rule`: checks whole multi-word blocker reasons, trimmed semicolon lists and FAIL for empty reasons or parts. F-report-blocker-list keeps only the first whitespace word; the named test must fail planted and pass restored.
- `foreign_and_wrong_version_imports_are_refused`: rejects imports outside the probe's Bus subset.
- `non_component_and_invalid_component_are_refused`: rejects a core module and invalid component bytes.
- `probe_hash_is_stable`: compares the SHA-256 values from two independent probe compilations on this Mac.
- `probe_imports_only_the_bus`: checks the imports of both built components.
- `probe_manifest_names_the_current_bus_world`: checks the WIT hash and component manifest fields.
- `tests::probe_refuses_without_a_launch_argument_channel`: checks the probe's explicit unavailable result.
- `cargo` (failure only): Cargo could not supply a complete test inventory or finish the suite.

The harness owns each fresh root under this lane's ignored `target/`. It checks
HOME and the derived data path before reading those paths or starting a child.
The launch primitive clears the parent environment and sets HOME, TMPDIR,
the fixed system PATH and `ELASTOS_CARRIER_MDNS=0`. The environment test checks that complete allowlist.
F-ac1c selects the inherited HOME and proves the guard refuses it before any
read. These checks protect the real Home by construction; they never read its
data. The fixture stores a selector, rather than a user's Home path.

These rows prove the harness, probe artifact and Runtime refusal rules.
Each native binary builds at most once per test process, with failures cached too.
Runtime and localhost-provider share the build settings, SHA-256 helper and
`target/runtime`; warm runs reuse Cargo's cached artifacts. All live checks share
the Runtime build.
The build keeps the developer's toolchain environment. Each Runtime launch uses
`harness::ThrowawayHome::launch` or `start`, which share one spawn site and
cleared environment. The operator lookup
returns before the storage constructor; AC-006-STORAGE remains open. The
ready-operator rows below prove the operator fixture;
the grant and effect rows below extend it. Runtime bundle-CID launch stays separate.

`tests/common::write_operator_home` owns the operator fixture for this test and
the ready-operator tests. It uses `write_component_home`, the shared entry-copy
and stamping helper, which also prepares the CID refusal fixture. The helper
checks the Home guard and installs executable bytes. For the operator fixture,
it writes a manifest containing only the repository's `external.localhost-provider`
entry and an empty `profiles` map; the CID fixture selects `external.ipfs-provider`.
It stamps the current Mac platform with the
copy's checksum, size and install path. The repository entry owns all other fields.
The writer supports `darwin-arm64` and `darwin-amd64` and refuses other platforms
with a reason. Exclusive creation keeps existing paths and symlinks intact.

The checksum test passes both `--addr 127.0.0.1:<free port>` and an in-root
`--storage-path`. Provider verification stops startup before Carrier and HTTP
bind (`server_infra.rs:768-776,1547`; `serve_cmd.rs:295,462`). F-ac1i changes the
writer's destination to `bin/localhost-provider-copy` while the manifest keeps
the required path. Runtime then reports the provider as missing, so the test
fails on its reason check. Both cases stop before network startup. Task 013
adds the matching-byte ready operator and closes AC-010-OFFLINE below.

F-ac1f changes the single data-dir rule to the Linux form. The decoy must remain
and `runtime_data_dir_is_under_throwaway_home` must fail. F-ac1g changes only the
probe's `runtime_abi` to a non-component value. The Runtime then returns a
different reason, so `run_without_operator_is_refused_with_reason` must fail.
This checkout rejects `wasi-preview1` during manifest validation, before the
operator lookup.
Select these tests with `--test runtime TEST_NAME -- --exact --nocapture` to
observe the Runtime refusal directly, independently of probe-build validation.
Restore each exact edit and require the same test to pass.

A passed test removes its root. A failed test prints and retains its root for
inspection. A failed command also retains Cargo output under `target/run-table.*`.
Keep each failed root only until its result is reviewed, then remove that root.
The [falsifier list](falsifiers.json) owns the exact mutations; [LOG.md](LOG.md)
records their local runs. The provider lane owns the shared runner's `lab` arm;
until it is available, apply and restore each mutation by hand.

For 025, run F-cid-provider under the same heavy-build lease in three steps:
run its named checksum-refusal test unchanged, apply its exact edit from
`falsifiers.json` and require FAIL, then restore the edit and require PASS.
The mutation stamps the script's own SHA-256 so Runtime can spawn it; the
marker assertion must fail. These two CID refusals precede CID validation and
give zero evidence that the CID was checked. They use only the inert script;
the full offline content fixture stays BLOCKED. Cargo supplies that ignored
row to the existing `run.sh` table, which reports `BLOCKED (AC-025-CID)`.

Task 013 adds these rows to the same Cargo-derived table:

- `fixture_operator_starts_ready_and_stops_cleanly`: installs matching provider bytes, copies the two-setting config, checks coordinates existence and HTTP 200 within 60 seconds, checks sockets, and requires group exit within the ten-second stop bound. This is the positive control for 012's native platform key.
- `fixture_operator_sockets_are_loopback_only`: measures every internet socket in the operator group at readiness and at least three seconds later. Both samples require the loopback API listener. `run.sh` also prints their socket counts.
- `socket_census_requires_parseable_loopback_endpoints_and_api_listener`: checks field-format parsing with IPv4/IPv6, connected sockets, wildcard and remote addresses, malformed listings and missing API visibility.
- `managed_child_stop_reaps_its_process_group`: checks SIGTERM and group cleanup with a parent and child fixture.
- `managed_child_drop_kills_its_group_and_keeps_root`: checks emergency group cleanup and root retention when a handle is dropped before stop.

The [operator recipe](GAPS.md#operator-in-a-throwaway-home) owns the ordered
setup and its measurement limits. `fixtures/operator-config.toml` selects
unsigned admission and a loopback Carrier bind. Admission grants no resource.
Readiness checks coordinates existence. The grant controller reads its fixture
credentials into memory and checks the harness-owned captures after group drain. System `kill`, `pgrep` and `lsof` use
the same guarded spawn site, null stdin, capture files and fixed environment.
Census failures stop the operator immediately and fail with a reason. The
census samples internet sockets in the group; it is not a packet capture.

Run F-ac1j only against `fixture_operator_sockets_are_loopback_only`: it changes
the committed API host to a wildcard for that short test, while Carrier stays
on loopback with mDNS disabled. Readiness requests still use loopback. Require
the wildcard-socket refusal, then restore the fixture and require PASS.
Run F-ac1k only against `launch_env_is_only_the_throwaway_home`; it removes the
mDNS-off entry for that environment test alone. Restore it before any operator
launch. F-census-a removes the API visibility requirement. F-managed-stop omits
SIGTERM and checks the timeout failure and forced cleanup. F-managed-drop omits
the retained-root marker. Their exact edits and named tests are in
`falsifiers.json`; each named test must fail planted and pass restored.


Task 003 adds these rows to the same table:

- `ungranted_effect_is_refused`: runs the read build against the ready fixture operator. Requires a nonzero exit and the lifecycle error `Internal("capsule manifest does not declare authority for localhost://Public/agent-conformance-ungranted/outside-fixture.txt")` inside the Runtime's component-failure wrapper.
- `ungranted_network_is_refused`: requires the same refusal for `elastos://net/stream`. This proves the network capability request is refused; provider execution is outside this check.
- `default_activation_refuses_without_selector`: runs the default build and requires the AC-002-ARGS unavailable reason through the guest lifecycle.
- `ungranted_model_call_is_refused`: BLOCKED (RT3), with the Runtime change in GAPS.md.
- `operator_storage_is_under_throwaway_home`: BLOCKED (AC-006-STORAGE), with the Runtime change in GAPS.md. The lane performs no reads through that Runtime-owned path.
- `probe_effects_are_exclusive`: building with both effect features must fail with the exact selector-conflict reason.

The artifact rows cover default, read, network, granted read, sibling read, four finite tasks and runaway builds. Each selector has
two independent probe compilations, matching hashes within its pair, and a distinct hash from the
other selectors. `run.sh` prints the shared typed identity records for built
bundles and live copies. The existing component build script uses
`RUSTFLAGS` cfg selectors for the declared Cargo features. Every build's bytes
are saved before that script can replace the shared entrypoint. The live tests
serialize build preparation and place the component in a SHA-256 directory
inside the throwaway root. The directory locates the artifact; its hash names
the bytes. Bundle-CID admission stays separate.

The earlier no-operator rows stop before the storage constructor. The new live
rows reach the existing AC-006-STORAGE exception, recorded in GAPS.md. Their
requests fall outside the manifest bound. The guest returns the Bus error,
and the harness requires both the nonzero exit and the exact reason. An
unexpected grant returns success without any provider invoke, causing the
refusal test to fail while keeping the probe free of real effects. Every live
row uses 013's ready operator, two socket samples and process-group stop.

F-ac1h discards the read build's Bus refusal; F-ac1n does the same for the
network build. Each named test must fail with exit zero and
`reason_present:false`, then pass after restoring the probe. F-probe-exclusive
removes the selector-conflict guard; `probe_effects_are_exclusive` must fail
because the conflicting build succeeds. F-probe-a now names the default live
test as well as its original host test; both must fail under that mutation.
F-probe-e follows the shared builder to `tests/common/probe.rs`. The remaining
artifact falsifiers retain their named checks. Commands and measured outputs
are recorded in LOG.md for the supervisor's PR and review.


Task 005 adds the following rows. The `process_isolation::` prefix and the
scope line printed by `run.sh` mean **process isolation, not capsule isolation**.

- `process_isolation::parallel_instances_complete_independently`: four `elastos run` clients start before collection, with separate temporary Homes, and attach to one fixture operator. Each probe computes its own addition and returns exactly its own diagnostic; both captures exclude sibling results. All finish inside one ten-second deadline from the first launch.
- `process_isolation::runaway_trap_is_bounded_while_siblings_finish`: the build-time runaway loops without bound. Runtime must return a natural lifecycle trap with exit 1 within the same deadline; the three finite siblings still return their expected diagnostics. Harness cleanup is a failure, never a Runtime stop.
- `process_isolation::runaway_is_stopped_with_reason`: BLOCKED (AC-005-REASON). Runtime must also expose the resource-stop cause on stderr. The strict assertion stays in this ignored test.
- `parallel_capsules_complete_independently`: BLOCKED (RT4). Separate client processes cannot establish resident capsule isolation in one Runtime.
- `parallel_instances_return_success_payloads`: BLOCKED (AC-002-ARGS). Bus v1 success returns unit. Finite probe results use `BusError::Unavailable` and exit 1 deliberately; their PASS rows prove diagnostic completion only.
- `parallel_collection_preserves_each_status_and_capture`: four shell fixtures all reach a barrier before collection, then return distinct statuses, stdout and stderr.
- `parallel_timeout_is_failure_and_reaps_every_group`: a shared deadline fails with its exact safety-net reason, reaps every group, and retains failed Homes.
- `parallel_collection_refuses_live_descendants`: a parent exit with a live child fails collection and triggers group cleanup.
- `parallel_attach_uses_only_guarded_fixture_coordinates`: clients receive exactly five environment entries and a damaged operator Home is refused before launch. The extra entry is the fixture-derived `ELASTOS_RUNTIME_COORDS_FILE`; Runtime reads its contents for attach; task 019 adds the fixture controller as the only test reader of `attach_secret`.

`RunningInstances::start` and `collect` extend the existing spawn site. Every
child still gets a cleared environment, null stdin and in-root capture files.
The group borrows both client and operator Homes until it settles. A failed
start or collection drops unfinished children through the existing process-group
cleanup. The operator gets the usual two socket samples and explicit stop.

The one probe has `task` and `runaway` Cargo features in addition to the earlier
read/network effects. The task index is supplied at build time; no guest
selector or environment import is added. All ten built variants retain the
Bus import check and two-build hash comparison. Builds and live runs use the
same staging function and artifact hashes. The tasks request no resource and
perform no provider, model or network effect.

F-ac3a uses the task's permitted probe mutation because Runtime fuel and memory
limits are compile-time constants. It replaces the runaway loop with 1,000
iterations and a successful return. The narrower live trap test must fail;
restoring the loop must restore PASS. This proves the trap check distinguishes
Runtime interruption from probe completion. The full stop-with-reason grade
remains BLOCKED. F-parallel-result replaces task-b's fixture with task-a's;
both named process tests must fail on their own-result check. F-parallel-capture,
F-parallel-bound, F-parallel-operator-guard, F-parallel-coordinates,
F-parallel-start and F-parallel-drain plant errors in the harness rules and each must fail its named harness test. Apply the exact edits from
`falsifiers.json` by hand and restore them before the normal gate. LOG.md holds
the commands and measured outcomes; this adds no second runner.


## Version receipt for each run

The existing report command writes `VERSIONS.json` into the fresh ignored
`target/run-table.*` directory and prints its lane-relative path. Reviewers cite
that path for the tested candidate. The report reads the full repository commit
and dirty state for this invocation; local edits set `dirty: true`.

The receipt contains native hashes, every observed probe's effect, component
SHA-256 and the complete bundle's lab CID (as `lab/capsule-identity` prints it),
the suite outcome, and the exact graded table plus its SHA-256. The sibling
identity library owns the bundle walk, manifest validation and encoding. The
staging path uses its checked entries for the component bytes. The lab CID
covers `capsule.json` and the payload;
Runtime CID launch remains BACKLOG item 13. Identity, admission and resource
allowance remain separate decisions. The receipt's description gives the lab
CID and any separate signed record zero admission or permission credit.
Runtime decides admission. Resource authority requires a Runtime grant for the
requesting session; only the corresponding observed Runtime journey supplies
that evidence. The signed-record contract stays with its owner.

Artifact observations stay in `build_only_probes`. Successful live launches
supply `probes`. The report checks the required variants for each active journey
in Cargo's results; artifact observations supply zero missing-launch credit.
Identical observations can repeat across test processes. A different identity
for the same native role or effect fails the receipt. New live journeys must
extend the report's identity requirements when they add a required variant.
The no-operator tests exercise manifest dispatch before payload loading; their
default component identity comes from the live default journey.

`versions_receipt (A14)` passes only with complete, valid, consistent identities
and a successful exclusive write. Missing or malformed values and Git query
failures produce an incomplete receipt with explicit reasons and a failing
command. A write refusal names its cause, including `AlreadyExists` or
`NotFound`, and fails the command. Exclusive creation preserves prior receipts
and symlink targets. A report-build failure stops before suite execution and
retains its build output; the command cannot issue a receipt without its writer.

`identity_status` describes identity coverage. `suite_outcome` describes the
Cargo rows, including FAIL and BLOCKED; `command_success` combines both gates.
A complete identity record preserves each journey's grade. The parser accepts
only typed identity fields and graded test rows for the receipt. Child captures,
HTTP bodies and environment dumps stay outside that data model. Synthetic
receipt fixtures stay inside ignored throwaway roots and supply zero live proof.

After a successful command, only the small receipt remains in its run directory.
The table is inside that receipt. Keep it through candidate review, then remove
the receipt and its empty directory. Failed commands retain Cargo output and
failed Homes under the existing review-and-remove rule. Generated native
binaries, WASM, receipts and synthetic fixtures remain ignored.

`versions_receipt_binds_current_run` checks two distinct synthetic runs and the
actual report CLI. `versions_receipt_rejects_incomplete_identity` checks missing,
malformed, conflicting and omitted launch identities, Git failure, exclusive
creation and write failure. `versions_receipt_uses_the_staged_bundle_identity`
checks the library's lab CID as an oracle: a manifest-only byte change changes
the bundle field while the component hash stays fixed. The extended
`run_table_requires_cargo_results` checks the combined command outcome.
F-versions-required bypasses the Runtime-identity requirement;
F-versions-bundle writes the component hash into the receipt's bundle field.
Each runs only its named synthetic report test, then passes after restoration.
F-versions-boundary removes the receipt's authority description; the same
current-run test must fail under that mutation and pass after restoration.

Task 019 adds the fixture's one grant controller (`tests/common/grants.rs`).
It reads only `attach_secret` from the guarded operator coordinates, attaches
once with scope `shell` at the operator's loopback port, then services pending
requests during the existing process collection loop. Resource, action and
reason must match an entry in `fixtures/grants.json` exactly. The entry supplies
`once` or `session`; this fixture selects `once`. Every other request receives
`fixture denies unlisted read`. An ambiguous match denies the whole pending
snapshot with a reason. A consumed entry also refuses a later matching request.

- `granted_read_succeeds`: seeds `Public/agent-conformance-grants/granted.txt`,
  observes exactly one matching request and grant, and requires exit 0 after
  the guest checks the complete file response and byte count.
- `ungranted_sibling_read_is_refused`: seeds `sibling.txt` inside the same manifest
  bound, observes one pending denial, and requires exit 1 with the delivered
  fixture reason inside the Runtime's component-failure message. Captures
  exclude the seeded bytes.
- `grants::tests::controller_matches_all_fields_exactly`: changing any match field
  prevents approval, including a resource that merely shares a path prefix.
- `grants::tests::controller_refuses_ambiguous_requests_before_deciding`: two
  matches or reuse of an entry fail before a grant is selected.
- `grants::tests::controller_requires_explicit_fixture_and_credentials`: missing
  coordinates, missing or empty attach data, and incomplete fixture rules refuse.
- `grants::tests::controller_refuses_failed_attach_and_http_responses`: failed
  attach, refused HTTP status, redirects and malformed framing refuse with a
  fixed reason. The controller connects only to IPv4 loopback.
- `grants::tests::controller_detects_credentials_without_disclosing_them`: an
  in-memory canary verifies capture detection. Both live rows scan every harness
  capture for the actual attach secret, shell token and returned grant tokens
  after the operator group stops. The check prints only its verdict.
- `tests::guest_checks_all_granted_file_bytes`: every changed byte of the expected
  provider response fails the guest comparison.
- `run_table_grades_skipped_only_with_failed_test`: a setup failure marker and a
  Cargo `FAILED` result produce `SKIPPED (<reason>)` and a failing command status.

SKIPPED means an external setup failure prevented the probe from running, such
as a refused loopback bind or failed probe build. The test prints
`SKIPPED <test>: <reason>` and fails. Runtime refusals and failed assertions keep
their FAIL grade. A SKIPPED marker paired with `ok`, an absent result, a repeated
marker or an unlisted test also grades FAIL. `run.sh` prints the marker and the
SKIPPED table row and exits non-zero. BLOCKED continues to mean a named open
Runtime contract gap.

The new selectors share the existing probe source, manifest, build staging,
import checks and two-build SHA-256 checks. The manifest bound is
`localhost://Public/agent-conformance-grants/*`; task 003's resources remain
outside it. `Public` is the file-backed fixture root. The controller writes the seed
through Runtime before the guest runs; Runtime owns the stored representation. The guest expects its bytes independently of the
seed fixture and keeps them inside the capsule.

F-ac1a widens approval to the parent fixture directory's two children by adding
an exact entry for the sibling. This keeps the controller's exact-match rule;
it introduces no wildcard approval path. The sibling then reads and checks its
bytes, exits 0, and fails the denial test. F-ac1b changes only the host seed and
fails the granted test on the guest content check after an observed grant.
F-report-b changes SKIPPED to PASS and fails the report test. The controller,
callback and guest comparison falsifiers are listed beside these in
`falsifiers.json`. Restore each mutation before running the next one.


## Bounded preparation and credential evidence

Task 019 carries 015's controller onto the base that contains 005 and 018.
The supervisor owns the fresh independent review. The earlier review covers
only 015's candidate. LOG.md records author checks separately.

`tests/common/probe.rs::build_probe` keeps one dependency and componentizer
cache per selector. Before each call it runs an offline package-scoped clean
for the probe's WASM release output. The repository component script then
compiles that package; the helper requires the compiler's package message.
Both reproducibility rounds do real compilations. Both artifacts still pass
import checks, pair hashes must agree, all variants must differ, and every
selector pair must fail compilation. Live tests use the same preparation.
The complete locked gate retains its 600-second bound. F-probe-rebuild omits
the package clean and catches a cached probe; F-probe-e changes round two's
bytes and catches the hash mismatch. Remove the ignored selector caches after
candidate review; they are rebuildable outputs.

`attach_secret_stays_in_memory` checks the existing controller with synthetic
in-memory canaries, then exercises the granted, sibling and fake host-file journeys. Each
journey checks its actual attach secret, shell token and returned grant tokens
against every expected stdout/stderr pair, the report table, the serialized
version receipt, committed lane blobs and candidate lane source files.
`render_run` produces the same table and receipt bytes used by `write_run`,
so credential acceptance can check both outputs in memory. Runtime owns the
original coordinates file; it remains the controller's input. Harness copies
stay in memory and reach the loopback HTTP calls directly. Process arguments,
environment entries and output files carry paths or public evidence only.

The spawn site records expected capture pairs. An empty inventory, missing
capture, symlink, or absent source/report coverage fails with a fixed reason.
Git's lane-only source inventory excludes ignored Homes and build outputs.
Detection reports only a fixed reason and safe surface label. The canary test
plants each of three synthetic values into an in-memory copy of every surface;
it keeps those values out of saved files and assertion messages.
F-grant-capture retains its checker-bypass mutation and now requires both the
original disclosure test and `attach_secret_stays_in_memory` to fail.
F-capture-inventory and F-output-inventory test missing evidence, separately
from credential detection. All named tests must pass after restoration.

Runtime owns admission and permission decisions. A package CID and separate
signed record identify the package. A valid CID, valid signature or successful
admission supplies zero fixture grant entries. Only an exact pending request
and explicit fixture entry can cause this controller to ask Runtime for a grant.
The granted and sibling checks observe that decision; F-ac1a changes only the
explicit sibling grant entry. Resource budgets remain a separate Runtime rule.
Tasks 016 and 017 must reuse these capture, source, report and receipt checks
before claiming their M1 results.


Task 004 adds the agent-memory rows to the same Cargo-derived table:

- `agent_cannot_read_human_space_without_grant`: the existing read feature asks for `Users/self` and requires the Runtime's principal-context refusal. This is the current unbound CLI's refusal half.
- `ungranted_memory_write_is_refused`: the new memory-write feature requests authority through the Bus and requires the Runtime's manifest refusal.
- `no_policy_file_does_not_mean_allow`: one in-manifest read receives zero controller decisions when `fixtures/no-policy.json` is absent. The natural pending-request refusal must arrive within 40 seconds. A harness timeout fails.
- `agent_memory_under_own_principal`, `agent_cannot_read_other_agent_memory`, and `agent_can_read_human_space_with_grant`: BLOCKED (UsersAI binding; AC-002-ARGS). GAPS.md names the Runtime changes and the future checks. These rows supply zero principal-isolation evidence today.
- `real_agent_host_journal_under_usersai_principal`: BLOCKED (UsersAI binding), the P7 gap in the default table. Forced with `--ignored`, it reads the real manifest and requires every capability under `UsersAI/self`; agent-host moves its journal when the Runtime binding lands.

F-ac2a grants agent-b agent-a's exact memory path. F-ac2b gives both fixture
instances the same principal. Both are retired under `UsersAI binding;
AC-002-ARGS` in `falsifiers.json` until their named tests,
`agent_cannot_read_other_agent_memory` and `agent_memory_under_own_principal`,
respectively, become live. Then return each mutation to the active list and
run it; forcing today's placeholders supplies zero falsifier evidence.
F-ac2c adds the absent `fixtures/no-policy.json` file using its `new` text in
`falsifiers.json` (`old: ""` denotes an absent file for this manual step).
The entry allows every effect attempted by this instance: its one read.
Run `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
--test effects no_policy_file_does_not_mean_allow -- --exact --nocapture` with
the usual offline environment and heavy-build lease. Require a successful
guest read, one observed grant, and the refusal test's FAIL. Remove only this
added policy file and rerun the identical command; require PASS. A build
failure, unrelated error, SKIPPED or BLOCKED result cannot catch a falsifier.

F-ac2-human and F-ac2-write change the respective probe activation to succeed
without its Bus refusal. Each named refusal test must fail, then pass when the
original probe bytes are restored. All mutations remain inside fixtures or the
one probe. The provider lane owns shared-runner support; these lab falsifiers
continue to run by hand. The existing report records every launched variant's
component SHA-256 and complete bundle lab CID.

## Fake host-file refusal (M1 A8)

`host_key_read_is_refused` copies `fixtures/fake-ssh/id_ed25519` into the guarded
throwaway home's `.ssh` directory before launch. The file contains an obvious
fake marker. The probe uses the one Bus read path, selected at build time by
`host-key-read`. The manifest bound supplies the baseline refusal. The test
checks its exact reason, marker-free captures and unchanged fake bytes.
`host_key::fixture_path_uses_the_guarded_home_rule` checks the fixed resource's
relative depth against the harness's Mac data-dir rule.

`run.sh` prints `host key read:` along with the checked controller, census,
refusal and identity lines, followed by the Cargo-derived test row. Read each
A8 row with the VERSIONS.json path printed by that invocation. Its
`host-key-read` entry names the launched component SHA-256 and complete bundle
lab CID. A probe that cannot start receives the existing SKIPPED grade and
supplies zero passing evidence. The scope is one route to one fake file;
GAPS.md describes the remaining scope.

Run F-ac8a by applying both exact edits in `falsifiers.json`: its one-use
controller entry and its exact manifest bound. Under the standard offline
environment and shared heavy-build lease, run both named tests separately:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects host_key_read_is_refused -- --exact --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects attach_secret_stays_in_memory -- --exact --nocapture
```

Both must fail on the changed refusal after credential coverage finishes.
Restore both files, run the same tests, and require PASS. F-ac8-fixture changes
the relative depth and must fail `host_key::fixture_path_uses_the_guarded_home_rule`.
F-ac8-receipt removes the required launched identity and must fail
`host_key_receipt_requires_this_launched_bundle`. These keep `command: lab`;
the shared runner's lab arm remains with the provider lane.

The existing synthetic-canary test and F-grant-capture also cover the new
printed-journey surface. The controller keeps the exact lines it prints in
memory and checks them again after all grant tokens arrive. The host-file
journey supplies its observed pass/fail result to the existing renderer, so a
planted-grant failure has a failed report with complete version evidence.
F-output-inventory and F-capture-inventory continue to test missing surfaces.
LOG.md records commands, results and local receipt hashes for supervisor review.

## Cleanup census and earlier runs

Run `lab/agent-conformance/run.sh` as before. Before any test, the report tool
checks existing `target/home-*` directories for live holders. For example:

```text
earlier run: PID 12345 root "home-12300-example"
earlier-run check: FAIL; live processes hold earlier Homes; inspect and stop their owners by hand before retrying
```

The PID names a live process. The root name selects a directory under this
lane's `target/`. Inspect that PID's owner and command locally with
`ps -p 12345 -o pid=,ppid=,pgid=,comm=`. Use the process's normal stop control.
If that control is unavailable, confirm the PID still belongs to this test
before sending `kill -TERM 12345`. Let it exit, then run the suite again. The
checker only reports processes; it never signals an earlier owner. Keep the
failed Home for review. Remove its data by hand only after its owner approves
cleanup. Keep Runtime-owned credentials inside the Home out of reports.

The pre-test root selection takes at most two seconds. The shared root census
uses one lsof call with a five-second limit. Every observed holder fails the
check. A timeout, warning or unreadable listing stops the run with a reason.
The scanner stays within Home roots and does not walk native or probe builds.
The report-build step runs before this bounded check.

After a fixture read, `cleanup census:` appears beside `operator census:`.
Read its process count and root-relative paths, API socket count, TMPDIR entry
count and paths, pending count and grant grade. Physical leftovers are FAIL;
the line names the retained `target/home-*`. Passing journeys remove their own
Homes after capture, source and report checks. The census tool's scratch Home
is removed after its captures join the existing credential-check inventory.

The grant result is currently `BLOCKED(AC-021-GRANTS)`: the fixture shell sees
its own grants. `run_leaves_no_live_grant` stays an ignored table row until
Runtime supplies the global live-grant contract in GAPS.md. F-cleanup-grant
waits for that contract. F-cleanup-temp and F-cleanup-process run the existing
`granted_read_succeeds` test; both must fail for their planted reason, then
pass after restoration. Other cleanup falsifiers exercise the port check,
pending and scope grading, capture inventory, earlier-run detection and table
scope. Exact edits and named tests are in `falsifiers.json`; LOG.md records the
measured commands.

Read these rows with the VERSIONS.json path printed by the same invocation:
“cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet
included”. The receipt identifies the Runtime, provider and launched probe
from that run. The census proves the root, API port and TMPDIR checks only.
The known `/tmp/elastos/storage` leftover stays under AC-006-STORAGE; this
command leaves its contents untouched. The earlier absent-policy refusal row
keeps its existing grade and labels pending/grant cleanup as unmeasured.

## Two seeded instances (023)

The rows `two_instances_overlap_with_separate_grants` and
`instance_grant_does_not_authorise_sibling` each run one shared journey and prove the
**process-isolation lab half of A3, A6 and A9**. Run `run.sh` under the shared
build lease. Read the checked `instance overlap:`, `fixture controller:` and
`fixture read:` lines beside the operator census and that run's VERSIONS.json.
The receipt requires both launched component hashes and bundle lab CIDs.

One operator serves two `elastos run` clients. The controller seeds each own
file through the Runtime provider route with distinct bytes. Both clients
request their own read, check every byte in the guest, then request the other
file. Each barrier waits for one pending snapshot with two distinct sessions
and two live children. Its monotonic bound is ten seconds, below the Runtime's
30-second decision wait. The final check requires a recorded decision from
both barriers. One pure `barrier_decision` function checks request shape for
the controller and synthetic tests. The controller grants each own read for its session,
then denies each sibling read with the fixture reason. Both stderr captures
must contain that delivered refusal. The existing collector drains both client
groups; the operator's existing stop and census run before capture checks.

A serial schedule, zero overlap, an early exit, or a failed barrier is FAIL.
Pre-launch prerequisites use the existing SKIPPED path. The output contains
local instance labels and measured times; session IDs and credentials stay in
memory. The shared credential checker covers every capture, the actual printed
lines, rendered table, serialized receipt, committed source and candidate source.

The two builds use `granted-read` with compiler feature subselectors
`instance-1` or `instance-2`, through the existing build helper. Cargo manifests
and lockfiles stay fixed. The probe keeps one read path and imports only the
Bus. Its manifest bound covers both fixture directories, so the Runtime's
session grants decide each read. Artifact identity gives zero grant credit.

F-ac3b grants instance 2 the sibling read; F-ac3c moves its own file into
instance 1's directory; F-ac3d starts the second client after the first exits.
Run each entry's named tests at baseline, with its exact edits, and after byte
restoration. LOG.md records the commands and libtest results.

F-overlap-second-barrier inserts the stage-1 shortcut in `Overlap::ready`;
both the synthetic wiring test and the existing live journey must fail.
F-overlap-sessions, F-overlap-sibling-new and F-overlap-alive remove the
corresponding barrier checks. The alive test starts bounded `true` and `sleep`
children through `RunningInstances::start` with its fixed system PATH.
F-seed-dotdot removes the seed parent-segment refusal. Run each named test
with `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
--test effects TEST_NAME -- --exact --show-output` under the same lease and
600-second bound, at baseline, planted and restored. Every named test must
fail with its planted bug before the entry receives CAUGHT credit.


## Pending-request cancellation

`cancelled_instance_settles_with_reason_sibling_completes` runs the two cached
instance builds against one operator. Read its table row as **cancel at the
pending-request point, lab half of A10 (A12 census)** and use the VERSIONS.json
printed by that same `run.sh` invocation. Both launched bundle identities are
required for the receipt. The report's existing grader retains every row's
grade; this journey adds a label and identity requirements.

The checked `cancel settlement:` line names local instance labels, the fixed
cancel reason, both exit statuses, the first barrier wait, measured overlap,
and elapsed times. Instance-1 exits with its exact denial. Instance-2 first
checks its own file bytes in the guest, then exits with the expected sibling
read denial, as in the two-instance journey. A nonzero sibling exit alone
supplies zero completion evidence. The two older instance rows each run the
same shared journey.

After collection, the controller checks pending requests while the operator
is alive. Its shell-owned pending control proves the live census call can
refuse a leftover and is then denied. The final empty-pending check precedes
operator group stop, root census, API-port closure and the empty `tmp/` check.
Cross-session live grants remain `BLOCKED(AC-021-GRANTS)` and give zero passing
credit. Resident cancellation stays RT4; this row covers the pending-request
point only. GAPS.md defines the cleanup visibility limits.

F-cancel-sibling cancels both first requests and must fail the sibling check.
F-cancel-reason changes the delivered reason. F-cancel-retry bypasses later
request validation. F-cleanup-live-wiring replaces the actual cleanup call
with a fixed success while a control is pending. F-cancel-receipt drops the
cancel row's launched identities. Each uses `command: lab` and its named test
must pass before planting, fail with the edit and pass after restoration.

## Worker kill and orphan settlement

`killed_worker_settlement_recorded_without_retry` covers **kill-worker
settlement, lab half of A11 (A12 census)**. Use the VERSIONS.json from the same
`run.sh` invocation. The receipt requires both existing instance builds, each
with its component hash and complete bundle lab CID.

The first overlap barrier observes both clients alive with distinct pending
requests. The shared controller grants instance-2's first read and leaves
instance-1 pending. The harness sends SIGKILL through instance-1's owned child
handle, reaps it, and records the signal request time. Collection requires an
exit on signal 9. Instance-2 must check its own bytes and receive the same
sibling denial as in 023.

The controller polls through both exits. It accepts only the original orphan
and instance-2's expected sibling request; every retry, including one from a
new session, fails. The spawn path counts each Home's `run` starts. After both
exits the controller measures the orphan, denies it with
`fixture settlement: worker killed`, and checks that the pending list is
empty. A further two-second quiet window polls the same list; five seconds is
the maximum permitted window. The existing cleanup path then checks the
operator and both client roots through its lsof implementation, checks the
closed API port and empty `tmp/` directories, and checks captures for fixture
credentials. Live grants remain `BLOCKED(AC-021-GRANTS)`.

Read the single checked `kill settlement:` line for both child statuses,
signal, kill time, first barrier time, overlap, elapsed times, quiet duration,
and orphan counts before and after settlement. This candidate's orphan is
**settled by the fixture**. AC-027-ORPHAN in GAPS.md describes the Runtime work
needed for automatic settlement. Resident lifecycle support remains RT4.
Both journeys require before 1 and after 0; an already-settled orphan gives FAIL until the lab re-measures AC-027-ORPHAN and cites the Runtime source line.

`no_policy_file_does_not_mean_allow` observes the pending request while the
client waits without approval. After its 30-second refusal it uses the same
orphan-settlement function, with `fixture settlement: client wait ended`, then
runs the normal pending census. Its checked `absent-policy settlement:` line
prints the measured count and settlement owner. The shared settlement formatter
also supplies 026's cancellation line. The existing credential checker covers
all three journeys' captures, printed lines, report, receipt and lane sources;
missing evidence fails with a fixed reason.

Run F-kill-retry and F-kill-sibling from `falsifiers.json` in baseline, planted
and restored steps. The first starts instance-1 again through the existing
spawn path and must fail the launch-count check. The second also kills the
sibling and must fail the sibling outcome check. F-kill-record drops the kill
record, F-kill-monitor accepts requests from other sessions,
F-orphan-settlement omits the shared denial, and F-kill-receipt drops the new
row's identities. Every test named by an entry must fail while planted.
LOG.md records the measured results.

## Real agent-host capsule (028, acceptance blocked)

Sasha can select the additional real-capsule journey with:

```bash
bash lab/agent-conformance/run.sh --agent-host
```

The plain command includes the P7 manifest gap row. The opt-in journey, when
forced with Cargo's `--ignored`, copies only `Cargo.toml`, `Cargo.lock`,
`capsule.json` and `src/` under the lane target,
places the read-only Bus contract beside that build tree, and uses the shared
offline builder, bundle stager, operator, controller and cleanup census.
A passing row requires exactly the journal write and read requests in that
order, both fixture denials, exit 0, and an empty journal-path census. Its
launched component SHA-256 and bundle lab CID belong to the same-run receipt.
Model calls (RT3), UsersAI principal binding, parallel isolation and CID launch
remain separate acceptance work.

`real_agent_host_gets_no_ungranted_authority` is BLOCKED (UsersAI binding): a
principal-scoped CLI launch must let the journal requests reach the shell.
Its exact two-request assertion and label are preserved. See the UsersAI
binding table in GAPS.md. F-agent-host-grant is retired under that blocker,
with its exact mutation bytes kept until the live baseline can pass.
The active agent-host checks under `--agent-host` include
`agent_host_journal_census_detects_planted_paths`,
`agent_host_grants::request_sequence_requires_exact_order_and_one_session`,
`agent_host_copy_takes_only_listed_files`,
`agent_host_row_requires_its_launched_identity`, and
`staging_uses_manifest_entrypoint_and_refuses_escape`. The shared
`agent_host_grants::tests` also run. These exercise the harness with fixtures;
the real capsule's shell-denial journey stays BLOCKED.
