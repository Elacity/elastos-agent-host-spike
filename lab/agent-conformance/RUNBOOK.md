# Agent conformance checks

From the repository root on the Mac, with the shared heavy-build lease held, run:

```sh
lab/agent-conformance/run.sh
```

The command uses cached dependencies, the pinned Rust toolchain and its
`wasm32-unknown-unknown` target and the macOS `shasum` tool. Reserve 12 GiB for
builds plus 2 GiB free. The
lease procedure is in [scripts/README.md](../../scripts/README.md#local-pre-push-gate).
The command prints `elastos sha256:<hex>` and `localhost-provider sha256:<hex>`
above one table from Cargo's test inventory and result lines. Each hash identifies
the binary built for the tests. It is computed for this machine and toolchain, as with the probe
hash; it is an identifier, rather than a graded rule. Successful test output
supplies the hash through Cargo's `--show-output`, which preserves result lines.
`ok` becomes PASS. `ignored, blocked: <id> …` becomes BLOCKED with that ID.
A failure, missing result, repeated result, ignored test without a blocker ID,
or Cargo error gives FAIL and a non-zero command exit status. BLOCKED rows
remain open in [GAPS.md](GAPS.md).

- `home_is_throwaway`: checks the Mac data path, fresh root, path guard, symlink refusals and removal after success.
- `launch_env_is_only_the_throwaway_home`: checks the four allowed environment entries, including `ELASTOS_CARRIER_MDNS=0`, null stdin, exit status and both output streams.
- `launch_stops_a_child_past_its_bound`: checks that a one-second bound stops a three-second sleep with the exact timeout reason.
- `run_without_operator_is_refused_with_reason`: runs the probe through the bounded launch primitive in a fresh Home and requires a nonzero exit with `This command requires a running runtime.` on stderr.
- `runtime_data_dir_is_under_throwaway_home`: places a dummy coordinates file in the guarded data directory and requires Runtime to remove it and return the same refusal reason. Its documentation-address URL is rejected before any network call.
- `serve_refuses_provider_whose_bytes_differ_from_its_hash`: installs the provider and its hash, appends one byte to the copy, and requires a nonzero `serve` exit with `localhost-provider` and `failed checksum verification` on stderr. It also checks that storage exists inside the root and the readiness file is absent.
- `run_table_requires_cargo_results`: checks PASS, BLOCKED and FAIL grading against Cargo-format result fixtures.
- `foreign_and_wrong_version_imports_are_refused`: rejects imports outside the probe's Bus subset.
- `non_component_and_invalid_component_are_refused`: rejects a core module and invalid component bytes.
- `probe_hash_is_stable`: compares the SHA-256 values from two fresh builds on this Mac.
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
grant, effect and bundle-CID checks belong to later tasks.

`tests/common::write_operator_home` owns the operator fixture for this test and
the ready-operator tests. It checks the Home guard, installs an executable copy, and
writes a manifest containing only the repository's `external.localhost-provider`
entry and an empty `profiles` map. It stamps the current Mac platform with the
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

Task 013 adds these rows to the same Cargo-derived table:

- `fixture_operator_starts_ready_and_stops_cleanly`: installs matching provider bytes, copies the two-setting config, checks coordinates existence and HTTP 200 within 60 seconds, checks sockets, and requires group exit within the ten-second stop bound. This is the positive control for 012's native platform key.
- `fixture_operator_sockets_are_loopback_only`: measures every internet socket in the operator group at readiness and at least three seconds later. Both samples require the loopback API listener. `run.sh` also prints their socket counts.
- `socket_census_requires_parseable_loopback_endpoints_and_api_listener`: checks field-format parsing with IPv4/IPv6, connected sockets, wildcard and remote addresses, malformed listings and missing API visibility.
- `managed_child_stop_reaps_its_process_group`: checks SIGTERM and group cleanup with a parent and child fixture.
- `managed_child_drop_kills_its_group_and_keeps_root`: checks emergency group cleanup and root retention when a handle is dropped before stop.

The [operator recipe](GAPS.md#operator-in-a-throwaway-home) owns the ordered
setup and its measurement limits. `fixtures/operator-config.toml` selects
unsigned admission and a loopback Carrier bind. Admission grants no resource.
The coordinates file is checked for existence only; the harness leaves its
contents and operator captures unread. System `kill`, `pgrep` and `lsof` use
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

The artifact rows now cover default, read and network builds. Each selector has
two fresh builds, matching hashes within its pair, and a distinct hash from the
other selectors. `run.sh` prints `probe component sha256:<hex> effect:<selector>`
for the built bytes and live copies. The existing component build script uses
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
