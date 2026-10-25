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
- `launch_env_is_only_the_throwaway_home`: checks the three allowed environment entries, null stdin, exit status and both output streams.
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
The launch primitive clears the parent environment and sets HOME, TMPDIR and
the fixed system PATH. The environment test checks that complete allowlist.
F-ac1c selects the inherited HOME and proves the guard refuses it before any
read. These checks protect the real Home by construction; they never read its
data. The fixture stores a selector, rather than a user's Home path.

These rows prove the harness, probe artifact and Runtime refusal rules.
Each native binary builds at most once per test process, with failures cached too.
Runtime and localhost-provider share the build settings, SHA-256 helper and
`target/runtime`; warm runs reuse Cargo's cached artifacts. All live checks share
the Runtime build.
The build keeps the developer's toolchain environment. Each Runtime launch uses
`harness::ThrowawayHome::launch` and its cleared environment. The operator lookup
returns before the storage constructor; AC-006-STORAGE remains open. Ready operator,
grant, effect and bundle-CID checks still need their own proof.

`tests/common::write_operator_home` owns the operator fixture for this test and
later operator tests. It checks the Home guard, installs an executable copy, and
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
owns ready-operator proof and the AC-010-OFFLINE decision.

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
