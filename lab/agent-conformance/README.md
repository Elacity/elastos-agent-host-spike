# Agent conformance probe

This workspace builds the lab component through the repository's existing
`scripts/build-component-capsule.sh`. Runtime owns launch, identity and grants.
The component currently returns an explicit unavailable result at activation;
[GAPS.md](GAPS.md) describes the missing selector and result channel.

From the repository root, run:

```sh
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
CARGO_NET_OFFLINE=true \
CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host" \
CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -- --nocapture
```

Use the repository's shared heavy-build lease for the test command. Reserve
2 GiB for generated files plus the required 2 GiB of free space. The test needs
the pinned Rust toolchain, its `wasm32-unknown-unknown` target and cached Cargo
dependencies. Its child builds run offline and treat compiler warnings as
errors. A missing build tool, target or dependency fails the check.

`probe_imports_only_the_bus` validates the built component and checks its outer
imports against the task's three-interface Bus subset. `probe_hash_is_stable` makes two
fresh builds, compares their SHA-256 values and prints the result. These checks
share the two builds within one test process. Each build directory is removed
after its artifact has been read; after an interrupted run, the next test
recreates those directories. Host build outputs and the final component are
rebuildable files under this lane.

The artifact hash is specific to the machine and toolchain. Cargo symbol hashes
can differ across hosts. Publication and admission must bind the complete
signed bundle through Runtime's content path; an artifact hash alone proves
neither of those steps.

The regression falsifiers are source mutations, applied one at a time and
restored after each test. Use the same environment and lease as above:

| ID | Planted change | Required failing test |
| --- | --- | --- |
| F-ac2a | In `probe/src/lib.rs`, replace the `run_probe` refusal with `Ok(())`. | `probe_refuses_without_a_launch_argument_channel` |
| F-ac2b | In `tests/artifact.rs`, replace the `allowed_import` catch-all refusal with `Ok(())`. | `foreign_and_wrong_version_imports_are_refused` |
| F-ac2c | In `tests/artifact.rs`, remove the `Parser::is_component` guard. | `non_component_and_invalid_component_are_refused` |
| F-ac2d | In `probe/capsule.json`, replace `wit_world_sha256` with 64 zeroes. | `probe_manifest_names_the_current_bus_world` |
| F-ac2e | In `build_probe`, append one zero byte to the returned artifact only for round 2. | `probe_hash_is_stable` |
| F-ac2f | In `imports`, remove the component validator call. | `non_component_and_invalid_component_are_refused` |

Select each named test with `cargo test --locked --manifest-path
lab/agent-conformance/Cargo.toml TEST_NAME -- --nocapture`. A caught mutation
requires that named test to run and fail; a build or test-loading error does
not count. Restore the source bytes before running the normal suite again.
