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
8 GiB for the Runtime and lane build outputs plus the required 2 GiB of free space. The test needs
the pinned Rust toolchain, its `wasm32-unknown-unknown` target and cached Cargo
dependencies. Both child builds use `build::offline_build`; the probe build
treats compiler warnings as errors. The Runtime build keeps its normal flags
and disables development debug info. A missing build tool, target or dependency fails the check.

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

The regression mutations are in the lane's one [falsifier list](falsifiers.json).
The former F-ac2a through F-ac2f are now F-probe-a through F-probe-f, in the same order.
Apply one mutation at a time and restore its exact bytes after its named test.
Use the offline environment and shared build lease above. The provider lane owns
the shared runner's future `lab` command arm; until then, run these by hand.
F-ac1d uses a synthetic parent environment, so its deliberate environment leak
captures fixture values only. [LOG.md](LOG.md) records the commands and results.

Select each named test with `cargo test --locked --manifest-path
lab/agent-conformance/Cargo.toml TEST_NAME -- --nocapture`. A caught mutation
requires that named test to run and fail; a build or test-loading error does
not count. Restore the source bytes before running the normal suite again.

The [runbook](RUNBOOK.md) gives the one-command table: `lab/agent-conformance/run.sh`.
The `harness` module owns fresh Homes and the one bounded launch primitive.
The Runtime tests use that same primitive to check the no-operator refusal
and the data directory inside the throwaway root. `runtime::runtime_under_test`
builds once per test process in `target/runtime`, hashes the binary with the
Mac's `/usr/bin/shasum`, and returns its absolute path and SHA-256. Build
failures retain Cargo's output and fail the tests. Its hash, like the probe's,
is specific to the machine and toolchain. Passing tests remove their Homes, and failing tests retain their
roots inside this lane's ignored `target/` and print their paths.
