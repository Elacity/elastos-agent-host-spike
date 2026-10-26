# Agent conformance suite

This workspace builds the lab component through the repository's existing
`scripts/build-component-capsule.sh`. Runtime owns launch, identity and grants.
The default component returns an explicit unavailable result at activation.
The `read` and `network` builds request one ungranted resource and return the
Runtime refusal through the Bus. [GAPS.md](GAPS.md) records the remaining
selector, model-call and storage-containment blockers.

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
12 GiB for generated files plus the required 2 GiB of free space. The test needs
the pinned Rust toolchain, its `wasm32-unknown-unknown` target and cached Cargo
dependencies. The shared `build::offline_build` setup keeps Cargo targets,
intermediates and temporary files under this lane's `target/`. Probe builds
treat warnings as errors; the Runtime build uses its normal warning policy.
A missing build tool, target or dependency fails the check with its output.

`runtime::runtime_under_test` builds the checkout's `elastos` binary once per
test process with `cargo build --locked --offline --manifest-path
elastos/Cargo.toml -p elastos-server --bin elastos`. It caches a build failure
as well as a success. The build uses the developer's toolchain environment,
sets `CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_INCREMENTAL=0`, and clears inherited
Rust flags. Its one target is `target/runtime`, with intermediates in `build/`
and temporary files in `tmp/` below that target. It returns the absolute binary
path and a SHA-256 computed from its bytes by macOS `shasum`. This identifies
the Runtime tested on this machine; it is separate from capsule bundle identity.

`probe_imports_only_the_bus` validates the built component and checks its outer
imports against the five-interface Bus v1 subset. `probe_hash_is_stable` makes two
fresh builds for each selector, compares their SHA-256 values and requires
distinct bytes across selectors. These checks share the builds within one test
process through `tests/common/probe.rs`. Each build directory and the shared
entrypoint are removed after the artifact bytes have been copied into memory; after an interrupted run, the next test
recreates those directories. Host build outputs are rebuildable files under this lane. Live effect tests
copy component bytes into a hash-named directory inside their fresh Home.
The shared staging path names the complete manifest and payload with
`capsule_identity::checked_bundle`. Build-only and launched identities use one
typed observation format.

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

The [runbook](RUNBOOK.md) gives the one-command table and retained `VERSIONS.json` receipt: `lab/agent-conformance/run.sh`.
The `harness` module owns fresh Homes and the one bounded launch primitive.
The no-operator Runtime checks require the operator-lookup refusal. The effect
checks use the ready operator recipe and require the guest lifecycle refusal. A decoy coordinates file proves which data
directory the Runtime reads. Passing tests remove their Homes, and failing tests retain their
roots inside this lane's ignored `target/` and print their paths.
