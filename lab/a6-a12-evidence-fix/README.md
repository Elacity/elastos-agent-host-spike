# A6 / A12 evidence fix

Lab-only checks for the two #294 holes that #323 left as NEEDS RUNTIME.
This folder calls Runtime `CapabilityManager::grant` / `validate` and owner
`census::cleanup` / `ThrowawayHome`. It does not edit those crates,
`BACKLOG.md`, `lane.env`, or `scripts/`.

## What the checks prove

- **A6:** instance-1 is granted a real session token. `validate` accepts that
  token as instance-1. The same token as instance-2 is `WrongCapsule
  { expected: instance-1, got: instance-2 }` (fields compared, not
  substrings). `instance-1-evil` and an empty token capsule are refused the
  same way. This is an in-process Runtime library journey. It is not two
  resident capsule instances inside one Home.
- **A12:** leftover census honours `ELASTOS_TMP_ROOT` (default `/tmp/elastos`
  when unset). A run that creates `{root}/storage` is scanned. Symlink roots
  are resolved. Renamed leftover trees are found by marker bytes. A clean
  isolated root is PASS. `ThrowawayHome::new` + `census::cleanup` are called;
  on Linux that construction is NOT RUN.

## How to run

From the repository root:

```sh
cargo fmt --manifest-path lab/a6-a12-evidence-fix/Cargo.toml -- --check
CARGO_NET_OFFLINE=true \
CARGO_TARGET_DIR="$PWD/lab/a6-a12-evidence-fix/target" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
cargo test --locked --offline --manifest-path lab/a6-a12-evidence-fix/Cargo.toml --lib -- --nocapture
```

Or `./lab/a6-a12-evidence-fix/run.sh`.

The Mac evidence pack can point leftovers at an isolated folder:

```sh
ELASTOS_TMP_ROOT=/path/to/isolated-tmp ./lab/a6-a12-evidence-fix/run.sh
```

`planted_bugs_are_caught` applies the plants under `plants/` and requires
each named test to print `FAILED`.

## NOT RUN on Linux

Resident instances and throwaway Homes need macOS:

```sh
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  two_instances_overlap_with_separate_grants -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  instance_grant_does_not_authorise_sibling -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
  cleanup_census_refuses_each_leftover -- --nocapture
```

Those skips are not passes. A6 and A12 stay in-flight for Anders's
resident-instance rule.
