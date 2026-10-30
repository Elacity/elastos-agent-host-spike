# A6 / A12 evidence fix

Lab-only corrected checks for the two #294 evidence holes that #323 left as
NEEDS RUNTIME. This folder invokes the agent-conformance census and
`ThrowawayHome` by source and name (`existing.rs`, `EXISTING_CLEANUP`).
It does not compile that crate and does not edit that lane, `BACKLOG.md`,
`lane.env`, `scripts/`, or Runtime source.

## What the checks prove

- **A6:** instance-1 may use its session token. Instance-2 presenting that
  token is refused with `wrong_capsule`. The Runtime source still has
  `validate` step 4 (`token.capsule != caller_capsule_id`). The existing A6
  rows never present a token, so they stay a documented gap.
- **A12:** the cleanup census includes `/tmp/elastos/storage` and
  `/tmp/elastos`. A leftover (including an empty directory or a planted file)
  fails the check. The existing census still inspects only the throwaway
  TMPDIR.

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

`planted_bugs_are_caught` applies `plants/F-A6-NO-TOKEN-CHECK.txt` and
`plants/F-A12-DROP-ROOTS.txt` in a child crate build and requires those named
tests to print `FAILED`.

The full agent-conformance A6/A12 journeys need a macOS throwaway Home and
Runtime resident instances. On Linux they are NOT RUN. That does not count
as a pass, and it does not move A6 or A12 off in-flight.
