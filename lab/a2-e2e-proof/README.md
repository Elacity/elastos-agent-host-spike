# A2 e2e proof

M1 check A2: session journal written through the real Runtime bridge,
revision-checked, resumable by head hash.

This folder does not edit the Agent Host lane or the Runtime tests. It
builds the pinned Runtime, starts it, runs the ignored A2 e2e tests
with `--ignored`, and records whether the whole journey passes.

## Why the e2e is ignored

The named test is
`runtime::tests::the_agent_host_writes_and_reads_its_journal_through_the_real_bridge`
in `elastos/crates/elastos-server/src/runtime.rs`. It is marked:

```text
#[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
```

It is ignored because it loads a built guest WASM that is not in git
and is not built by CI. It is not marked flaky or broken. A default
`cargo test` reports `ignored`, not `ok`. This runner never counts
that skip as a pass.

Two sibling tests share the same ignore:

- `the_agent_host_stores_nothing_when_its_journal_grants_are_denied`
- `the_agent_host_refuses_a_format_1_journal_with_its_reason`

## Journey

| Step | What must be true | How this runner checks it |
| --- | --- | --- |
| Write | Guest writes the journal through the real bridge | Ignored e2e, run with `--ignored` |
| Stale revision | A write with an old `if_revision` is refused with its reason | Bridge unit `a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept` plus the same reason on the live serve path when the harness can reach it |
| Resume | After the Runtime restarts, a read returns the latest revision | Equivalent harness on a persisted data dir; if the shipped guest cannot do this, the step is FAIL |

A skip is a FAIL.

## Run

From the repository root, with Rust 1.91.0 and `wasm32-unknown-unknown`:

```sh
export RUST_TEST_THREADS=2
lab/a2-e2e-proof/run.sh
```

`run.sh` writes `evidence.txt`. `python3 -I lab/a2-e2e-proof/falsify.py F-A2-REVISION`
applies one plant, runs the named test, restores the file, and prints
CAUGHT only when that test fails at its assertion.

## A2 count

A2 stays counted only when write, stale-revision refusal, resume after
restart, and one CAUGHT falsifier all pass. See `REPORT.md`.
