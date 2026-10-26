# A2 e2e resume

M1 check A2: session journal written through the real Runtime bridge,
revision-checked, resumable after a process restart.

This folder is a new lab. It copies the #331 `lab/a2-e2e-proof` idea and
replaces the hardcoded resume FAIL. Every journey row is derived from
driver or process output. A skip is `NOT RUN`, never `PASS`.

## Journey

| Step | What must be true | How this runner checks it |
| --- | --- | --- |
| WRITE | Guest writes a format-2 journal through the real bridge | First `a2-resume-driver` process; `ROW WRITE` from stored bytes |
| STALE | A write with a stale `if_revision` is `revision_conflict` | Same process, same store; stored bytes stay |
| STOP | That Runtime process has exited | First process return code |
| START | A fresh process opens the same store | Second process prints `PROCESS second` |
| RESUME | The new launch loads the latest revision and does not overwrite | Guest launch on the fresh process; sha256 and revision match |
| WRITE2 | A write that names that revision is stored | Bridge write with the loaded `if_revision` |

## Run

From the repository root, with Rust 1.91.0 and `wasm32-unknown-unknown`:

```sh
export RUST_TEST_THREADS=2
lab/a2-e2e-resume/run.sh
```

`run.sh` writes `evidence.txt`, then plants each falsifier, reruns the
affected phases, and restores the file.

## Falsifiers

| Id | Plant | Must be CAUGHT by |
| --- | --- | --- |
| F-A2-CREATE-ONLY | `run()` writes with `create_only` on a new launch | RESUME FAIL |
| F-A2-SKIP-LOAD | `load_latest_journal` always returns no journal | RESUME FAIL |
| F-A2-REVISION | A stale `if_revision` write returns ok | STALE FAIL |

## A2 count

A2 stays counted only when WRITE, STALE, STOP, START, RESUME, WRITE2
are PASS and every falsifier is CAUGHT.
