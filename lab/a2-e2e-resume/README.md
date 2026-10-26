# A2 e2e resume

M1 check A2: session journal written through the real Runtime hostcall,
revision-checked, resumable after a process restart.

WRITE, STALE, RESUME, and WRITE2 all go through the guest's
`providers.invoke` hostcall. The driver does not call
`handle_component_resource_request` and does not mint a write token.
Every journey row is computed from journal files, the pinned guest hash,
audit invokes, and exit codes. `Proof.row` refuses PASS. A skip is
`NOT RUN`.

## Journey

| Step | What must be true | How this runner checks it |
| --- | --- | --- |
| WRITE | Guest writes a format-2 journal through the real hostcall | First process; journal on disk; `write:ok`; guest sha256 matches `guest.sha256` |
| STALE | Guest write with a stale `if_revision` is `revision_conflict` | Same process; audited `write:conflict`; stored sha256 stays |
| STOP | That Runtime process exited 0 | First process return code is exactly 0 |
| START | A fresh process opened the same store | `PROCESS second` after setup; different pid; journal still on disk |
| RESUME | The new launch loads the latest revision | Pre-launch store matches; audited `read:ok` |
| WRITE2 | Guest writes again with that loaded revision | Audited `write:ok`; new format-2 revision on disk |

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
| F-REV-SECOND-STALE-WRITE | Second process writes with a stale `if_revision` | WRITE2 FAIL |
| F-REV-OLDER-JOURNAL | State names a different journal than the store | RESUME FAIL |
| F-REV-STORE-WIPE | Store removed between processes | RESUME not PASS |
| F-REV-GUEST-HASH | Last guest wasm byte flipped | WRITE FAIL |
| F-REV-HARDCODED-HARNESS-PASS | Six hardcoded `Proof.row(..., "PASS")` | refused |
| F-REV-SKIPPED-STALE | Guest never sends the stale write | STALE NOT RUN |
| F-REV-STOP-NONZERO | First process exits 1 after WRITE+STALE | STOP FAIL |

## A2 count

A2 stays counted only when WRITE, STALE, STOP, START, RESUME, WRITE2
are computed PASS and every falsifier is CAUGHT.
