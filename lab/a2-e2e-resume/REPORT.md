# A2 e2e resume

```text
Lane:         lab/a2-e2e-resume
Branch / PR:  cursor/a2-e2e-resume-27c8  https://github.com/Elacity/elastos-agent-host-spike/pull/351
Base:         cursor/a2-journal-load-b1e8 db8f7510d99f4e1f887801fc642861043d10b474
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Guest:        sha256:b234ac47ca4f52de27b17ff999ec2af6b9694135e53bf059e49c16897df058e4
```

## Independent review of #341

`open_task_journal` / `load_latest_journal` load a stored format-2 journal
and do not write. `create_only` runs only when nothing is stored. A stale
`if_revision` is still `revision_conflict`. No new guest imports. #341's
host test is FakeRuntime in one process. This lab is the process restart.

## Journey

| Step | Result | Evidence |
| --- | --- | --- |
| WRITE | PASS | first process; format-2; revision `5a9ce060…ae6b01bc` |
| STALE | PASS | `revision_conflict`; sha256 unchanged |
| STOP | PASS | first process exited 0 |
| START | PASS | second process on the same store |
| RESUME | PASS | same revision and sha256 |
| WRITE2 | PASS | write with loaded revision; new revision `5e3156e3…9040cfeb` |

Skipped rows: none. A2_counted: yes.

## Falsifiers

| Id | Result | Caught by |
| --- | --- | --- |
| F-A2-CREATE-ONLY | CAUGHT | RESUME FAIL |
| F-A2-SKIP-LOAD | CAUGHT | RESUME FAIL |
| F-A2-REVISION | CAUGHT | STALE FAIL |

Raw log: `lab/a2-e2e-resume/evidence.txt`.

Do not merge.
