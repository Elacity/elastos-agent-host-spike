# Review r6 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b` at `5547edea`). This folder
only adds `lab/review-a6-a12-343-r6/`. It does not edit #343's branch,
other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime
source.

Prior reviews: PR #365 of `011d01f2` (FALSIFIED); PR #380 of
`732b6990`; PR #394 of `87b974a1` (r3); PR #412 of `19becdd7` (r4);
PR #422 of `9d55f8fb` (r5: `/var/tmp` and `/dev/shm` unseen; write-then-delete
unseen; sparse hash equaled zeros; 64 KiB hash cap survived the named
test; empty-handle fallback; parent-swap without re-check wrote
outside; stubbed `prove`/`inspect` PASSed two sleep pids).

## How to run

Subject worktree at `/tmp/pr343-r6` must be
`5547edeacab167bd822e90a6af7258c5d55f2ce1` (detached). Then:

```
lab/review-a6-a12-343-r6/run.sh
```

That reruns `./lab/a6-a12-evidence-fix/run.sh`, checks that plants
restore `manager.rs` byte-for-byte, independently replants the 34
named plants, reapplies the r5 survivor mutants, and runs the new r6
hunts against the author's NOT COVERED list and beyond.

Findings: `REVIEW.md`.
