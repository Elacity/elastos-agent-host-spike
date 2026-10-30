# Review r5 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b` at `9d55f8fb`). This folder
only adds `lab/review-a6-a12-343-r5/`. It does not edit #343's branch,
other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime
source.

Prior reviews: PR #365 of `011d01f2` (FALSIFIED); PR #380 of
`732b6990`; PR #394 of `87b974a1` (r3); PR #412 of `19becdd7` (r4:
Pass path accepted this pid plus pid 1; FileId missed same-bytes
reuse and a large in-place rewrite; isolation-under and live
`/tmp/elastos` snapshot halves untested; write after a leaf symlink
swap landed outside).

## How to run

Subject worktree at `/tmp/pr343-r5` must be
`9d55f8fbd670bbaef9cd329fd795b5fb5cb9c04e` (detached). Then:

```
lab/review-a6-a12-343-r5/run.sh
```

That reruns `./lab/a6-a12-evidence-fix/run.sh`, checks that plants
restore `manager.rs` byte-for-byte, independently replants the 25
named plants, reapplies the two r4 mutants, and runs the new r5
hunts.

Findings: `REVIEW.md`.

Verdict on this machine: A12 Linux lab half **PASS**. A6 **BLOCKED
(RA-6)**. Mac owner commands stay on hold.
