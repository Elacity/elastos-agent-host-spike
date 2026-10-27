# Review r7 of draft PR #457

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #457 (`cursor/a12-r6-survivors-c4de` at `4564a30f`). This folder
only adds `lab/review-a6-a12-457-r7/`. It does not edit #457's branch,
#343, other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or
Runtime source. It does not merge or close anything.

Subject: draft #457, head `4564a30f1384f1b9d070762eb8e4a8e727bd2959`,
base `cursor/a6-a12-evidence-fix-6e3b` (#343). Prior review: PR #441
of `5547edea` (r6 FIX).

## How to run

Subject worktree at `/tmp/pr457-r7` must be
`4564a30f1384f1b9d070762eb8e4a8e727bd2959` (detached). Then:

```
lab/review-a6-a12-457-r7/run.sh
```

That reruns `./lab/a6-a12-evidence-fix/run.sh` at least three times,
checks that plants restore `manager.rs` byte-for-byte, independently
replants every named plant, and runs the new r7 hunts.

Findings: `REVIEW.md`.

Verdict on this machine: A12 Linux lab half **FIX** (FIFO hang,
weak overflow pin, TMPDIR mid-run false FAIL). A6 **BLOCKED
(RA-6)**. Mac owner commands stay **NOT RUN**. The author's 46
plants / 53 CAUGHT lines hold. Headings `34/39` and `12/14` are
plants / CAUGHT-lines, not a miss rate.
