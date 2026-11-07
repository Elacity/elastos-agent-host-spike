# Review r2 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b` at `732b6990`). This folder
only adds `lab/review-a6-a12-343-r2/`. It does not edit #343's branch,
other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime
source.

Prior review: PR #365 at head `011d01f2` (FALSIFIED). Author claims the
six surviving mutants are now CAUGHT.

## How to run

Subject worktree at `/tmp/pr343-r2` must be `732b6990`. Then:

```
lab/review-a6-a12-343-r2/run.sh
```

That reruns `./lab/a6-a12-evidence-fix/run.sh`, checks that plants
restore `manager.rs` byte-for-byte, replants every #365 mutant, and
runs the new r2 probes.

Findings: `REVIEW.md`.
