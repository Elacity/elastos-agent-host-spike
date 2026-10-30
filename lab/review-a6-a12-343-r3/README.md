# Review r3 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b` at `87b974a1`). This folder
only adds `lab/review-a6-a12-343-r3/`. It does not edit #343's branch,
other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime
source.

Prior reviews: PR #365 of head `011d01f2` (FALSIFIED); PR #380 of head
`732b6990` (A6 and A12 not bookable). Author claims a created-set
census, a tmp guard, isolated `run.sh` / `mac-pack.sh`, named r2
probes, and an RA-6 journey that stays BLOCKED and FAILs if validate
step 4 is removed.

## How to run

Subject worktree at `/tmp/pr343-r3` must be `87b974a1631efcf48e103f84d028eb5b1a2a3c7f`. Then:

```
lab/review-a6-a12-343-r3/run.sh
```

That reruns `./lab/a6-a12-evidence-fix/run.sh`, checks that plants
restore `manager.rs` byte-for-byte, independently replants every r2
survivor, and runs the new r3 hunts.

Findings: `REVIEW.md`.
