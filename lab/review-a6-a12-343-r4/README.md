# Review r4 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b` at `19becdd7`). This folder
only adds `lab/review-a6-a12-343-r4/`. It does not edit #343's branch,
other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime
source.

Prior reviews: PR #365 of head `011d01f2` (FALSIFIED); PR #380 of head
`732b6990` (A6 and A12 not bookable); PR #394 of head `87b974a1` (r3:
RA-6 stub Ok was PASS; guard accepted `..` and a live-Home symlink;
census missed `$TMPDIR`/XDG, inode reuse, and writes before the
snapshot).

## How to run

Subject worktree at `/tmp/pr343-r4` must be
`19becdd74c3f96d5900487051d2e175fd5c06747` (detached). Then:

```
lab/review-a6-a12-343-r4/run.sh
```

That reruns `./lab/a6-a12-evidence-fix/run.sh`, checks that plants
restore `manager.rs` byte-for-byte, independently replants the named
plants, ports the r3 hunts, and runs the new r4 hunts and mutants.

Findings: `REVIEW.md`.
