# lab/review-a9-290-r2

Independent adversarial review, round 2, of draft PR #290
(M1 check A9: another agent's files are denied).

This folder does not edit `lab/owned-storage/`, other `lab/` trees,
`BACKLOG.md`, `lane.env`, or `scripts/`. It does not change the Runtime.
It does not push to #290's branch.

Reviewed head: `2e5c37293279996fcb98ee2623381264f2d92e3f`
(`cursor/owned-storage-a9-9b7c`).

```bash
python3 -I lab/review-a9-290-r2/run.py
python3 -I lab/review-a9-290-r2/mutants.py
```

`run.py` uses a detached worktree of #290 (default `/tmp/pr-290-r2`).
It reruns that crate's own tests, then a probe compiled against that crate.
The probe writes nothing into #290.

The findings table and the bookability verdict are in `REPORT.md`.
