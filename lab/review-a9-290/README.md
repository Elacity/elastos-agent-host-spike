# lab/review-a9-290

Independent adversarial review of draft PR #290 (M1 check A9).

This folder does not edit `lab/owned-storage/`, other `lab/` trees,
`BACKLOG.md`, `lane.env`, or `scripts/`. It does not change the Runtime.

Reviewed head: `c0b16491076c30366a3504066499c9f5ad831ef2`
(`cursor/owned-storage-a9-9b7c`).

```bash
python3 -I lab/review-a9-290/run.py
python3 -I lab/review-a9-290/check.py
```

`run.py` uses a read-only worktree of #290 (default `/tmp/pr-290-readonly`).
It runs that crate's own tests, then a probe compiled against that crate.
The probe writes nothing into #290.

The findings table and the bookability verdict are in `REVIEW.md`.
