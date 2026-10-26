# lab/review-a9-290-r4

Independent adversarial review, round 4, of draft PR #290
(M1 check A9: another agent's files are denied).

This folder does not edit `lab/owned-storage/`, other `lab/` trees,
or Runtime sources. It does not push to #290's branch
`cursor/owned-storage-a9-9b7c`. It does not touch
`Elacity/elastos-runtime`.

Reviewed head: `c411060d8c86db853fae352dd20d56da019c9d26`
(tested code ancestor `9e0f28552c9862b7c02a92467caaa746217a6c2b`).

```bash
python3 -I lab/review-a9-290-r4/run.py
python3 -I lab/review-a9-290-r4/mutants.py
```

`run.py` uses a detached worktree of #290 (default `/tmp/pr-290-r4`).
It reruns that crate's own tests, then a probe compiled against that crate.
The probe writes nothing into #290.

The verdict is in `REVIEW.md`.
