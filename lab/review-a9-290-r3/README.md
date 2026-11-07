# lab/review-a9-290-r3

Independent adversarial review, round 3, of draft PR #290
(M1 check A9: another agent's files are denied).

This folder does not edit `lab/owned-storage/`, other `lab/` trees,
or Runtime sources. It does not push to #290's branch.

Reviewed head: `8d4d50104edcfd1eee03e4cd93816e7ed62b6088`
(tested code ancestor `578e0959a374af726bbc8f113afdbb5e7723636d`).

```bash
python3 -I lab/review-a9-290-r3/run.py
python3 -I lab/review-a9-290-r3/mutants.py
```

`run.py` uses a detached worktree of #290 (default `/tmp/pr-290-r3`).
It reruns that crate's own tests, then a probe compiled against that crate.
The probe writes nothing into #290.

The verdict is in `REVIEW.md`.
