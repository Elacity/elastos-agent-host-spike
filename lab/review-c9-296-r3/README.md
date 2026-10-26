# Adversarial review of PR #296 C9 fixes (r3)

Draft only. Do not merge. This folder reviews draft PR #296 at
`9a769ad1`. It does not edit `lab/linux-confine/` or any other lab folder.

```text
Lane:         lab/review-c9-296-r3
Branch / PR:  cursor/review-c9-296-r3-2982
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         9a769ad109164c8e40b080d63144d8138141baf0
Tree:         /tmp/wt/linux-confine-296-r3
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6
```

Prior reviews: draft PR #326 (`lab/review-c9-296/`) and draft PR #349
(`lab/review-c9-296-v2/`). This folder re-runs the claimed suite on the
fix head and plants new mutants for the three WEAK items in #349.

```bash
git fetch origin cursor/linux-confine-e156
git worktree add --detach /tmp/wt/linux-confine-296-r3 9a769ad1
export LC_REVIEW_TREE=/tmp/wt/linux-confine-296-r3
python3 -I lab/review-c9-296-r3/run.py
python3 -I lab/review-c9-296-r3/extra.py
python3 -I lab/review-c9-296-r3/mutants.py
python3 -I lab/review-c9-296-r3/build_env.py
python3 /tmp/wt/linux-confine-296-r3/lab/linux-confine/falsify.py
```

Verdicts live in `REVIEW.md`.
