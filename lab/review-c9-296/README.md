# Adversarial review of PR #296 (C9 / B4 Linux confinement)

This folder reviews draft PR #296. It does not edit `lab/linux-confine/` or
any other lab folder.

Fetch the PR branch into a worktree, then:

```bash
git fetch origin cursor/linux-confine-e156
git worktree add /tmp/wt/linux-confine-296 origin/cursor/linux-confine-e156
cargo test --manifest-path /tmp/wt/linux-confine-296/lab/linux-confine/Cargo.toml --test confine --no-run
python3 -I lab/review-c9-296/run.py
python3 -I lab/review-c9-296/falsify.py
python3 -I -m unittest discover -s lab/review-c9-296 -v
```

`run.py` compiles the escape probe, launches it through #296's `lc-setup`
once on the short filter and once on the provider filter, and runs the same
binary unconfined so a hole is visible. Aarch64 and the Jetson stay NOT RUN.
The runner does not register binfmt_misc or qemu.

Verdicts live in `REVIEW.md`.
