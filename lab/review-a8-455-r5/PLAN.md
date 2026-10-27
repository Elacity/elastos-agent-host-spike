# Review plan r5 of #455

Subject: draft PR #455, head `75bb4d85c157c6191246a8dd5042a08c7b6eacb2`,
code `f062eb8c`, targeting #301 `cursor/a1-a8-hardening-85ce`.

This review only writes under `lab/review-a8-455-r5/`. It does not push
to #455 or #301. It does not edit Runtime source except the subject's
own `runtime-local` plants, which `falsify.py` restores.

## Re-run

1. `cargo fmt --check` on the lane and wasi-guest.
2. `lab/a1-a8-hardening/run.sh`.
3. Forced `--ignored` on the two A8 ignore rows.
4. All 22 plants in `falsifiers.json`, one at a time.
5. `python3 lab/a1-a8-hardening/mutants/binding.py`.
6. SHA-256 restore check after the last plant.

## New hunts

Each hunt asks: would this reach cargo `ok` / later PASS once the
Runtime prints a session id?

- session from time or pid
- session reused across runs
- seal stored where the guest can write
- seal computed before the final flush
- seq overflow or wrap
- seq gaps
- staged-file rename TOCTOU, or mmap, between hash and load
- unicode lookalike JSON keys
- NaN or large numbers
- BOM
- CRLF jsonl
- truncated final line
- symlinked journal
- hardlinked journal
- journal on tmpfs remounted

Hunts live in `tests/r5_hunts.rs` and call the subject's public API.
`attacks/run_plants.py` re-runs the named 22 plants into `evidence/`.
