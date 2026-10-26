# jetson-proof-kit log

- 26 Oct 2026, cloud: first cut. `run-on-jetson.sh` records uname and the
  PR #314 Landlock probe, fetches #307 and #296 into `~/flint-elastos-test`,
  builds with `-j 4`, and writes `evidence.txt`. Path and memory guards have
  tests. F-JPK-OUTSIDE and F-JPK-MEM are the two falsifiers. Jetson rows stay
  NOT RUN.
- 26 Oct 2026, cloud: `tests/test_guards.sh` reads evidence as TSV so `NOT RUN`
  stays one status. 26 passed. Both falsifiers caught on copies.
- 26 Oct 2026, cloud: host probe now records ABI, per-right bits, seccomp,
  unprivileged namespaces, gating sysctls, and CapBnd. `decide.py` prints a
  launch/refuse table for did, wallet, and model under the ABI 5 floor and
  the per-right floor. C0 source is selectable with `JPK_C0_PR`. Simulated
  kernel fixtures and F-JPK-ABI cover a mis-reported ABI. Jetson rows stay
  NOT RUN.
