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
- 26 Oct 2026, cloud: fix the #338 JPK findings. `decide.py` is a labeled
  oracle of #307 `2c70a0d8`. Default C0 pin is that commit. Refusal text
  matches `missing_rights_reason`. `CAP_SETPCAP` is bit 8. A real stand-in
  is launched for did, wallet, and model. Absent rights stamp `ABSENT`.
  A lying ABI 5 launches under per_right because #307 trusts the ABI
  number. Jetson rows stay NOT RUN.
- 26 Oct 2026, cloud: harden the live-board safety gaps from #345.
  TMPDIR, CARGO_HOME, and src stay under `~/flint-elastos-test`. The
  script refuses uid 0 and a `SUDO_*` environment. A memory stop kills
  the process group. `prep-offline.sh` vendors C0 so the board can build
  with `--offline`. Host-surface tokens stay unnamed. Jetson rows stay
  NOT RUN.
