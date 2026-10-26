# jetson-proof-kit log

- 26 Oct 2026, cloud: first cut. `run-on-jetson.sh` records uname and the
  PR #314 Landlock probe, fetches #307 and #296 into `~/flint-elastos-test`,
  builds with `-j 4`, and writes `evidence.txt`. Path and memory guards have
  tests. F-JPK-OUTSIDE and F-JPK-MEM are the two falsifiers. Jetson rows stay
  NOT RUN.
