Slice:        lab/jetson-proof-kit
Branch / PR:  cursor/jetson-proof-kit-fd7b  https://github.com/Elacity/elastos-agent-host-spike/pull/320
Commit:       f563f6c65203da81b6aaa82ed25837a4befe5c62
Parent:       906a6e763bd2d0f644ca4f532dc195fc8246459e   first kit commit
              fec85a34c5aa91df5e722ce70745b2046b61a6d4   spike/agent-host
Develop:      Elacity develop not merged this slice; lab folder only
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), Python 3.12.3, Landlock ABI 6 on this VM
Changed:      lab/jetson-proof-kit/run-on-jetson.sh - operator script for the board
              lab/jetson-proof-kit/lib.sh - path guard and 1 GiB memory guard
              lab/jetson-proof-kit/probe_landlock.py - PR #314 Landlock ABI probe
              lab/jetson-proof-kit/evidence.txt - seven Jetson rows, all NOT RUN
              lab/jetson-proof-kit/tests/test_guards.sh - path, memory, committed rows
              lab/jetson-proof-kit/falsify.sh - F-JPK-OUTSIDE and F-JPK-MEM
              lab/jetson-proof-kit/README.md - operator steps
              lab/jetson-proof-kit/LOG.md - kit log
              examples/agent-host/handoff/reports/jetson-proof-kit.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    The kit writes only under ~/flint-elastos-test, builds with -j 4, stops when MemAvailable is below 1 GiB, and keeps the C0/C9 Landlock floor at 5. A refusal below ABI 5 is the evidence row.
Refusals:     a path outside ~/flint-elastos-test -> REFUSED path is outside
              MemAvailable below 1048576 kB -> REFUSED available memory below 1 GiB
              missing MemAvailable line -> REFUSED MemAvailable is missing
              C0/C9 ABI below 5 -> the guard's own refusal text, unchanged
Tests run:    bash lab/jetson-proof-kit/tests/test_guards.sh -> summary 26 passed 0 failed
              bash lab/jetson-proof-kit/falsify.sh -> F-JPK-OUTSIDE CAUGHT, F-JPK-MEM CAUGHT, summary 2 CAUGHT of 2
              python3 -I lab/jetson-proof-kit/probe_landlock.py -> landlock_abi 6 on this VM
              git diff --check -> clean
Not run here: run-on-jetson.sh on the Jetson Orin Nano. No fetch of #307 or #296 into a board folder. No C0 or C9 binary was started for aarch64. All seven evidence rows stay NOT RUN.
Falsifiers:   F-JPK-OUTSIDE (jpk_path_inside always returns 0) -> planted_path_outside_folder FAILED, then restored on a copy
              F-JPK-MEM (jpk_require_memory always returns 0) -> memory_below_floor_is_refused FAILED, then restored on a copy
              Working tree after falsify.sh: only the intended test-parse fix
Guest hash:   unchanged; no wasm32 build in this slice
Import list:  unchanged
Principles:   3 no ambient authority: the script owns only ~/flint-elastos-test
              11 fail closed then explain: ABI below 5 keeps the guard refusal
              12 docs, code, tests, and operations agree: evidence rows, README, and tests share one status set
DeepSeek:     none
Not proven:   The board kernel, machine, and Landlock ABI. JetPack R36.4.7 is a release name. This VM's ABI 6 is not a Jetson measurement. C0 still needs rustc and a static probe on the board. C9 still needs gcc. A missing tool is a REFUSED row, not an install step.
Checklist:    unchanged
Questions:    none
