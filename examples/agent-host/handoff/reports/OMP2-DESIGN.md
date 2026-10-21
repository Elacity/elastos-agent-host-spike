# OMP idea 2 design draft, and the edit provider design note

```text
Slice:        OMP idea 2, design draft only (no code), plus the edit provider design note Sasha asked for on 21 Oct.
Branch / PR:  claude/omp2-design  (draft PR in this repo, base spike/agent-host)
Commit:       the commit that adds this file; parent f5396709c286f1b8f8e2ac020b300395dd29999f (spike/agent-host)
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container).
Changed:      examples/agent-host/handoff/OMP2-DESIGN.md - child limits: depth, budget (requests and wall time,
                whichever first, recorded), result cap as spill pointer, cancel; guest rules and the Runtime layer
              examples/agent-host/handoff/EDIT-PROVIDER.md - all-or-none multi-file write in the object provider
                (if_revision per file), after 0.8.0, Anders decides
              examples/agent-host/handoff/reports/OMP2-DESIGN.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    none (no code).
Tests run:    none (no code change).
Falsifiers:   none run; each proposed test in OMP2-DESIGN.md and EDIT-PROVIDER.md names its falsifier.
Guest hash:   unchanged (no code).
Import list:  unchanged.
Principles:   3, 7 a child's budget, like its resource, is never wider than its parent's; 11 no budget means refused,
                not unlimited; the guest does not pretend to measure time it cannot see; 10 one revision rule, in the
                object provider; 19 one change is one effect, all or none across a crash.
DeepSeek:     none. omp at 2220e58 for ideas only (cited in both notes); no code copied.
Not proven:   Everything here is a proposal. Facts about today's code were read at f5396709c and are cited by file
              and function: the two revision formulas, Library's if_revision check outside the object lock, the one
              process-wide object lock, the migration journal's roll-back, and the token fields max_uses, expiry and
              delegatable.
Checklist:    no item moves.
Questions:    in OMP2-DESIGN.md (depth and cap values, what counts as a model request, top-task default budget,
              option A or B, whether to write the Runtime budget note now) and EDIT-PROVIDER.md "Not decided" (for
              Anders).
```

**What is next:** stop. Building idea 2 waits for Codex to pass PR #24 and for the answers above.
