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
              examples/agent-host/handoff/RUNTIME-BUDGET.md - budget fields on capability grants, for Anders after
                0.8.0 (added after Sasha's answers)
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
              and function: the two revision formulas, the one
              process-wide object lock, the migration journal's roll-back, and the token fields max_uses, expiry and
              delegatable.
Checklist:    no item moves.
Questions:    answered by Sasha on 21 Oct; see the update below.
```

## Update: Sasha's answers applied (21 Oct)

- EDIT-PROVIDER.md: the Library write point is now one line, with a pointer to the private note. The principal-root
  revision formula is agreed.
- OMP2-DESIGN.md:
  - depth limit 2 and a 4,000-byte result cap are kept;
  - one counter for every model call, hosted or local;
  - the top task's budget comes from its grant (host default, visible, raisable), and the guest never sets it;
  - children need an explicit budget;
  - cancel now stops the whole tree at the next model call, keeping partial results marked `cancelled`.
- **Option A is not possible without changing what a field means**, so the draft uses option B (format 2):
  - `argv` would change meaning;
  - a labelled Person record can be forged by a person's message that starts with the label.

  Format 2 needs Sasha's yes before building.
- RUNTIME-BUDGET.md added, for Anders after 0.8.0.

## Update: journal format 2 note (21 Oct)

Sasha said yes to format 2:
- a format 1 journal is refused with a clear reason, and there is no migration;
- every record gets a typed kind, so a person's message can never read as a record;
- one refusal record per refusal is right.

JOURNAL-FORMAT-2.md is the design:
- the header, node and step bytes, with room for the idea 2 fields (reserved, empty until then);
- the decode refusals;
- the tests, including the required falsifier "a message that starts with each label stays a message".

No code until PR #24 passes Codex.

**What is next:** wait for Codex on PR #24. Then the format 2 PR (code), then idea 2 on top of it.
