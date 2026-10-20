# S3 design

```text
Slice:        S3 design, no code. Overnight 1, item 4.
Branch / PR:  claude/overnight-1  https://github.com/SashaMIT/elastos-agent-host-spike/pull/3 (draft)
Commit:       the commit that adds this file; parent 989fa4c345e2eee0a5d93aa54c94e93103e4f44c (end of S2)
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/handoff/S3-DESIGN.md - the design (new)
              examples/agent-host/handoff/reports/S3-design.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    None; no code changed. The design states the S3 invariant: an append is written only by the
              Runtime, only with a grant for that exact journal, only as a compare-and-swap on the version
              the guest read, and only under the agent principal's own UsersAI root.
Refusals:     Listed in S3-DESIGN.md section 4 (attack list).
Tests run:    none new. The tree is the S2 tree plus two documents (verify.sh 86 passed at the end of S2).
Not run here: n/a
Falsifiers:   none; this item makes no code claim. Every code fact in S3-DESIGN.md has a file and line. I
              re-read each one at this branch. Facts I took from a helper and did not open myself are
              marked "read by a helper".
Guest hash:   fa10cca7929f1d538e914337999230e9daf6cd5413edf8256824ceb893d6be33 (unchanged since S2)
Import list:  unchanged. S3 would change it (providers, maybe capabilities), and the design says so.
Principles:   3, 7, 11, 16, 18, 19. See the design: UsersAI/self parallels Users/self (7); no grant,
              a foreign root, or a stale version fails closed (11); settlement_unknown stays explicit (19).
DeepSeek:     none
Not proven:   Everything in the design. It is a plan.
Checklist:    56 of 63 (no todo moved)
Questions:    1. Security finding, details for Sasha (S3-DESIGN.md section 5, item 1): UsersAI paths are not
                 scoped to a principal, the shell's agent-mode defaults allow localhost://UsersAI/*, and two
                 launch paths default the shell to auto-grant when ELASTOS_SHELL_MODE is unset. Shipping code,
                 not spike code. Not tested on an installed Home.
              2. Which principal owns an agent's journal (S3-DESIGN.md section 5, item 2)?
              3. Guest-requested grant or launch-time grant (section 5, item 3)?
              4. Confirm grants are not stored (S2).
```

## Why the run stops here

`OVERNIGHT-1.md` stops the run on "a question about security, grants, or signing that the files do not answer". Question 1 is one. S3 would put an agent's private journal under `UsersAI`. Today nothing in the Runtime scopes `UsersAI` to a principal, and I cannot tell from the files how the shell's mode defaults behave on an installed Home. I stopped after finishing this design rather than guess past it.

Item 5 (guard sweep) was not started. It changes no code and does not depend on Question 1, so it can run in the next session as it is written.

## What is next

Sasha answers the four questions. Then: the guard sweep (item 5 of this plan), and S3 only after a yes.
