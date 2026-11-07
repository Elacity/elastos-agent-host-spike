# Fixes after overnight 1

```text
Slice:        Small fixes from the PR #3 review (item a of the 20 Oct plan). Docs only.
Branch / PR:  claude/fixes-after-overnight-1  (draft PR in this repo; link in LOG.md and the PR)
Commit:       the commit that adds this file; parent cc845e1 (merge of claude/overnight-1, PR #3, review PASS)
Base:         origin/spike/agent-host 6883dda. PRs #1-#3 are not merged yet, so this branch merges
              claude/overnight-1 (which contains #1 and #2) first. Merge commits only.
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/handoff/HANDOFF.md - section 10 gains the S1 server test and the no-store
                Node test; the S2 round-trip wording says decode(encode(j)) is without_grants(j)
              examples/agent-host/handoff/S3-DESIGN.md - the review answers: the journal goes under
                Users/self/.AppData/Agents/<agent-id>/ for now (moves to UsersAI once the Runtime scopes it);
                the launching person owns it; a grant at launch, no capabilities import; writes only through
                write_principal_root_object_if_revision; the 5(a) note that UsersAI is 0700 on disk but has no
                principal mapping; the installed-Home check result; new open question 5 (import list)
              examples/agent-host/handoff/USERSAI-JOURNAL.md - the resource line follows the answer (Users/self
                for the spike, UsersAI later)
              examples/agent-host/handoff/reports/fixes-after-overnight-1.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    none (docs only)
Refusals:     none
Tests run:    (cd elastos && cargo test -p elastos-server launch_refuses_untrusted) -> "test result: ok. 1 passed",
                exit 0, 5 min 38 s from a cold integration-test build (the new HANDOFF line works as written)
              node --test scripts/home-agent-no-store.test.mjs -> "# pass 2 # fail 0"
Not run here: nothing else; no code changed (verify.sh 86 at fcd27b7 still holds).
Falsifiers:   none; no code claim. The new HANDOFF commands were run as written (above).
Guest hash:   fa10cca7929f1d538e914337999230e9daf6cd5413edf8256824ceb893d6be33 (unchanged; guest not touched)
Import list:  unchanged
Principles:   12 Docs, code, tests agree: HANDOFF now says what S2 does, and section 10 lists the S1 tests.
DeepSeek:     none
Not proven:   n/a
Checklist:    56 of 63
Questions:    1. Answer 3 keeps the guest import list at identity, runtime, types. Those offer only
                 runtime.info() and identity.context() (elastos/wit/elastos-bus-v1.wit:63-73), so the guest
                 cannot hand bytes to the Runtime. S3 needs elastos:bus/providers@1.0.0 (as HANDOFF S3 says)
                 or a WIT change. Is the providers import allowed for S3? Recorded as S3-DESIGN question 5.
```

## What is next

Item b: the guard sweep, on its own branch.
