# Overnight run 1 (night of 20 Oct 2026)

Sasha is asleep and Cursor is not reviewing until morning. You may do several pieces of work in a row, in the order below, on **one branch** with **one PR**. Everything in `HANDOFF.md` still applies. Where this file is stricter, this file wins.

## Setup

1. Start from `spike/agent-host`. If PR #2 (`claude/s0b-catch-up`) is not merged yet, merge that branch into yours first (a merge commit, never a rebase). It already contains PR #1.
2. Merge Elacity `develop` as in HANDOFF rule 4. If it is not clean, stop the whole run and report.
3. Branch name: whatever the session gives you. Open the PR **early**, after the first push, as a draft, titled `Overnight 1: S0c, S1, S2, S3 design, guard sweep`, base `spike/agent-host`. Update its description as you go.

## Order of work

Do them in this order. Each item ends with its own commit(s), its own report, one line in `handoff/LOG.md`, and a **push**. Push after every item, so nothing is lost if the session ends.

1. **S0c** as in HANDOFF section 8. Report `reports/S0c-pin-guards.md`.
2. **S1** `sell-closed-admission` as in HANDOFF section 8. Report `reports/S1-closed-admission.md`. Tests only, no production change.
3. **S2** UsersAI journal format, guest only, no I/O, as in HANDOFF section 8. Contract in `handoff/USERSAI-JOURNAL.md`, report `reports/S2-journal-format.md`. State our choice on empty assistant text (we keep it in model bytes; DeepSeek now drops it) and why.
4. **S3 design, no code.** Write `handoff/S3-DESIGN.md` for the slice that comes after: the Runtime stores the journal. Find and cite (file and line) the real code it would use: the component host's `invoke` path, how a grant reaches it, the object provider's version and compare-and-swap calls, how `UsersAI` resources are named and owned today, and where `settlement_unknown` already exists. Then list the exact tests from HANDOFF S3, an attack list (another principal's journal, a replayed old version, a grant for a different resource, a crash between write and result, an oversized append, a host path in the resource), and the smallest diff you would make. No code change in this item. Report `reports/S3-design.md` (short; the design file is the substance).
5. **Guard sweep, no code change.** List every refusal in `examples/agent-host/src/lib.rs` and `elastos/crates/elastos-compute/src/exec_vm.rs` (each `return false`, `Err(...)`, `None`, or early return that refuses input). For each, mutate it so it accepts, run the tests, record which test fails, revert. Table in `reports/guard-sweep.md`: function, line, mutation, failing test or **none**. Do not add tests in this item; the gaps become the next slice. Revert every mutation; the final tree must equal the start of this item except the report.

## Stop rules (any one stops the whole run)

- A merge is not clean.
- A test that passed at the start of an item fails at its end and you cannot see why.
- A slice would need a production change it does not allow, an import-list change, or a change to the shipping Assistant.
- A question about security, grants, or signing that the files do not answer. Write it under `Questions:` and stop. Do not guess past it.
- Anything that would touch an Elacity repo.

If you stop, finish the current report with what is done and why you stopped, push, and update the PR description. A clean stop is a good result.

## Not tonight

S3 code, SA, S4, S5, anything Mac-only, anything in phase C to F.

## Morning summary

When you finish or stop, put this at the top of the PR description:

```text
Overnight 1 summary
Items done:     <list, each with its last commit SHA>
Item stopped:   <item and reason, or "none">
Tests at end:   <section 10 results>
Guest hash:     <Linux sha256, and whether it changed and why>
Import list:    <unchanged, or what changed>
Checklist:      <n> of <total>
Grade:          <n> of 70, with the rows that moved and the tests that moved them
Questions:      <for Sasha>
```
