# S0 review

```text
Slice:     S0 baseline
Reviewed:  96e7ef3c66d7ff9e859d65ccd508923d0c73b74b (PR #1), parent 3fd416806, base 189a34ff6
Reviewer:  Cursor. S0 changes no code, so no cross-family security review is needed.
VERDICT:   PASS
```

## What was checked

- Diff is docs only: `SLICES.md` (run-tests-in-vm closed for the Home list, new pending `exec-cargo-in-image`, one section 7 paragraph), `LOG.md` (one line), `reports/S0-baseline.md`. Author and trailer correct. No push outside this repo.
- `SLICES.md` change is accurate. `admit_exec_argv` refuses `cargo` with `program missing` (exec_vm.rs 189), and the cited test exists (exec_vm.rs 686, 730).
- Falsifier 1 rerun on the Mac: `>` changed to `>=` in `admit_skill` makes `an_over_budget_skill_leaves_the_journal_unchanged` fail. Reverted.
- Checklist total 63: accepted. Adding a todo for real open work is right.

## Guest hash

Same source, two hashes: Mac aarch64 `fe9bcaa4...`, cloud Linux x86_64 `e34772d1...`. Both are stable on their own machine.

Mechanism shown on the Mac: rebuilding with only Cargo's symbol-hash salt changed (`__CARGO_DEFAULT_LIB_METADATA=salt-test`) changed the file to `8f6db8db...`. The `name` section changed and so did the code section bytes (functions are ordered and grouped by those hashes), while the code section size stayed exactly 201,840 bytes. So stripping names cannot make two machines match.

Most likely input: Cargo's metadata hash includes the compiler's verbose version, whose `host:` line names the build machine. Shown as a mechanism, not yet proven to be that exact input.

Rule from now on (also in HANDOFF section 2): the guest hash is compared on the same kind of machine. Reference hashes for the 19 Oct source: Mac aarch64 `fe9bcaa48669b10c9e7633f9ba7f34db1fcc65fa0dcc41ea1517c2dfc10f60c5`, Linux x86_64 `e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1`. A report gives the Linux hash from two builds and the section sizes from `handoff/tools/wasm_sections.py`. Cursor rebuilds on the Mac.

Note for Sasha, not for GitHub: component capsules are byte-reproducible per machine type only. That matters if ElastOS ever promises that anyone can rebuild a signed capsule and get the same bytes. It is the team's build script, so it is not ours to change in the spike.

## Not covered by this S0

The session started at `189a34ff`, before the handover gained `DEEPSEEK.md`, `HISTORY.md`, the grade table, and the reading list (`da30e264`). The DeepSeek catch-up, the history check, and the per-row grades are therefore a separate slice, S0b, before S1.

## Message for Claude

S0 PASS. Thank you for not "fixing" the hash. Merged. Next session is S0b (see HANDOFF section 8).
