# A5 grant-binding acceptance harness

This lane holds the acceptance spec and harness for M1 check A5: grants bound
to agent identity, session, capsule instance and owned storage. A5 comes
before A4 and A7 acceptance. A Public-storage read does not establish
binding.

The Runtime team owns the real grant record. This lane changes no Runtime
code. Real-Runtime rows stay with `cx-agent-conformance`; this folder writes
none of them. [SPEC.md](SPEC.md) states each row, the Runtime evidence that
counts, and the RA-* ask it needs. Today every row is BLOCKED.

## Run

From the repository root:

```sh
lab/a5-binding-harness/run.sh
```

It runs `cargo fmt --check`, the harness self-tests, then prints the
acceptance table:

```text
check | test | grade
A5-ID-POS | acceptance_a5_identity_grant_used_by_bound_agent | BLOCKED (RA-1; RA-5; RA-6)
...
A5 binding: accepted 0 of 9; failed 0; blocked 9; skipped 0
```

Below the table it lists each missing capability with its evidence, read from
this checkout on every run (file, line, and what that line shows). Exit
status: 0 when no row failed or was skipped, 1 on a failed row or self-test,
4 on a skipped row. BLOCKED rows keep exit 0 and stay open in SPEC.md, as in
`lab/resident-instances`.

The first build fetches `serde_json` from crates.io. Later runs work offline
with `--locked`.

## Reading the results

- `cargo test` shows the nine acceptance rows as `ignored, blocked: RA-...`.
  Forced with `-- --ignored`, each row fails with its BLOCKED text.
- `blocker_evidence_still_holds` passes while every gap's evidence is still in
  the Runtime source. When the Runtime changes one of those lines, it fails
  and names the capability to re-measure against a live operator.
- `tests/journeys.rs` runs every journey against a reference double. The
  honest double passes. A fixture that fakes a refusal, a skipped row counted
  as passed, and a Public-storage read counted as binding are each refused.
  These rows test the harness. They are not Runtime evidence.

## Live run (after the Runtime ships the SPEC capabilities)

Start a throwaway operator Home with `dev_mode = true`. Then:

```sh
A5_RUNTIME_COORDS=/abs/path/to/runtime-coords.json \
lab/a5-binding-harness/run.sh
```

The harness reads the attach secret into memory, attaches once as the shell
on IPv4 loopback, and prints instances by local label only. Use a throwaway
Home only.

A capability leaves the BLOCKED list only after a live journey measured it.
Nothing reports PASS without that operator evidence.

## Files

- `SPEC.md`: the rows, the gaps, grading, open questions.
- `src/capability.rs`: RA-1, RA-2, RA-3, RA-5, RA-6 and the evidence pins.
- `src/journey.rs`: the nine journeys.
- `src/http.rs`: the operator adapter for the SPEC routes.
- `src/contract.rs`: Runtime evidence, Public-read refusal, PASS construction.
- `tests/acceptance.rs`: the nine acceptance rows.
- `tests/gates.rs`: keeps the BLOCKED grades, the rows and SPEC.md in step.
- `tests/journeys.rs`, `tests/common/double.rs`: harness self-tests.
- `falsifiers.json`: the mutations that show each check can fail.
- `LOG.md`: commands and results.

## Principles

3, 7, 10, 11, 12, 18. See SPEC.md section 8.
