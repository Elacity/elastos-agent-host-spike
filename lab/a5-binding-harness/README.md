# A5 grant-binding SPEC and BLOCKED table

This folder is a SPEC and a BLOCKED table, not the A5 acceptance gate.
It states M1 check A5: grants bound to agent identity, session, capsule
instance and owned storage. A Public-storage read does not establish
binding.

Landing RA-1, RA-2, RA-3, RA-5, RA-6 and guest-handle use (#463) is not
enough. A live measurement, a host-record lookup, guest-handle use, seed
and read, session-end, and live-evidence recording must be written and
independently reviewed before any row can PASS. The Runtime shipping those
asks does not write that record.

The Runtime team owns the real grant record. This lane changes no Runtime
code. Real-Runtime rows stay with `cx-agent-conformance`; this folder writes
none of them. [SPEC.md](SPEC.md) states each row, the Runtime evidence that
will count, and the ask it needs. Today every row is BLOCKED.

## Run

From the repository root:

```sh
lab/a5-binding-harness/run.sh
```

It runs `cargo fmt --check`, the harness self-tests, then prints the
BLOCKED table:

```text
check | test | grade
A5-ID-POS | acceptance_a5_identity_grant_used_by_bound_agent | BLOCKED (RA-1; RA-5; RA-6; #463)
A5-STOR-POS | acceptance_a5_owned_storage_grant_used_on_bound_root | BLOCKED (RA-1; RA-3; RA-5; RA-6; #463)
A5-PUB | acceptance_a5_public_storage_read_is_not_binding | BLOCKED (RA-1; RA-6; #463)
...
A5 binding: accepted 0 of 9; failed 0; blocked 9; skipped 0
```

Below the table it lists each missing ask with its evidence, read from
this checkout on every run (file, line, and what that line shows). Exit
status: 0 when no row failed or was skipped, 1 on a failed row or self-test,
4 on a skipped row. BLOCKED rows keep exit 0 and stay open in SPEC.md, as in
`lab/resident-instances`.

The first build fetches `serde_json` from crates.io. Later runs work offline
with `--locked`.

## Reading the results

- `cargo test` shows the nine rows as `ignored, blocked: RA-...`.
  Forced with `-- --ignored`, each row fails with its BLOCKED text.
- `blocker_evidence_still_holds` passes while every gap's evidence is still in
  the Runtime source. When the Runtime changes one of those lines, it fails
  and names the ask to re-measure against a live operator.
- `needs_cover_every_runtime_call_the_journey_makes` runs each journey,
  records its Runtime calls, and fails if `needs()` omits any ask those
  calls require. A5-PUB calls `host_record`, so it must list RA-1 and #463.
- `tests/journeys.rs` runs every journey against a reference double. The
  honest double passes. A fixture that fakes a refusal, a skipped row counted
  as passed, and a Public-storage read counted as binding are each refused.
  These rows test the harness. They are not Runtime evidence.

## Live run (after the later write, not after the asks land)

Start a throwaway operator Home with `dev_mode = true`. Then:

```sh
A5_RUNTIME_COORDS=/abs/path/to/runtime-coords.json \
lab/a5-binding-harness/run.sh
```

The harness reads the attach secret into memory, attaches once as the shell
on IPv4 loopback, and prints instances by local label only. Use a throwaway
Home only.

A capability leaves the BLOCKED list only after a guest journey on a live
operator measured it. Clearing `gap()` is not a measurement. Nothing reports
PASS without a guest handle from that operator. Landing the asks without the
later write in SPEC.md section 9 still leaves every row BLOCKED.

## Files

- `SPEC.md`: the rows, the gaps, grading, live-evidence rules, open questions.
- `src/capability.rs`: RA-1, RA-2, RA-3, RA-5, RA-6, #463, pin evidence, guest measurement.
- `src/journey.rs`: the nine journeys (four different positive rows).
- `src/http.rs`: operator adapter for routes that exist on develop.
- `src/walk.rs`: owned-name walk (`..`, symlink, prefix collision).
- `src/contract.rs`: handle, structured refusal, Public-read refusal, PASS.
- `tests/acceptance.rs`: the nine BLOCKED table rows.
- `tests/gates.rs`: keeps the BLOCKED grades, the rows and SPEC.md in step.
- `tests/journeys.rs`, `tests/common/double.rs`: harness self-tests.
- `falsifiers.json`: the mutations that show each check can fail.
- `LOG.md`: commands and results.

## Principles

3, 7, 10, 11, 12, 18. See SPEC.md section 8.
