# Resident instances acceptance harness

This lane holds the acceptance harness for M1 check A3: two or more agents run
at the same time as independent resident capsule instances inside one Runtime.
It also re-proves A6 (separate grants), A10 (cancel one instance, sibling
unaffected), A11 (a failed instance's pending request is settled by the
Runtime) and A12 (cleanup census) for resident instances.

The Runtime team owns resident instances. This lane changes no Runtime code.
[SPEC.md](SPEC.md) states the interface the harness expects, with the evidence
for each capability that is missing today. Today every check is BLOCKED.

## Run

From the repository root:

```sh
lab/resident-instances/run.sh
```

It runs `cargo fmt --check`, the harness self-tests, then prints the
acceptance table:

```text
check | test | grade
A3 | acceptance_a3_two_resident_instances_in_one_runtime | BLOCKED (RI-1; RI-2; RI-3; RI-4)
...
resident instances: accepted 0 of 5; failed 0; blocked 5; skipped 0
```

Below the table it lists each missing capability with its evidence, read from
this checkout on every run (file, line, and what that line shows). Exit status:
0 when no row failed or was skipped, 1 on a failed row or self-test, 4 on a
skipped row. BLOCKED rows keep exit 0 and stay open in SPEC.md, as in
`lab/agent-conformance`.

The first build fetches `serde_json` from crates.io. Later runs work offline.

## Reading the results

- `cargo test` shows the five acceptance rows as `ignored, blocked: RI-...`.
  Forced with `-- --ignored`, each row fails with its BLOCKED text.
- `blocker_evidence_still_holds` passes while every gap's evidence is still in
  the Runtime source. When the Runtime changes one of those lines, it fails and
  names the capability to re-measure against a live operator.
- `tests/journeys.rs` runs every journey against a reference double, an
  in-memory stand-in for the SPEC interface. The honest double passes; each of
  16 wrong behaviours is refused for its own reason. These rows test the
  harness. They are not Runtime evidence and count toward no M1 check.

## Live run (after the Runtime ships the SPEC capabilities)

Start a throwaway operator Home with `dev_mode = true`, for example with
agent-conformance's ready-operator recipe
([GAPS.md](../agent-conformance/GAPS.md#operator-in-a-throwaway-home)). Build
the two fixture guests (SPEC.md section 5). Then:

```sh
RESIDENT_RUNTIME_COORDS=/abs/path/to/runtime-coords.json \
RESIDENT_FIXTURE_READ_SHARED=/abs/path/to/read-shared \
RESIDENT_FIXTURE_FAIL_AFTER_SUBMIT=/abs/path/to/fail-after-submit \
lab/resident-instances/run.sh
```

The harness reads the attach secret into memory, attaches once as the shell on
IPv4 loopback, and prints instances by local label only (`instance-1`). Use a
throwaway Home only: the journeys launch, grant, deny and stop instances on
that operator.

## Files

- `SPEC.md`: the interface, the gaps, the journeys, grading, open questions.
- `src/capability.rs`: capabilities RI-1 to RI-7, which check needs which, and
  the evidence pins.
- `src/journey.rs`: the five journeys and the census.
- `src/http.rs`: the operator adapter for the SPEC routes.
- `src/wit.rs`: a small reader for the Bus WIT files, used by two pins.
- `tests/acceptance.rs`: the five acceptance rows.
- `tests/gates.rs`: keeps the BLOCKED grades, the rows and SPEC.md in step.
- `tests/journeys.rs`, `tests/common/double.rs`: harness self-tests.
- `falsifiers.json`: the mutations that show each check can fail.
- `LOG.md`: commands and results.

Falsifiers use the shared data format. The shared runner
`examples/agent-host/falsify.py` has no command for this lane and refuses it;
apply and restore each mutation by hand, as LOG.md records.
