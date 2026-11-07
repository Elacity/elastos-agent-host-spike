# Useful task checker log

## 001 — judge two agent tasks and refuse stubs

Here, “fixed stub” means exactly `ok`, `done`, `TODO`, or `pass`. A constant
answer equal to `recorded.json` passes. These fixtures measure answer validity;
they cannot prove rejection of every constant-answer program or a real model turn.

Added the `useful-task` workspace with one task and acceptance spec for
`agent-a` and `agent-b`, their hand-captured answers, and a checker that judges
a model proposal against the parsed recorded value. The checker trims the
answer, then refuses `empty`, `echo`, `fixed-string`, `shape` and `mismatch` in
that order; it reads no file, opens no socket, and grants nothing. The test also
accepts equivalent JSON with different formatting and key order, and refuses
malformed JSON, extra keys, non-string values and a spec swap.

Initial checks before this repair (source SHA-256
`3172093cf08032b0c96fcd735f258855c6d11fa7e80e969e173f9c21297709ec`,
fixtures with their specified hashes):

```
cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/useful-task/Cargo.toml
```

```
test checker_accepts_recorded_answer_and_refuses_stubs ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Planted faults

Each fault was hand-applied to `src/lib.rs`, the named test ran alone with
`--exact`, and the original bytes were restored before the next fault. Every
fault failed the named test.

Unconditional accept, the first statement of `judge`:

```
    return Verdict::Accept { answer_sha256: sha256_hex(answer.trim()) };
```

```
thread 'checker_accepts_recorded_answer_and_refuses_stubs' panicked at tests/checker.rs:82:13:
assertion `left == right` failed: blank answer is empty
  left: Accept { answer_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
 right: Refuse { reason: "empty" }
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Restored, the same command:

```
running 1 test
test checker_accepts_recorded_answer_and_refuses_stubs ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Separate refusal-rule faults:

- `Reason::Empty => false,` failed at `tests/checker.rs:82:13`:
  `left: Refuse { reason: "shape" }` / `right: Refuse { reason: "empty" }`.
- `Reason::Echo => false,` failed at `tests/checker.rs:88:9`:
  `left: Refuse { reason: "shape" }` / `right: Refuse { reason: "echo" }`.
- `Reason::FixedString => false,` failed at `tests/checker.rs:94:13`:
  `left: Refuse { reason: "shape" }` / `right: Refuse { reason: "fixed-string" }`.
- `Reason::Shape => false,` failed at `tests/checker.rs:128:9`:
  `left: Accept { answer_sha256: "6c983180..." }` / `right: Refuse { reason: "shape" }`.
- `Reason::Mismatch => false,` failed at `tests/checker.rs:128:9`:
  `left: Accept { answer_sha256: "7f0fca5c..." }` / `right: Refuse { reason: "mismatch" }`.

Parsed-value comparison fault, comparing the trimmed answer string with the
serialized expected value:

```
.is_none_or(|value| spec.schema.matches(value) && trimmed != expected.to_string()),
```

It failed at `tests/checker.rs:66:5`: `left: Refuse { reason: "mismatch" }` /
`right: Accept { answer_sha256: "be6bff0dff3b3ebdcd97da9db1cdbe24aaa194e90fef6ac158ff8b0b36eb5ba5" }`.

Answer-hashing fault, `sha256_hex(answer)` instead of `sha256_hex(trimmed)`:

```
    Verdict::Accept {
        answer_sha256: sha256_hex(answer),
    }
```

It failed at `tests/checker.rs:66:5`:
`left: Accept { answer_sha256: "043eec2fa4d70dafc04b87b9b594b703dc6a3f9db7d1f2baca9a2c50d44e3468" }` /
`right: Accept { answer_sha256: "be6bff0dff3b3ebdcd97da9db1cdbe24aaa194e90fef6ac158ff8b0b36eb5ba5" }`.

- 001: Added `lab/useful-task` with agent-a/agent-b inputs, specs and recorded answers, and a hash-checking stub-refusing judge; planted eight faults and restored the source before commit.

### Validated spec repair

`Spec` now owns its validated fields privately and provides shared read access.
The compile-fail examples exercise clearing the reason list, removing only
`Mismatch`, changing lists through accessors, changing schema fields, and direct
construction. The named test checks every loader refusal string for both specs,
including empty, reordered, duplicated and individually omitted checks.

Each of the following faults was applied separately, tested, and restored.
For all twelve loader faults, this command exited 101 at the assertion in
`tests/checker.rs:30`:

```sh
cargo test --offline --locked --manifest-path lab/useful-task/Cargo.toml -- checker_accepts_recorded_answer_and_refuses_stubs --exact
```

| Fault in `load_spec` or its validation helper | Observed assertion failure |
| --- | --- |
| JSON parse fallback to `null` | `spec is not an object` instead of `spec is not JSON: EOF while parsing a list at line 1 column 1` |
| Replace a non-object with an empty object | `spec is missing kind` instead of `spec is not an object` |
| Unknown kind becomes `Schema::Fields(Vec::new())` | `expect_err("malformed spec")` received `Ok(Spec)` |
| Disable the unexpected-key check | `expect_err("malformed spec")` received `Ok(Spec)` |
| Unknown reason becomes `Reason::Empty` | `spec reasons are not the canonical checks` instead of `spec reason unknown is unknown` |
| Disable the canonical check-order check | `expect_err("malformed spec")` received `Ok(Spec)` with `reasons: []` |
| Missing required field becomes `Value::Null` | `spec kind is not a string` instead of `spec is missing kind` |
| Non-string field becomes an empty string | `spec kind  is unknown` instead of `spec kind is not a string` |
| Non-array field becomes an empty array | `spec fields is empty` instead of `spec fields is not an array` |
| Non-string array element becomes an empty string | `expect_err("malformed spec")` received `Ok(Spec)` |
| Disable the empty-schema check | `expect_err("malformed spec")` received `Ok(Spec)` |
| Disable the duplicate-schema-field check | `expect_err("malformed spec")` received `Ok(Spec)` |

Each loader fault produced:

```text
test checker_accepts_recorded_answer_and_refuses_stubs ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

A separate privacy fault changed the field to `pub reasons: Vec<Reason>`.
`cargo test --offline --locked --manifest-path lab/useful-task/Cargo.toml --doc`
exited 101 because both bypass examples compiled:

```text
---- src/lib.rs - Spec (line 25) stdout ----
Test compiled successfully, but it's marked `compile_fail`.
---- src/lib.rs - Spec (line 31) stdout ----
Test compiled successfully, but it's marked `compile_fail`.
test result: FAILED. 4 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
```

After restoring all faults, formatting and the complete test suite succeeded:

```sh
cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check
cargo test --offline --locked --manifest-path lab/useful-task/Cargo.toml
```

```text
test checker_accepts_recorded_answer_and_refuses_stubs ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
```

The restored `src/lib.rs` SHA-256 is
`f073b66a62bd1af48e5d8d6044114fef3180272ff9fa3cc6586d04d8c99d67cb`.
These runs used `RUST_TEST_THREADS=2`, `CARGO_INCREMENTAL=0`, and Cargo target
and build directories under `lab/useful-task/target/`. The privacy-fault run
used the default test thread count. The repair remains pending the supervisor's
checks and fresh review.

## 002 — the shared runner catches the unconditional accept

Added `lab/useful-task/falsifiers.json` with one entry, `F-UT1`. Its `command`
is `useful-task`, its `expect` is `caught`, and it names one test,
`checker_accepts_recorded_answer_and_refuses_stubs`. Its single edit replaces
the one line `    let trimmed = answer.trim();\n` in
`../../lab/useful-task/src/lib.rs` with an early
`return Verdict::Accept { answer_sha256: sha256_hex(answer.trim()) };` before
that line. The entry carries a `title`, because the runner prints it on every
result line. The list's paths are relative to `examples/agent-host`, the same
way the agent-conformance list names its crate.

This moves 001's hand plant onto the one shared runner. The edit and its
restoration live in `examples/agent-host/falsify.py`; this task did not change
that file, `src/lib.rs`, `tests/checker.rs`, the fixtures, `Cargo.toml` or
`Cargo.lock`. `PROVIDER_TARGETS` still does not name this crate's source, so a
killed run restores the file only from the finished run's own backup.

Run from the repository root with `RUST_TEST_THREADS=2` and
`CARGO_INCREMENTAL=0`:

```
python3 -I examples/agent-host/falsify.py --from lab/useful-task/falsifiers.json
```

```
baseline: 1 named tests pass without an edit, 0 do not
F-UT1  CAUGHT                             1s  accept every answer before the judge reads it
summary: 1 CAUGHT of 1
```

The command exited 0. The word is `CAUGHT`, not `BUILD FAILED` and not
`NOT RUN`. After it, `git diff -- lab/useful-task/src/lib.rs` was empty and
`lab/useful-task/src/lib.rs.falsify-original` was absent. The committed `judge`
still begins with `let trimmed = answer.trim();` and has no early return. On
that restored tree:

```
cargo test --locked --manifest-path lab/useful-task/Cargo.toml -- checker_accepts_recorded_answer_and_refuses_stubs --exact
```

```
test checker_accepts_recorded_answer_and_refuses_stubs ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The measurement is only about the checker. The live model turn stays in
BACKLOG and stays opt-in; this task reads no model endpoint and starts no
agent.

- 002: Added `lab/useful-task/falsifiers.json` with F-UT1 on the shared runner; the registered `useful-task` command catches the early-accept plant and restores `src/lib.rs`.
