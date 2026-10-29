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

## 003 — judge binds to the named fixture hashes

`Spec` gained `recorded_sha256` and its read-only accessor. `CHECK_ORDER` is now
the seven reasons `input`, `recorded`, `empty`, `echo`, `fixed-string`, `shape`,
`mismatch`. `load_spec` requires `recorded_sha256` as a known key and refuses a
missing key, a non-string, or a string that is not 64 lowercase hex characters
for both `input_sha256` and `recorded_sha256`; the messages are
`spec is missing <key>`, `spec <key> is not a string`, and
`spec <key> is not a sha256 hex`. One new function, `sha256_field`, performs the
format check; `sha256_hex` stays the only hasher.

`judge(spec, input, expected, answer)` now takes the expected bytes as `&str`.
Its first statement is still `    let trimmed = answer.trim();`. Inside the
existing reasons loop, `input` refuses when `sha256_hex(input)` is not the
spec's `input_sha256`, and `recorded` refuses when `sha256_hex(expected)` is not
its `recorded_sha256`. Both hash the arguments exactly as given. The five later
checks keep their meanings, with the expected value parsed from those bytes.

Both `accept.json` files carry `recorded_sha256` and the seven-reason list. The
input and recorded fixtures keep their bytes and hashes
(`043eec2f...e3468` for agent-a, `c7209888...221a7` for agent-b).

`checker_accepts_recorded_answer_and_refuses_stubs` now also checks the recorded
hash accessors, a one-character input change with the real recorded bytes as
both expected and answer (`input`), each agent's schema-valid substitute as both
expected and answer (`recorded`), and both hash fields set to `abc`, `A`×64, and
`g`×64, plus missing and `17`. The existing accept, empty, echo, fixed-string,
shape, mismatch, spec-swap and malformed-spec checks use all seven reasons.

### Planted faults

Each fault was hand-applied to `src/lib.rs`, the named test ran alone, and the
original bytes were restored before the next fault. The restored source SHA-256
is `b30f53d23fafd545b3aa5878d180323cc3bf7adaf5d01e996151c61fc547ff4a`.
Every run used
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/useful-task/Cargo.toml -- checker_accepts_recorded_answer_and_refuses_stubs --exact`.

1. `            Reason::Input => false,` failed at `tests/checker.rs:208:5`:
   `assertion left == right failed: changed input is input`,
   `left: Accept { answer_sha256: "be6bff0dff3b3ebdcd97da9db1cdbe24aaa194e90fef6ac158ff8b0b36eb5ba5" }`
   / `right: Refuse { reason: "input" }`.
2. `            Reason::Recorded => false,` failed at `tests/checker.rs:222:5`:
   `assertion left == right failed: agent-a substitute against its own hash is recorded`,
   `left: Accept { answer_sha256: "7f0fca5c7e7768cdcfa47fcc6990699ba0431582e99c5ddade2b99813e85a179" }`
   / `right: Refuse { reason: "recorded" }`.
3. Replacing the check with `if false {` (so `abc` loads) failed at
   `tests/checker.rs:38:33`: `malformed spec: Spec { ... input_sha256: "abc",
   recorded_sha256: "043eec2f...e3468", ... }`.
4. Skipping only the input key:
   `if key == "input_sha256" { return Ok(value); }` failed at
   `tests/checker.rs:38:33` with `input_sha256: "abc"`.
5. Skipping only the recorded key:
   `if key == "recorded_sha256" { return Ok(value); }` failed at
   `tests/checker.rs:38:33` with `recorded_sha256: "abc"`.
6. Replacing the charset with `byte.is_ascii_hexdigit()` (so uppercase loads)
   failed at `tests/checker.rs:38:33` with 64 `A` characters in
   `input_sha256`.
7. Replacing `b'a'..=b'f'` with `b'a'..=b'z'` (so a non-hex letter loads)
   failed at `tests/checker.rs:38:33` with 64 `g` characters in
   `input_sha256`.

After the final restore, the same command passes:

```
test checker_accepts_recorded_answer_and_refuses_stubs ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

`cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check` passes. The
full `cargo test --locked --manifest-path lab/useful-task/Cargo.toml` passes one
integration test and six doctests. `F-UT1` in the existing `falsifiers.json`
stays unchanged and the shared runner reports `CAUGHT`. The live model turn
stays held.

- 003: Bound `judge` to the spec's `input_sha256` and `recorded_sha256`, added the seven-reason order and strict hash-field loading, and extended the named test with the wrong-input and substitute refusals plus format plants.

## 004 — judge requires one of the two named task specs

`CHECK_ORDER` now names eight checks, with `task` first. `judge` keeps
`    let trimmed = answer.trim();` as its first statement and the existing
reasons loop gains one arm, `            Reason::Task => !is_named_task(spec),`.
`is_named_task` loads the embedded `tasks/agent-a/accept.json` and
`tasks/agent-b/accept.json` with the one `load_spec`, compares `Spec` equality,
and refuses when either embedded spec fails to load. A caller-supplied spec
whose hashes match a different note and answer is now `task` instead of
`Accept`. Both fixture specs change only their `reasons` arrays; `input.txt`,
`recorded.json`, `Cargo.toml`, `Cargo.lock` and `F-UT1` keep their bytes.

The one test `checker_accepts_recorded_answer_and_refuses_stubs` now uses the
eight labels and adds three refusals: a copy of agent-a's spec with `m1` set to
`other` judged against the real fixture bytes, and the self-consistent agent-a
and agent-b substitutes described in the task. Each substitute keeps its own
`task_id`, hashes its own input and recorded strings with `sha256_hex`, and is
`task`. Without the new arm those three calls are `Accept`; the other refusals
and the spec swaps keep their reasons.

### Falsifiers

`F-UT2` skips the named-task check with
`            Reason::Task => false,` and names the same test. The shared runner
reports:

```
baseline: 1 named tests pass without an edit, 0 do not
F-UT1  CAUGHT                             1s  accept every answer before the judge reads it
F-UT2  CAUGHT                             1s  skip the named-task check
summary: 2 CAUGHT of 2
```

After the run, `lab/useful-task/src/lib.rs.falsify-original` is absent and the
source is restored to SHA-256
`7cb4678485686ecc154837b8321022038a7acb42db45bb6a9e09791ad76dd96c`. The
restored tree passes `cargo fmt --manifest-path lab/useful-task/Cargo.toml --
--check`, the named test, and the full `cargo test --locked` run (seven
tests). The live model turn stays held.

- 004: Made `judge` refuse a spec that is not one of the two named task specs, added the eight-reason order with `task` first, extended the named test with the m1 and self-consistent substitute cases, and added `F-UT2`.

## 005 — judge refuses an answer that repeats a JSON key

`CHECK_ORDER` now names nine checks, with `duplicate` between `shape` and
`mismatch`. `judge` keeps `    let trimmed = answer.trim();` as its first
statement and reads the answer through one private `parse_answer`, which
replaces `serde_json::from_str` on the answer. `parse_answer` uses
`serde_json::Deserializer::from_str`, one `serde::de::Visitor` (`UniqueValue`),
and `Deserializer::end` after the value, so trailing non-whitespace is
`AnswerParse::Invalid` and a unique-key value is `AnswerParse::Value`.

The visitor builds each object with `Map::insert`. A key that is already
present sets a `Cell` flag and returns `Error::custom("duplicate key")`, and
`parse_answer` reads that flag as `AnswerParse::Duplicate`. A key written with
a `\u` escape decodes to the same key, so it is the same case; an object inside
an array uses the same visitor. Truncated JSON and any other parse error stay
`AnswerParse::Invalid`. The expected bytes still use `serde_json::from_str`.

The `shape` check refuses `AnswerParse::Invalid` and a `Value` that fails
`schema.matches`, and it passes `AnswerParse::Duplicate`, so the new one-line
arm decides that case:
`            Reason::Duplicate => matches!(parsed, AnswerParse::Duplicate),`.
The `mismatch` check compares only a `Value`, so a repeated key has no value to
compare. Hand-setting the duplicate arm to false makes the first Context answer
`Accept`: the named test panicked at `tests/checker.rs:379:9` with
`left: Accept { answer_sha256: "0e7900bc0d0567eb66d8637414f5b4e4bf0ab996fbb93fb629b81cbd4c1c7345" }`
/ `right: Refuse { reason: "duplicate" }`. The `shape` check passes
`AnswerParse::Duplicate` and `mismatch` matches only a `Value`, so the other
three duplicate fixtures take the same `Accept` path; the source was restored
to the SHA-256 below afterwards.

`Cargo.toml` gains `serde = "=1.0.229"`, which the lock already carried as a
`serde_json` dependency, and the lock's root entry gains `serde`. Both
`accept.json` files change only their `reasons` arrays to the nine labels;
`input.txt`, `recorded.json`, `F-UT1` and `F-UT2` keep their bytes.

`checker_accepts_recorded_answer_and_refuses_stubs` now uses the nine labels
and adds six refusals: the three Context answers, the reversed-key answer, and
a repeated key beside an extra field are `duplicate`; a unique-key answer whose
`goods` string contains the word `place` is `mismatch`; and a valid value with
trailing non-whitespace is `shape`. The three Context answers are `Accept`
without the duplicate arm, so the test fails without it.

### Falsifiers

`F-UT3` sets the duplicate arm to false and names the same test. The shared
runner reports:

```
baseline: 1 named tests pass without an edit, 0 do not
F-UT1  CAUGHT                             1s  accept every answer before the judge reads it
F-UT2  CAUGHT                             1s  skip the named-task check
F-UT3  CAUGHT                             1s  skip the duplicate-key check
summary: 3 CAUGHT of 3
```

The command exited 0, `lab/useful-task/src/lib.rs.falsify-original` is absent,
and `src/lib.rs` kept SHA-256
`5ff9694e7362b1611eaac6967e4af6975965e6e08f7245ca3334545230d4e7d2` across the
run. The restored tree passes
`cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check`, the named
test, and the full `cargo test --locked` run (one integration test and six
doctests). The live model turn stays held.

- 005: Made `parse_answer` refuse a repeated object key with one deserializer and one visitor, added the nine-reason order with `duplicate` between `shape` and `mismatch`, extended the named test with the duplicate and unique-key cases, and added `F-UT3`.
