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

## 006 — the lane gate holds only F-UT2

The lane gate runs `lab/useful-task/falsifiers.json` when it exists, and that
list now has one entry: `F-UT2`, copied unchanged from head `aa1103891` — id
`F-UT2`, title `skip the named-task check`, command `useful-task`, expect
`caught`, tests `["checker_accepts_recorded_answer_and_refuses_stubs"]`, and
one edit of `            Reason::Task => !is_named_task(spec),\n` to
`            Reason::Task => false,\n`. The other two entries moved unchanged
into `lab/useful-task/held-judge-plants.json`, which the gate does not read:
`F-UT1` (title `accept every answer before the judge reads it`) then `F-UT3`
(title `skip the duplicate-key check`), each with the same command, expect and
named test and its one edit of `src/lib.rs`.

The reason is recovery, not preference. `PROVIDER_TARGETS` in
`examples/agent-host/falsify.py:343` lists the files `recover_backups` at
`falsify.py:433` restores after a killed run, and it has no
`lab/useful-task/src/lib.rs`. A killed `F-UT1` or `F-UT3` run would therefore
leave an always-accept judge or a skipped duplicate-key check in the source.
`F-UT2` has the same target and is held for the same reason once this list
shrinks further; it stays because the gate needs one live plant, and it does
not change the recovery gap. The two `about` strings carry this condition:
`F-UT1` and `F-UT3` return to `falsifiers.json` only after `PROVIDER_TARGETS`
includes `lab/useful-task/src/lib.rs`.

This task does not run `examples/agent-host/falsify.py`. It proves the split
and the source bytes with two commands, both exited 0:

```
cargo test --locked --manifest-path lab/useful-task/Cargo.toml -- checker_accepts_recorded_answer_and_refuses_stubs --exact
python3 -c 'import json; g=json.load(open("lab/useful-task/falsifiers.json")); h=json.load(open("lab/useful-task/held-judge-plants.json")); assert [e["id"] for e in g["falsifiers"]]==["F-UT2"]; assert [e["id"] for e in h["falsifiers"]]==["F-UT1","F-UT3"]; assert g["falsifiers"][0]["edits"][0]["new"]=="            Reason::Task => false,\n"; assert h["falsifiers"][0]["edits"][0]["new"]=="    return Verdict::Accept { answer_sha256: sha256_hex(answer.trim()) };\n    let trimmed = answer.trim();\n"; assert h["falsifiers"][1]["edits"][0]["new"]=="            Reason::Duplicate => false,\n"'
```

The id lists are `["F-UT2"]` for the gate file and `["F-UT1","F-UT3"]` for the
held file. `git diff -- lab/useful-task/src/lib.rs` is empty, and the three
old strings each occur once in `src/lib.rs`; `tests/checker.rs`, both
`accept.json` files, both `input.txt` files, both `recorded.json` files,
`Cargo.toml` and `Cargo.lock` keep their bytes. The tree still passes
`cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check` and the full
`cargo test --locked` run. A4 stays open and the live model turn stays held.

- 006: Moved `F-UT1` and `F-UT3` unchanged into `held-judge-plants.json`, left `F-UT2` as the only entry in `falsifiers.json`, and stated the `PROVIDER_TARGETS` condition in both `about` strings.

## 007 — `load_spec` refuses a spec that repeats a JSON key

The one loader no longer calls `serde_json::from_str` for its value.
`load_spec` reads the spec text through the existing `parse_answer`, the same
unique-key parser that `judge` uses for the answer, and takes the accepted
value from `AnswerParse::Value`. This closes the collapse: `from_str` keeps the
last value of a repeated key, so a spec that named a wrong `m1` and then the
real `m1` loaded as the named task and judged a real answer `Accept`.

A repeated key returns `Err("spec repeats a key")` from the one line
`        AnswerParse::Duplicate => return Err("spec repeats a key".to_owned()),`.
`AnswerParse::Invalid` keeps the earlier messages by retrying
`serde_json::from_str::<Value>` on the same bytes: the parse error text as
`spec is not JSON: {error}`, and plain `spec is not JSON` when that retry is
`Ok`. `CHECK_ORDER` keeps its nine reasons, `judge` keeps its first statement
and its task and answer-duplicate arms, and `parse_answer` stays the only
unique-key parser with one `Visitor`. Key order and whitespace stay `Spec`
equality.

`checker_accepts_recorded_answer_and_refuses_stubs` now loads both fixture
files once into `a_spec_bytes` and `b_spec_bytes`, then refuses each Context
text with `spec repeats a key`: agent-a with the first `"m1":` replaced by
`"m1":"other","m1":`, agent-a with that insertion written as
`"\u006d1":"other","m1":`, and agent-b with the first `"task_id":` replaced by
`"task_id":"other","task_id":`. The existing other-`m1` spec still loads and is
still `task`, and `"["` still gives
`spec is not JSON: EOF while parsing a list at line 1 column 1`.

### Hand plant

The one duplicate arm was replaced with:

```
        AnswerParse::Duplicate => serde_json::from_str(bytes).map_err(|error| format!("spec is not JSON: {error}"))?,
```

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/useful-task/Cargo.toml -- checker_accepts_recorded_answer_and_refuses_stubs --exact`
exited 101:

```
thread 'checker_accepts_recorded_answer_and_refuses_stubs' panicked at tests/checker.rs:40:33:
malformed spec: Spec { task_id: "agent-a", m1: "A4: Each agent completes one useful task through real Runtime resources (model via a Runtime grant, DeepSeek on the Sparks); the permitted effect succeeds (granted_effect_succeeds).", input_sha256: "6cce0615e268e9a905d394b4e6f1c228fef86569ef8778c006626b1a45d57f30", recorded_sha256: "043eec2fa4d70dafc04b87b9b594b703dc6a3f9db7d1f2baca9a2c50d44e3468", fixed_strings: ["ok", "done", "TODO", "pass"], reasons: [Task, Input, Recorded, Empty, Echo, FixedString, Shape, Duplicate, Mismatch], schema: Fields(["place", "goods", "close"]) }
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The original bytes were then restored and the same command passed:

```
test checker_accepts_recorded_answer_and_refuses_stubs ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The committed `load_spec` has the `spec repeats a key` arm, that line occurs
once, and `src/lib.rs.falsify-original` is absent. The restored source SHA-256
is `a017e4a78ba0ac343f065bfdcba5a5e77842475fd4e4c978cea38258b93961a9`.

### Checks

`cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check` exited 0. The
full `cargo test --locked --manifest-path lab/useful-task/Cargo.toml` passed
the integration test and six doctests. The shared runner reported:

```
baseline: 1 named tests pass without an edit, 0 do not
F-UT2  CAUGHT                             1s  skip the named-task check
summary: 1 CAUGHT of 1
```

`falsifiers.json`, `held-judge-plants.json`, both `accept.json` files, both
`input.txt` files, both `recorded.json` files, `Cargo.toml` and `Cargo.lock`
keep their bytes. `src/lib.rs` has no `std::fs` and no `std::net`. The F-UT2
target still is not in `PROVIDER_TARGETS`, so recovery after a killed run stays
the open gap recorded in 006. A4 stays open and the live model turn stays held.

- 007: Made the one `load_spec` read through `parse_answer` and refuse a repeated spec key with `spec repeats a key`, extended the named test with the three Context texts, and hand-planted then restored the collapsed-parse arm.

## 008 — refuse non-JSON whitespace around an answer

`judge` no longer calls `str::trim` on the answer. Its first statement is now
`    let trimmed = trim_json_whitespace(answer);`, and the echo arm is
`            Reason::Echo => trimmed == trim_json_whitespace(input),`. The one
private helper in `src/lib.rs` is:

```rust
fn trim_json_whitespace(text: &str) -> &str {
    text.trim_matches(&[' ', '\t', '\n', '\r'][..])
}
```

It removes only space, tab, line feed and carriage return from both ends and
leaves every other character in place. `src/lib.rs` now has no `.trim()` call,
and `parse_answer` is still the only answer parser with one trim ahead of it.
`CHECK_ORDER` keeps its nine reasons, the task arm, the duplicate arm and the
`expected_value` line stay as they were, and `src/lib.rs` still has no
`std::fs` and no `std::net`. `held-judge-plants.json` changes only F-UT1's
`old` to `    let trimmed = trim_json_whitespace(answer);\n` and its `new` to
the early return followed by that same line; `falsifiers.json` stays F-UT2
only, and neither F-UT1 nor F-UT3 ran.

`checker_accepts_recorded_answer_and_refuses_stubs` still accepts each recorded
answer and each equivalent-JSON answer, and now also accepts a recorded answer
with a leading tab and one with a trailing carriage return. `""`, `"   "` and
`"\r\n \t"` are `empty`. For each agent the recorded bytes with U+00A0 before
them, U+000B before them, U+000C after them or U+FEFF before them are `shape`,
and `"\u{00a0}ok"` is `shape`. Every earlier refusal stays, including the spec
swap and the malformed-spec cases.

### Hand plant

The helper body was replaced with `text.trim()`:

```rust
fn trim_json_whitespace(text: &str) -> &str {
    text.trim()
}
```

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/useful-task/Cargo.toml -- checker_accepts_recorded_answer_and_refuses_stubs --exact`
exited 101 on the U+00A0 assertion:

```
thread 'checker_accepts_recorded_answer_and_refuses_stubs' panicked at tests/checker.rs:337:13:
assertion `left == right` failed: non-JSON whitespace around an answer is shape
  left: Accept { answer_sha256: "be6bff0dff3b3ebdcd97da9db1cdbe24aaa194e90fef6ac158ff8b0b36eb5ba5" }
 right: Refuse { reason: "shape" }
```

The original body was then restored and the same command passed. `src/lib.rs`
kept SHA-256
`ad69585f3afbc3298499e5a89ea74c27918d00f2bbb9e7f2c23b9c384f5511a4` across the
plant and the restore, the committed helper does not call `text.trim()`, and
`lab/useful-task/src/lib.rs.falsify-original` is absent.

### Checks

`cargo fmt --manifest-path lab/useful-task/Cargo.toml -- --check` exited 0. The
full `cargo test --locked --manifest-path lab/useful-task/Cargo.toml` passed
the integration test and six doctests. The shared runner reported:

```
baseline: 1 named tests pass without an edit, 0 do not
F-UT2  CAUGHT                             1s  skip the named-task check
summary: 1 CAUGHT of 1
```

`held-judge-plants.json`, `tests/checker.rs` and `src/lib.rs` are the only
changed files; both `accept.json` files, both `input.txt` files, both
`recorded.json` files, `Cargo.toml`, `Cargo.lock` and `falsifiers.json` keep
their bytes. A4 stays open and the live model turn stays held.

- 008: Made the one trim remove only the four JSON whitespace characters through `trim_json_whitespace`, reused it in the echo arm, extended the named test with the tab, carriage-return and four non-JSON-wrapped cases, and hand-planted then restored the `text.trim()` body.
