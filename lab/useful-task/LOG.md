# Useful task checker log

## 001 — judge two agent tasks and refuse stubs

Added the `useful-task` workspace with one task and acceptance spec for
`agent-a` and `agent-b`, their hand-captured answers, and a checker that judges
a model proposal against the parsed recorded value. The checker trims the
answer, then refuses `empty`, `echo`, `fixed-string`, `shape` and `mismatch` in
that order; it reads no file, opens no socket, and grants nothing. The test also
accepts equivalent JSON with different formatting and key order, and refuses
malformed JSON, extra keys, non-string values and a spec swap.

Checks on the committed tree (source SHA-256
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
