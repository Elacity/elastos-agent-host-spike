# Four interleaved sessions in one guest stay isolated

Task 024, branch `spark/agent-host/024-four-interleaved-sessions`.
Machine: macOS arm64. Every command below ran with
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`.

## Guard first: no journal format change

Sessions needed no key and no field, so the journal **format** is untouched.
The test keeps four `Journal` values side by side in one process and compares
each with its own solo run. `JOURNAL_FORMAT`, `encode_journal`,
`decode_journal` and the format-2 rendering table are unchanged; the
format-2 golden tests (`the_rendering_changes_only_with_the_format_number`,
`RENDERING_PIN`, the round-trip tests) still pass, and the guest hash is
unchanged. `USERSAI-JOURNAL.md` bytes did not change.

## Invariant

A session is one `Journal` value, and the guest holds no other state. Four
sessions advanced round by round in one process therefore produce, each, the
same model view and the same stored-journal head as that session run alone.
Grants, skills and inbox answers live in one journal and are visible to no
other.

## Changed

- `examples/agent-host/src/lib.rs`: four tests and their helpers in `mod tests`
  (`run_session_round` at `:19200`, `session_fingerprint` at `:19247`). No
  production code changed.
- `examples/agent-host/falsifiers.json`: `F-AH2a`, `F-AH2b`, `F-AH2c`.

## New named tests

| Test | Line | Rule |
| --- | --- | --- |
| `four_interleaved_sessions_match_their_solo_runs` | `:19260` | Four journals advanced round by round give the solo view, cache bytes and final head each; the four heads differ; a second interleaved run in the same process gives the same four fingerprints |
| `a_grant_never_crosses_sessions` | `:19347` | A grant on session A's step 1 runs that step only; session B's step 1 holds no grant, is denied, and no encoded journal carries the grant string |
| `a_skill_never_crosses_sessions` | `:19390` | A skill admitted in A leaves B's view and cache bytes unchanged and its own skill stays its own |
| `an_inbox_answer_never_crosses_sessions` | `:19435` | A's `allow-session` answer authorizes A's step only and is A's log entry only; B's own `allow-session` answer with no grant id mints nothing, so B's step is denied |

The session script (`run_session_round`) exercises the journal-wide state in
one script: head and epoch, a turn and a step marker, an observation, a skill,
a granted run and its tool result, an `allow-session` answer on a hosted step,
and compaction (which rewrites the tail and bumps the epoch). Each session's
text carries `session-mark-<n>-unique`, so another session's bytes would show
in the view.

The second-run assertion in the first test is the cheap pin for "no shared
mutable global": a value kept outside a `Journal` would change the second
run's fingerprints.

## Statics and globals in `src/lib.rs` (complete)

`static` items: **none**. The 49 occurrences of the token `static` are all the
`'static` lifetime on error literals and test fixtures (`&'static str`,
`&'static [Refusal]`).

`static mut`, `thread_local!`, `lazy_static!`, `OnceCell`, `OnceLock`,
`Mutex`, `RwLock`, `RefCell`, `Cell<`, `Atomic*`, `UnsafeCell`: **none**. A
grep for those tokens returns zero matches.

`const` items are immutable data with no interior mutability, so none holds
session state:

Module level (14): `EXPECTED_RUNTIME_ABI:65` (the one accepted runtime ABI),
`SYSTEM_HEAD:68` (node 0's text), `COMPACTION_SUMMARY:72` (the guest-written
summary), `RENDERING_FORMAT:294` (test pin for the rendering table),
`JOURNAL_MAGIC:358`, `JOURNAL_FORMAT:360`, `FORMAT_1_REASON:363`,
`JOURNAL_CAP:367`, `JOURNAL_HEADER:372` (the journal format; format decision,
never session state), `SKILL_BUDGET:1198`, `NOOP_EDIT_LIMIT:2376`,
`CHANGE_FILES_LIMIT:2508`, `RUN_LOG_BUDGET:2965` (limits), `JOURNAL_ROOT:3736`
(the one resource root).

Function-local or macro level (16): `HEX:1475` and `K:1633` (SHA-256 tables),
`ALL:1899` (generated in the `refusals!` macro), `READ_TIMEOUT:8233`, `JSON:8587`,
`WRITE_GRANT`/`READ_GRANT:15839-15840`, `NOTES`/`STYLE:16781-16782`,
`NFD`/`ALIAS`/`UPPER:18044-18046`, `IOTA_DIALYTIKA_TONOS`/
`CAPITAL_IOTA_DIALYTIKA_ACUTE:18350-18351`, `FORMAT_1_JOURNAL:18480`,
`RENDERING_PIN:18628`; all are test fixtures or algorithm tables except
`READ_TIMEOUT` (a test-only HTTP read timeout). `const { assert!(...) }` at
`:13190` is a compile-time size assertion, not an item.

New in this task (2): `SESSION_COUNT:19176`, `SESSION_ROUNDS:19178`, inside
`mod tests`.

Session state lives in `Journal` (`:184`), passed by `&mut`. The guest's
`run()` (`:4244`) holds one local `Journal`; a grant a guest may use is a
`JournalGrant` in memory (`:3750`) inside a `JournalCursor` per task
(`:3786`), and `JournalGrants` (`:3807`) is built per cursor. Decoded steps
hold no grant (`without_grants:945`).

## Falsifiers

| Id | Planted bug | Named test | Observed |
| --- | --- | --- | --- |
| `F-AH2a` | `open_turn` takes its turn number from a `static mut` process counter instead of the journal's turn list | `tests::four_interleaved_sessions_match_their_solo_runs` | FAILED on `assert_eq!(interleaved[index], solo[index], "session {index} differs from its solo run")`: `session 0 differs from its solo run` |
| `F-AH2b` | `dispatch` drops the per-step grant check (`step.grant.is_none()`), so a grant any step holds runs the step | `tests::a_grant_never_crosses_sessions` | FAILED on `assert!(!dispatch(&mut second, second_run))` (`:19367`) |
| `F-AH2c` | an `allow-session` answer mints its own grant id (`.or(Some("allow-session"))`), so a session answer authorizes without Runtime authority | `tests::an_inbox_answer_never_crosses_sessions` | FAILED on `assert!(!apply_inbox(..., InboxAnswer::AllowSession, Some("")))` (`:19467`) |

All three CAUGHT by `python3 -I examples/agent-host/falsify.py F-AH2a F-AH2b
F-AH2c`: `summary: 3 CAUGHT of 3`.

## Checks run

```text
bash examples/agent-host/verify.sh                                 219 passed, 2 ignored; clippy clean; guest hash 12d02f29 (unchanged)
bash examples/agent-host/run-local.sh                              1 passed
bash examples/agent-host/run-e2e.sh                                3 passed
python3 -I examples/agent-host/falsify.py --self-test              OK
python3 -I examples/agent-host/falsify.py                          91 CAUGHT of 91
cargo test --locked --manifest-path elastos/crates/elastos-compute/Cargo.toml --lib cargo_is_not_in_the_image -- --test-threads=2
                                                                   1 passed
python3 scripts/build/test_build_exec_initrd.py                    19 tests, OK (skipped=1)
```

## Principles

1. Named by hash: yes. Nothing new names code or content by a name or URL; the
   test compares stored-journal heads (`session_fingerprint:19247`).
2. No ambient authority: yes. A grant, a skill and an inbox answer stay in one
   `Journal` (`a_grant_never_crosses_sessions:19347`,
   `an_inbox_answer_never_crosses_sessions:19435`); no new import, no file,
   no network, no `wasi:*`.
3. One path (P10): yes. The session script uses the existing functions only
   (`admit_skill`, `propose_run`, `apply_inbox`, `compact`); no second rule and
   no second copy of a check was added.
4. Trusted core: yes. No `elastos/`, capsule or Runtime change; the work is
   guest tests in `examples/agent-host/src/lib.rs`.
5. Fails closed (P11): yes. The guest mints no grant for an `allow-session`
   answer; without a grant id the step is `Denied` (`F-AH2c` breaks it and the
   test catches it).
6. Self-contained (Rong): yes. Each session keeps its logic and state inside
   its own `Journal` and calls down only through the existing granted paths.
7. Tests prove it: yes. Four named tests and three falsifiers, each caught.

## Not proven

- The guest is single-threaded: "interleaved" means advancing four `Journal`s
  turn by turn in one process, not threads or concurrent tasks.
- This is a correctness proof for in-process session state, not a grade point.
- No journal **format** change was needed, so `USERSAI-JOURNAL.md` bytes and
  the guest hash are unchanged.
