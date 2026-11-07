# S2 journal format

```text
Slice:        S2 UsersAI journal format 1, guest only, no I/O. Overnight 1, item 3.
Branch / PR:  claude/overnight-1  https://github.com/SashaMIT/elastos-agent-host-spike/pull/3 (draft)
Commit:       540c50ad8444ad3d256f6f6a364896de795f3c4b (contract + encode/decode + 9 tests)
              4594443933fd02cbc345ed9ca0e42f10522e7d01 (cap boundary + relinked-malformed tests, contract note)
              parent db8a110c3690ee425a4ab28fefe971772e885887 (end of S1); this report is the next commit
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0, cargo 1.91.0.
Changed:      examples/agent-host/handoff/USERSAI-JOURNAL.md - the object contract (new)
              examples/agent-host/src/lib.rs - encode_journal, decode_journal, JournalReader, without_grants;
                run() round-trips its journal; 11 new tests
              examples/agent-host/handoff/reports/S2-journal-format.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    A journal encodes to exactly one format 1 byte string of at most 256 KiB. decode accepts only
              bytes that encode produced for some journal: right size, magic, format version, every hash
              link and the head, canonical records. It returns the same journal with every grant cleared.
              A grant string is never in the bytes, and empty assistant text is.
Refusals:     > 256 KiB -> "too large"        short or cut -> "truncated"      magic -> "not a journal"
              format != 1 -> "format version"  a link or the head -> "hash"     extra bytes -> "trailing bytes"
              tag out of order, unknown tag, backup/pending record without its flag, bool not 0/1,
              absent option with a value, bad enum tag, bad UTF-8, short payload -> "record"
              encode of a journal over the cap -> None
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "test result: ok. 86 passed; 0 failed", 0 warnings, "agent-host capsule verification: OK"
              ./examples/agent-host/run-local.sh -> "agent_host_example_keeps_the_head_across_a_compaction ... ok"
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "test result: ok. 16 passed; 0 failed"
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> "test result: ok. 7 passed; 0 failed"
              node --test scripts/home-agent-prefix.test.mjs scripts/home-agent-no-store.test.mjs -> "# pass 4 # fail 0"
Not run here: Mac-only tests; home-version-list-smoke.mjs (Chromium build mismatch).
Falsifiers:   17 mutations, one at a time on the committed code, undone with git checkout; tree clean after.
              S2a per-record link check removed      -> every_flipped_byte_is_refused FAILED
              S2b trailer head check removed         -> every_flipped_byte_is_refused FAILED
              S2c both removed                        -> every_flipped_byte_is_refused FAILED
              S2d format version check removed       -> a_wrong_format_version_is_refused FAILED
              S2e decode keeps a grant                -> a_grant_is_never_stored FAILED (+1)
              S2f final encode cap check removed      -> the_cap_holds_at_the_last_byte FAILED
              S2g decode cap check removed            -> a_journal_over_the_cap_is_refused FAILED
              S2h trailing bytes accepted             -> every_truncation_is_refused FAILED
              S2i epoch not restored                  -> node_zero_and_the_epoch_survive_a_round_trip FAILED (+5)
              S2j prev_head not written               -> the_previous_head_links_two_versions FAILED
              S2k empty assistant dropped on encode   -> decoding_keeps_the_replay_bytes FAILED (+2)
              S2l absent option may carry a value     -> a_relinked_but_malformed_journal_is_refused FAILED
              S2m record order not checked            -> a_relinked_but_malformed_journal_is_refused FAILED
              S2n reader bool accepts any byte        -> a_relinked_but_malformed_journal_is_refused FAILED
              S2o backup record without its flag      -> a_relinked_but_malformed_journal_is_refused FAILED
              S2p header bool accepts any byte        -> a_relinked_but_malformed_journal_is_refused FAILED
              S2q run() expects prev_head [1; 32]     -> run-local: "the journal did not round-trip through format 1"
              In the first pass S2f, S2l and S2m failed no test. That led to the two tests in 4594443
              and the "corruption, not tampering" note in the contract (see below).
Guest hash:   fa10cca7929f1d538e914337999230e9daf6cd5413edf8256824ceb893d6be33 on two builds (verify.sh, run-local.sh).
              Changed from e34772d1 because S2 adds guest code (the encoder runs in run()).
              wasm_sections.py: file 273813 bytes; /1/10 213981 fe08902a8843d2d0 (was 201840).
Import list:  unchanged (elastos:bus/identity@1.0.0, runtime@1.0.0, types@1.0.0); run-local checks it.
Principles:   7 One authority model: agent state goes under UsersAI/self, parallel to Users/self.
              11 Fail closed: any unexpected byte refuses the whole journal; a decoded step has no grant.
              16 UI is not authority / no bearer tokens: a grant string is never in the bytes.
              19 Consequences: a decoded Dispatched step keeps its state, so a crash note makes it
                 settlement_unknown and nothing is dispatched again.
              12 Docs, code, tests agree: USERSAI-JOURNAL.md lists the refusals and tests, and each has a falsifier.
DeepSeek:     docs/subsystems/session.md and packages/llm/llm-deepseek/src/serialize.ts:30,:123 at 687f282e,
              for the empty-assistant choice only. No code copied.
Not proven:   Nothing is stored yet; that is S3. The Runtime revision, the compare-and-swap, the UsersAI/self
              rewrite, and refusing another principal's root are not built.
              The hash chain has no key. It detects corruption, not a hostile writer; the Runtime's
              owner-only storage is what prevents tampering (S3).
Checklist:    56 of 63 (no todo moved; hold-usersai is S3)
Questions:    1. Grants are not stored, so decode(encode(j)) equals j only when no step holds a grant.
                 HANDOFF says "decode(encode(j)) is j". I followed docs/AGENT_ARCHITECTURE.md:336 (Runtime owns
                 grants) and PRINCIPLES 16. Please confirm this reading before S3 writes anything.
```

## Our choice on empty assistant text

We keep an empty assistant line in the journal bytes and in `model_bytes`; `derive` drops it from the model view. DeepSeek, since 687f282e, drops it while serializing the request (`serialize.ts:30`, `:123`). Both keep it away from the model. We keep it in the record because our journal is the durable log, and `model_bytes`/`replay` must stay exact inverses of it (SLICES, review corrections). A later change to the view can then never rewrite stored bytes. `decoding_keeps_the_replay_bytes` checks that an empty assistant line survives the round trip, and mutation S2k breaks it.

## Grade

No row moves. Row 2 (session log) now has a versioned, integrity-checked format, but the journal is still not stored, so it stays at 3 until S3. Total stays **38 of 70**.

## What is next

Overnight item 4: S3 design (no code).
