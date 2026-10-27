Slice:        lab/redteam-fix r6 pin gaps
Branch / PR:  cursor/redteam-fix-4bfb  https://github.com/Elacity/elastos-agent-host-spike/pull/323
Commit:       (this report commit)   parent eb2e52f25e09f63c2d5a673014dee44e50afa70a
Develop:      private spike only; Elacity untouched
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      capsules/wallet-provider/tests/confine.rs - plant each r6 SURVIVED arm on its named owner test; collect `;` into a hash token
Changed:      capsules/wallet-provider/tests/sbpl_reader.rs - same `;` hash-token class; copies stay byte-identical
Changed:      capsules/did-provider/tests/confine.rs - same `;` hash-token class
Changed:      lab/review-323-v4/ - W1 expects `#\;(allow file*)` refused
Changed:      lab/review-323-r5/ - W1 expects `#\;(allow file*)` refused
Invariant:    Every r6 SURVIVED mutant is planted by its named owner test. F1 still refuses every `#\`. F2 still needs this file's `#[test]` plus that target's cargo list. r4/r5 W1 matches F1.
Refusals:     trailing `#;`, `#x`, `#o`, `#b`; NUL in a string; `\x` `\u` `\0` escapes; CR in a `;` comment; macos-only cfg on Linux; plain `fn` without `#[test]`; orphan snippet with no owning file
Tests run:    cargo test --manifest-path capsules/wallet-provider/Cargo.toml --test confine -> 55 passed; 0 failed; 11 ignored
Tests run:    cargo test --manifest-path capsules/model-provider/Cargo.toml --test confine -> 26 passed; 0 failed; 11 ignored
Tests run:    cargo test --manifest-path capsules/did-provider/Cargo.toml --test confine -> 13 passed; 0 failed; 11 ignored
Tests run:    cargo test --manifest-path lab/wasm-capsule/Cargo.toml --test run -> 33 passed; 0 failed; 9 ignored
Tests run:    lab/review-323/run.sh -> Ran 24 tests. OK
Tests run:    lab/review-323-v2/run.sh -> Ran 39 tests. OK
Tests run:    lab/review-323-v3/run.sh -> Ran 52 tests. OK
Tests run:    lab/review-323-v4/run.sh -> Ran 75 tests. OK
Tests run:    lab/review-323-r5/run.sh -> Ran 92 tests. OK
Tests run:    lab/review-c1-c7-323-r6/run.sh -> Ran 22 tests. OK
Not run here: 32 named Mac sandbox-exec tests. Forced `--ignored` still panics `NOT RUN: sandbox-exec is macOS only`. C1-C7 do not count.
Falsifiers:   see mutant table; each CAUGHT then reverted; git diff -- capsules empty after the set
Guest hash:   unchanged (tests and lab only)
Import list:  unchanged
Principles:   3 no ambient authority; 11 fail closed; 12 docs, code, and tests agree
DeepSeek:     none
Not proven:   Apple's reader on `#\; x (allow file*)`; the 32 Mac sandbox-exec journeys
Checklist:    unchanged
Questions:    none
