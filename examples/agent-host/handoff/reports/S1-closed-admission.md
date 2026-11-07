# S1 closed admission

```text
Slice:        S1 sell-closed-admission. Overnight 1, item 2.
Branch / PR:  claude/overnight-1  https://github.com/SashaMIT/elastos-agent-host-spike/pull/3 (draft)
Commit:       e7ca94e40ed26658072422e3d3c3e140af923557 (launch test), fe365006e01cd835db9a302fc33a267c9502dd31 (no-store test)
              parent 367601314856785a44ea8c7df9c707a0429c0d04 (end of S0c); this report is the next commit
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0, cargo 1.91.0.
Changed:      elastos/crates/elastos-server/src/runtime.rs - one new test inside `mod tests`; no production line changed
              scripts/home-agent-no-store.test.mjs - new Node test: the Assistant is not a store
              examples/agent-host/handoff/SLICES.md - todo sell-closed-admission -> completed
              examples/agent-host/handoff/reports/S1-closed-admission.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    While #217 is open, a capsule that is unsigned, or signed by a key this Home does not trust, or
              whose entrypoint changed after a trusted signature, is refused at launch before any compute
              provider loads it. On an installed Home, capsules are installed only when the signed release
              names them. The Assistant is not a store: it can only ask Home to open Marketplace.
Refusals:     Launch (Runtime::run_local -> verify_capsule_signature, runtime.rs:282, before provider.load at :297):
                unsigned, Home with no release and dev_mode off -> Err "... is unsigned; only a source or development Home ..."
                signed by an untrusted key (fixture key 9)     -> Err "Capsule signature verification failed"
                trusted signature, entrypoint bytes changed      -> Err "Capsule signature verification failed"
                no trusted key configured at all                 -> Err "... has no trusted keys configured" (runtime.rs:383-387)
                installed Home, unsigned capsule not at its release path -> Err "... not from the installed signed release"
              Install (setup): a component with no signed release path -> Err "must come from the signed release:
                release_path is required" (setup.rs:3499); wrong catalog/head/release signer -> refused with no writes.
              Control: the same capsule signed by the trusted fixture key 42 is loaded (provider load count 1).
Tests run:    export RUST_TEST_THREADS=2
              (cd elastos && cargo test -p elastos-server --lib -- launch_refuses_untrusted_signers_before_the_provider_loads
                installed_release_refuses_unsigned_and_foreign_signed_local_capsules
                home_without_installed_release_runs_unsigned_capsules_only_in_dev_mode) -> 3 passed
              (cd elastos && cargo test -p elastos-server --lib -- component_without_signed_release_path_is_refused_before_fetch
                installed_setup_refuses_wrong_signers_without_writes installed_setup_refuses_tampered_components_without_writes
                ensure_capsule_component_rejects_registry_checksum_mismatch_before_fetch) -> "test result: ok. 4 passed"
              (cd elastos && cargo clippy -p elastos-server --lib --tests -- -D warnings) -> exit 0, no warnings
              cargo fmt --manifest-path elastos/Cargo.toml -p elastos-server -- --check -> ok
              node --test scripts/home-agent-no-store.test.mjs -> "# pass 2 # fail 0"
              node scripts/home-agent-shell-smoke.mjs -> "canonical Assistant shell smoke: ok"
              node --test scripts/home-agent-cancellation.test.mjs -> "# pass 50 # fail 0"
              ./examples/agent-host/verify.sh -> 75 passed (run at the end of S0c; the guest is untouched since)
Not run here: the whole elastos-server suite (3036 tests; only the named ones). Mac-only VM tests.
Falsifiers:   One at a time on the committed tests, undone with git checkout; tree clean after each.
              S1a runtime.rs:282 `self.verify_capsule_signature(&manifest, path).await?;` removed
                  -> launch_refuses_untrusted_signers_before_the_provider_loads FAILED; the two team tests PASSED
                  (they call verify_capsule_signature directly, so before S1 nothing pinned the launch path) -> reverted
              S1b `if !verifier.verify_capsule(...)` -> `if false && ...`
                  -> launch_refuses_... FAILED, installed_release_refuses_... FAILED -> reverted
              S1c configure_capsule_admission `(None, false) => Refused` -> `Allowed`
                  -> launch_refuses_... FAILED, home_without_installed_release_... FAILED -> reverted
              S1d setup.rs required_release_path accepts a blank path (`.filter(|_| true)`)
                  -> component_without_signed_release_path_is_refused_before_fetch FAILED -> reverted
              S1n1 Assistant capsule.json gains "capabilities": ["elastos://marketplace/*"]
                  -> "the Assistant manifest grants no store operation" FAILED -> reverted
              S1n2 assistant.js posts `marketplace:buy` instead of `home:open-target`
                  -> "the Assistant page only asks Home to open Marketplace" FAILED -> reverted
              S1n3 assistant.js fetches `/api/provider/marketplace/buy` instead of the catalog
                  -> "the Assistant page only asks Home to open Marketplace" FAILED -> reverted
              The positive control (trusted key 42 loads once) is inside the new test, so a check that refuses
              everything fails it too.
Guest hash:   e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1 (unchanged; guest not touched)
Import list:  unchanged
Principles:   15 Trust travels with signed content: launch admits only a signature from a key this Home trusts,
                over the entrypoint bytes; install admits only what the signed release names.
              11 Fail closed: no trusted key, no signature, or a wrong signature stops the launch before load.
              16 UI is not authority: the Assistant only asks Home to open Marketplace; it holds no store operation.
              18 Isolated capsules: the refusal is before the compute provider sees the capsule.
DeepSeek:     none (DeepSeek has a plugin manager and no signed admission).
Not proven:   Capsule signatures still cover the manifest and the entrypoint file only, not the whole tree
              (runtime.rs:389, "hash the entrypoint file"). A trusted signer's capsule can change its other files.
              This is the known e-init-whole-tree gap; S1 did not change it.
              Fixture keys 9, 42, 71 are disposable test keys (AGENTS.md standing test-key permission). No real key was used.
              Web projections (Home GUI apps) open through Home launch tokens, not through run_local. I did not
              check their admission path in this slice.
Checklist:    56 of 63 (sell-closed-admission moved to completed)
Questions:    none
```

## How the pieces fit

- **Launch.** `Runtime::run_local_with_principal` calls `verify_capsule_signature` (`runtime.rs:282`) before it picks and loads a provider (`:286-297`). The default is fail-closed: `UnsignedCapsules::Refused` (`:68`, `:85`). `create_runtime` (`main.rs:2297-2339`) configures admission from `config.toml` trusted keys plus the installed release's publisher keys (`runtime.rs:188-210`). `elastos run` reaches `run_local` for component capsules (`run_cmd.rs:265`) and for other types (`:71`). MicroVM capsules are launched by the supervisor by name only, from the signed release registry (`supervisor.rs:839-874`).
- **Install.** On an installed Home, setup installs only components the signed release names, and checks the release's signers first. A capsule from someone else has no install path while #217 is open.
- **The gap S1 closed.** The team test `installed_release_refuses_unsigned_and_foreign_signed_local_capsules` (`runtime.rs:722`) calls `verify_capsule_signature` directly. Removing the call from the launch path (S1a) failed no existing test. The new test goes through `run_local` and counts provider loads.

## Grade

Row 14 (Package and sell) moves from **0 to 1**. Closed admission at launch and install, and an Assistant with no store, are now proven by named tests with falsifiers. Packaging and selling themselves are not built, and the signature still covers only the entrypoint, so the row stays low. Total **38 of 70**.

## What is next

Overnight item 3: S2 journal format.
