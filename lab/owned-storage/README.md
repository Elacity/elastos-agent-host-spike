# owned-storage

Lab stand-in for M1 check A9. One agent cannot read or write another agent's files.

The component launcher still passes `/tmp/elastos/storage` to every component run (`elastos/crates/elastos-server/src/run_cmd.rs`). `LocalMutableStorage` keeps a path inside the base directory the caller already chose (`elastos/crates/elastos-storage/src/mutable/local.rs`). This crate gives each agent instance its own base directory, bound to that instance's identity and session.

The grant names the root `UsersAI/<identity>/<session>/<instance>`. Those fields match `grant_binding::Decision` (`identity`, `session`, `owned_root`) plus the instance that decision is bound to. This crate does not bind grants. `lab/grant-binding` and the cx-agent-conformance lane own that check (A5).

A path into another agent's root is refused with a reason. The refused paths are the other agent's host path, a `..` path, a symlink that leaves the root, and the shared temp directory `/tmp/elastos/storage`. Cleanup removes the yard. Drop removes it too. When removal fails, the yard is sealed so it cannot be read.

This crate does not change the Runtime. AC-006-STORAGE stays open until the launcher derives storage from the selected Home.

## Checks

```bash
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
```

`plants/F-A9-share.txt` makes every instance use one directory. `planted_shared_root_is_caught` requires the three denial tests to fail on that plant.
