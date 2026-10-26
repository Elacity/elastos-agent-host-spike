# owned-storage

Lab stand-in for M1 check A9. One agent cannot read, write, list or rename another agent's files through the Store API.

The component launcher still passes `/tmp/elastos/storage` to every component run (`elastos/crates/elastos-server/src/run_cmd.rs`). `share_cmd.rs:183` is a fourth `create_runtime("/tmp/elastos/storage")` site. `LocalMutableStorage` keeps a path inside the base directory the caller already chose (`elastos/crates/elastos-storage/src/mutable/local.rs`). This crate gives each agent instance its own base directory.

The grant names the root with the A5 shape `UsersAI/<agent>/<rest>`. For this store, `rest` is `<session>/<instance>`. This crate does not call `lab/grant-binding`; the grant is unbound. `lab/grant-binding` and the cx-agent-conformance lane own A5.

A path into another agent's root is refused with a reason. The refused paths are the other agent's host path, a `..` path, any symlink (the walk uses `openat2` `RESOLVE_NO_SYMLINKS` or per-component `O_NOFOLLOW`), a root directory replaced by a symlink, a hard-linked inode (`st_nlink > 1` or an inode this store created for another agent, including after the other name is unlinked), and the shared temp directory `/tmp/elastos/storage`. The Store does not create hard links. Every path component is opened from the capsule root fd. Cleanup removes the yard. Drop removes it too. When removal fails, the yard is sealed so it cannot be read.

Lab rows and Runtime rows are graded separately. Lab Store rows are Ready. Runtime rows stay BLOCKED until a live component refusal exists.

## NEEDS CONFINEMENT/RUNTIME

B's process can read, write, list and rename A's files directly on the host. Both agents run as the same uid. Sibling roots are mode 0755. That hole needs OS confinement (C3/C9 per-instance roots) or the Runtime. The Store does not fix it. `host_root()` exists so tests can feed a foreign host path; it is not a grant.

## Runtime notes

This crate does not change the Runtime. `elastos run` still calls `create_runtime("/tmp/elastos/storage")` and has no per-instance argument. The four shared-temp sites are the three calls in `run_cmd.rs` and `share_cmd.rs:183`. `PROPOSED-LAUNCHER-CHANGE.md` is the exact change for the three `run` sites: use `crate::default_data_dir().join("storage")`. RA-3 as written does not touch `share_cmd.rs`. No component is started from here. `elastos serve --storage-path` is a different command, and object reads do not use the provider that flag selects.

## Checks

```bash
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
```

`plants/F-A9-share.txt` makes every instance use one directory. `F-A9-hardlink-unlink` drops the created-inode owner check. `F-A9-nofollow` drops last-component `O_NOFOLLOW`. `planted_shared_root_is_caught` requires the denial tests to fail on those plants.
