# owned-storage

Lab stand-in for M1 check A9. One agent cannot read, write, list or rename another agent's files through the Store API.

The component launcher still passes `/tmp/elastos/storage` to every component run (`elastos/crates/elastos-server/src/run_cmd.rs`). `share_cmd.rs:183` is a fourth `create_runtime("/tmp/elastos/storage")` site. `LocalMutableStorage` keeps a path inside the base directory the caller already chose (`elastos/crates/elastos-storage/src/mutable/local.rs`). This crate gives each agent instance its own base directory.

The grant names the root with the A5 shape `UsersAI/<agent>/<rest>`. For this store, `rest` is `<session>/<instance>`. This crate does not call `lab/grant-binding`; the grant is unbound. `lab/grant-binding` and the cx-agent-conformance lane own A5.

A path into another agent's root is refused with a reason. The refused paths are the other agent's host path, a `..` path, any symlink (the walk uses `openat2` `RESOLVE_NO_SYMLINKS` or per-component `O_NOFOLLOW`), a bind-mount of another tree (`RESOLVE_NO_XDEV`), a root directory replaced by a symlink, a hard-linked inode (`st_nlink > 1`), a file this agent did not create through the Store (host-created files renamed in, and files from another Store yard after link+unlink), a reused inode after unlink, a host rename inside the same tree, and the shared temp directory `/tmp/elastos/storage`. Ownership is a per-agent on-disk record that binds `(st_dev, st_ino)` to the owning agent, the exact relative path, and a generation stamp (ctime, birth time, and a per-inode nonce). The Store writes the record when it creates the file. Read and write `fstat` the opened fd and refuse unless every field matches. Store unlink forgets the entry. Store rename updates the path. A create whose `(dev, ino)` already appears replaces that stale entry only for the creator. The record survives restart and is shared across Store handles. It is not an in-memory map. The Store does not create hard links. Every path component is opened from the capsule root fd. Cleanup removes the yard. Drop removes it too. When removal fails, the yard is sealed so it cannot be read.

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

`plants/F-A9-share.txt` makes every instance use one directory. `F-A9-hardlink-unlink` drops the on-disk owner check. `F-A9-nofollow` drops live-walk `O_NOFOLLOW` in `walk.rs`. `F-A9-host-rename`, `F-A9-two-yards`, `F-A9-bind-mount`, and `F-A9-no-xdev` cover the r3 hunts. `F-A9-inode-reuse` and `F-A9-host-rename-own` cover the r4 hunts. `planted_shared_root_is_caught` requires the denial tests to fail on those plants.

APFS case-fold and Unicode normalization stay NOT RUN off a Mac.
