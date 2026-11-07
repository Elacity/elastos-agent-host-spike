# A9 r4 fix (draft #290)

Lab only. Do not merge. Do not book A9.

```text
Slice:        A9 r4 fix (path+stamp ownership, forget on unlink)
Branch / PR:  cursor/owned-storage-a9-9b7c  https://github.com/Elacity/elastos-agent-host-spike/pull/290
Parent:       c411060d8c86db853fae352dd20d56da019c9d26
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28), kernel 6.12.94+
```

The r4 review (draft #411) at `c411060d` found that `{root}.owned` never forgets a `(dev, ino)`. After A unlinked a file, B's Store create reused the pair. A host rename of that file into A's tree made `Store::read(&a, "stolen.txt")` return B's bytes.

## What changed

An ownership entry now binds `(dev, ino)` to the owning agent, the exact relative path, and a generation stamp: `ctime`, birth time where `statx` has it, and a 16-byte nonce in `user.owned-storage.nonce`. Read and write `fstat` the opened fd and refuse unless every field matches. Store unlink forgets the entry. Store rename updates the path and refreshes `ctime`. A create whose `(dev, ino)` already appears replaces that stale entry only for the creator. The old owner's leftover line fails closed on path or stamp.

`lab/a9/RUNTIME-ASK.md` names the hole: a persisted `(dev, ino)` set that never forgets an unlinked inode grants after reuse.

Runtime rows stay Blocked (`AC-006-STORAGE`, `executed=false`, `read_refusal=None`). Host same-uid walks stay `NEEDS CONFINEMENT/RUNTIME`.

## Tests

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean, exit 0

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 25 tests, 0 benchmarks. No ignored names.

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
# 25 passed; 0 failed; 0 ignored
# bind-mount unshare child: CAUGHT
# inode-reuse journey CAUGHT
# race two-store iters=5000 denied=4906 escaped=0
# NOT RUN: APFS case/Unicode (not a Mac)

python3 -I lab/owned-storage/r2-mutants.py
# mutants=14 caught=14 surviving=0
```

```text
lib.rs    sha256 76b4458f3f1fabeb632cbe85f66a9a991ecebf66104186c3e86ace464c00109a
walk.rs   sha256 4af2844f495a591606f801c740757ba95e06f3728d4351b109fa541a7b3a0b92
launch.rs sha256 d3ed87a9acfe22eab892fa13083a9ea6dabbdbbc37ac9501610f027a6c2c267c
```

The previous official bar still holds: those 23 names pass, the original 10 plants still catch, the original 12 mutants still catch, race `escaped=0`, bind-mount CAUGHT.

New plants (both CAUGHT by `planted_shared_root_is_caught`):

```text
F-A9-inode-reuse        CAUGHT   require_generation_bind off; stolen.txt grants
F-A9-host-rename-own    CAUGHT   require_path_match off; host rename inside A grants
```

New mutants:

```text
M-stamp-skip            CAUGHT   require_stamp_match off; same-name reuse grants
M-unlink-keep           CAUGHT   forget_on_unlink off; gone.txt inode stays in the record
```

Official plant files are now 12. Official mutants are now 14.

## macOS

APFS case-fold and Unicode normalization: **NOT RUN** (this is Linux ext4). The named test `apfs_case_and_unicode_not_run_off_macos` prints that and passes.

## Runtime rows

Blocked. This session did not start `elastos`.

- `real_runtime_each_instance_has_its_own_storage_root`: Blocked, `BLOCKED AC-006-STORAGE: elastos run calls create_runtime("/tmp/elastos/storage")`.
- `real_runtime_agent_a_read_of_b_is_refused`: Blocked, `BLOCKED AC-006-STORAGE: agent file reads do not use that storage provider`.
- `executed=false`, `read_refusal=None`.

## Principles

- 3 No ambient authority: Store I/O stays on the grant's root fd. A recycled inode is not a grant.
- 11 Fail closed, then explain: reused, host-renamed, or stamp-mismatched entries stop with `HardLink`.
- 12 Docs, code, tests agree: Runtime rows stay Blocked; RUNTIME-ASK names inode reuse.
- 18 Isolated execution: lab directories are separate. The host process is not.

DeepSeek: none.
Not proven: two Runtime agents; host same-uid confinement; APFS case/Unicode.
