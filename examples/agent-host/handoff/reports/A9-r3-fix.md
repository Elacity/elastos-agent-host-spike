# A9 r3 fix (draft #290)

Lab only. Do not merge. Do not book A9.

```text
Slice:        A9 r3 fix (positive ownership, NO_XDEV, live walk pins)
Branch / PR:  cursor/owned-storage-a9-9b7c  https://github.com/Elacity/elastos-agent-host-spike/pull/290
Commit:       9e0f28552c9862b7c02a92467caaa746217a6c2b
Parent:       8d4d50104edcfd1eee03e4cd93816e7ed62b6088
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28), kernel 6.12.94+
```

The r3 review (draft #401) found three Store journeys that still let B see or receive A's bytes, and a surviving walk-flag pin. Those holes were in `lab/owned-storage`. Runtime store code was not patched. `lab/a9/RUNTIME-ASK.md` now names the second-store map gap, bind-mount / `RESOLVE_NO_XDEV`, and that a per-store inode map is not enough.

## What changed (Flint)

1. Ownership is positive. A Store may read, list or write an existing file only when that file's `(st_dev, st_ino)` is in the agent's own on-disk record, written when that agent's Store created the file. The record lives beside the agent root, survives restart, and is shared across Store handles. Host-created files renamed into B, and files from another Store yard after link+unlink, are refused. `st_nlink > 1` stays refused.
2. The live walk adds `RESOLVE_NO_XDEV`. A bind-mount of another agent's tree under B is refused. The `unshare -Urm` journey ran here and printed `bind-mount unshare child: CAUGHT`.
3. Live walk flags are pinned in `walk.rs`. `M-no-nofollow` drops `nofollow_flag()` on the path `open_one` uses. Mutants also drop `RESOLVE_NO_SYMLINKS` and force plain `openat`. All are caught.
4. New plants: `F-A9-host-rename`, `F-A9-two-yards`, `F-A9-bind-mount`, `F-A9-no-xdev`. All CAUGHT.

Runtime rows stay Blocked (`AC-006-STORAGE`, `executed=false`, `read_refusal=None`). Host same-uid walks stay `NEEDS CONFINEMENT/RUNTIME`. A host-planted file in A's tree is now refused by the Store (the host process can still read it).

## Tests on 9e0f2855

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean, exit 0

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 23 tests, 0 benchmarks. No ignored names.

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
# 23 passed; 0 failed; 0 ignored
# bind-mount unshare child: CAUGHT
# race two-store iters=5000 denied=4999 escaped=0
# NOT RUN: APFS case/Unicode (not a Mac)

python3 -I lab/owned-storage/r2-mutants.py
# mutants=12 caught=12 surviving=0
```

Race: 5000 iterations, two Store instances, 0 files left in B (`escaped=0`, `denied=4999`).

Plants (10 files, all CAUGHT by `planted_shared_root_is_caught`):

```text
F-A9-bind-mount
F-A9-fake-runtime
F-A9-hardlink
F-A9-hardlink-unlink
F-A9-host-rename
F-A9-no-xdev
F-A9-nofollow
F-A9-root-swap
F-A9-share
F-A9-two-yards
```

Mutants (12, all caught):

```text
M-root-swap          caught
M-hardlink-nlink     caught
M-list-no-resolve    caught
M-a5-users           caught
M-inode-noop         caught
M-unowned-allow      caught
M-no-nofollow        caught   (now mutates walk.rs)
M-walk-no-symlinks   caught
M-walk-force-openat  caught
M-walk-no-xdev       caught
M-share-count-zero   caught
M-fake-runtime-read  caught
```

`/tmp/elastos/storage` absent before and after. Worktree clean after mutants.

```text
lib.rs    sha256 82b79350ae0cb7cac7b8b310ca188d29d4ea57f0d0d8a2710c3ee265dc6e8cd5
walk.rs   sha256 12577ada20a9edfcab5a149a9139e383237c5e27e445afdd00c418facdb5bc54
launch.rs sha256 d3ed87a9acfe22eab892fa13083a9ea6dabbdbbc37ac9501610f027a6c2c267c
```

## macOS

APFS case-fold and Unicode normalization: **NOT RUN** (this is Linux ext4). The named test `apfs_case_and_unicode_not_run_off_macos` prints that and passes. Run it on a Mac before claiming those names.

## Principles

- 3 No ambient authority: Store IO stays on the grant's root fd. A bind-mount under that fd is refused by `RESOLVE_NO_XDEV`.
- 11 Fail closed, then explain: an inode this agent did not create stops with `HardLink`. A mount crossing stops with `CrossMount`.
- 12 Docs, code, tests agree: Runtime rows stay Blocked; RUNTIME-ASK is for Anders.
- 18 Isolated execution: lab directories are separate. The host process is not.

DeepSeek: none.
Runtime-ASK: yes, `lab/a9/RUNTIME-ASK.md` (second-store, bind-mount, per-store map is not enough).
Not proven: two Runtime agents; host same-uid confinement; inode-number reuse after a host unlink; APFS case/Unicode.
