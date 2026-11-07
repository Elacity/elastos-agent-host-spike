# Same-tick file-cache tampers (for Anders, after 0.8.0)

This is a lab note. It is not a Runtime change. The two caches live in
elastos-runtime `develop` at `92aeea44`. This tree holds the same bytes
(`release_publication.rs` `6aad02e3`, `browser_vm_image.rs` `93c908cd`).
Every commit on those files is the Runtime team's. The spike owns none of
the cache.

## The gap

Both caches treat a file as unchanged while its device, inode, size, mode,
mtime and ctime match. Linux 6.12 stamps mtime and ctime from
`CLOCK_REALTIME_COARSE` (4 ms here). A same-size rewrite in that tick keeps
every compared field. Anyone who can write the file can also restore mtime
with `utimensat`. ctime is the only remaining stamp, and it does not move.

The four tests that this hole breaks:

- `published_cache_refuses_same_size_in_place_metadata_and_artifact_changes`
  (`release_publication.rs:1260`)
- `browser_image_cache_reuses_unchanged_set_and_invalidates_release_receipt_and_replacement`
  (`browser_vm_image.rs:1562`)
- `browser_image_cache_rejects_same_size_mutation_with_restored_mtime_and_keeps_failures_uncached`
  (`browser_vm_image.rs:1594`)
- `browser_image_cache_rejects_mutation_between_verification_and_admission`
  (`browser_vm_image.rs:1614`)

They pass when the clock happens to tick. They fail when it does not.

## Reproduction

`lab/runtime-asks/cache-tamper` waits for a fresh coarse tick, does the last
honest write and the tamper in that tick, and restores mtime with
`utimensat` (`FileTimes::set_modified`). An attempt that crosses a tick is
discarded. The tests then check the precondition (stamp equal, bytes
different) before they ask the Runtime.

```bash
CARGO_TARGET_DIR=/workspace/target-build \
  cargo test --locked --manifest-path lab/runtime-asks/cache-tamper/Cargo.toml
```

Today the Runtime admits the rewrite. `read_verified_artifact` and a cold
image check still refuse the bytes. The cache is the hole.

## Trial patch

`lab/runtime-asks/cache-tamper/trial.patch` is a trial only. Apply it, run
the four tests, then restore the two Runtime files. Do not land it here.

The patch does two small things:

1. Browser image identity also carries a content hash. A same-tick rewrite
   changes the hash, so the cache misses and verification runs again.
2. Publication `unchanged_published` keeps the cheap stamp path when ctime
   is older than the current coarse clock (git's racy-git rule). In the
   current tick it re-hashes against the admitted digest.

AuthState already uses ctime to catch a restored mtime. That is not enough
on this kernel. The hash, or a racy re-hash, is.

## How to prove

```bash
sha256sum \
  elastos/crates/elastos-server/src/release_publication.rs \
  elastos/crates/elastos-server/src/setup/browser_vm_image.rs
git apply lab/runtime-asks/cache-tamper/trial.patch
export RUST_TEST_THREADS=2
export CARGO_TARGET_DIR=/workspace/target-build
for i in $(seq 1 20); do
  (cd elastos && cargo test -p elastos-server --locked -- \
    published_cache_refuses_same_size_in_place_metadata_and_artifact_changes \
    browser_image_cache_reuses_unchanged_set \
    browser_image_cache_rejects_same_size_mutation \
    browser_image_cache_rejects_mutation_between_verification)
done
# falsifier: drop the hash / racy re-hash, one of the four fails
git checkout -- \
  elastos/crates/elastos-server/src/release_publication.rs \
  elastos/crates/elastos-server/src/setup/browser_vm_image.rs
sha256sum \
  elastos/crates/elastos-server/src/release_publication.rs \
  elastos/crates/elastos-server/src/setup/browser_vm_image.rs
```

Results of the run that wrote this note:

- Machine: Linux 6.12 x86_64, rustc 1.91.0. `CLOCK_REALTIME_COARSE` is 4 ms.
- Ownership: Runtime. Files match Elacity `develop` `92aeea44` (`6aad02e3`, `93c908cd`) before and after the trial.
- Repro (unpatched Runtime): `cargo test --locked` in this crate → 4 passed, 20 of 20 runs.
  (`browser_image_check_admits_a_same_size_rootfs_rewrite_from_the_same_tick`,
  `published_release_check_reports_a_same_size_artifact_rewrite_from_the_same_tick_unchanged`,
  `trial_rule_refuses_a_racy_same_size_rewrite`,
  `trial_rule_trusts_an_old_matching_stamp`).
- Four Runtime tests with `trial.patch` applied: 20 of 20 passed
  (`published_cache_refuses_same_size_in_place_metadata_and_artifact_changes`,
  `browser_image_cache_reuses_unchanged_set_and_invalidates_release_receipt_and_replacement`,
  `browser_image_cache_rejects_same_size_mutation_with_restored_mtime_and_keeps_failures_uncached`,
  `browser_image_cache_rejects_mutation_between_verification_and_admission`).
- Same four tests after restore (no patch): `published_cache_refuses_same_size_in_place…`
  failed 10 of 10 at `release_publication.rs:1260`.
- Falsifier: `TRUST_RACY_STAMP = true` → `trial_rule_refuses_a_racy_same_size_rewrite`
  panicked `a racy same-size rewrite must not be a cache generation`. Constant
  restored to `false`.
- Runtime files restored: `git hash-object` matches `HEAD` (`6aad02e3`, `93c908cd`).

## Lab rule

`lab/runtime-asks/cache-tamper/src/lib.rs` is the same rule in a few lines,
so a plant can turn it off. `trial_rule_refuses_a_racy_same_size_rewrite`
must fail when `TRUST_RACY_STAMP` is set to `true`.
