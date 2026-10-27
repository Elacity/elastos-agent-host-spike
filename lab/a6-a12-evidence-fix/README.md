# A6 / A12 evidence fix

Lab-only checks for the two #294 holes that #323 left as NEEDS RUNTIME.
This folder calls Runtime `CapabilityManager::grant` / `validate` and owner
`census::cleanup` / `ThrowawayHome`. It does not edit those crates,
`BACKLOG.md`, `lane.env`, or `scripts/`.

## What the checks prove

- **A6:** instance-1 is granted a real session token. `validate` accepts that
  token as instance-1. The same token as instance-2 is `WrongCapsule
  { expected: instance-1, got: instance-2 }` (fields compared, not
  substrings). Prefix, empty, case, zero-width, other resource/action,
  expired, revoked, and tampered-base64 cases are named tests. This is an
  in-process Runtime library journey. It is not two resident capsule
  instances inside one Home. Two resident instances are **RA-6**. The
  ready journey reports **BLOCKED**, never PASS, until the Runtime hosts
  that pair. Removing validate step 4 from the Runtime this process
  loaded makes that journey FAIL. An `Ok` from a stub with an empty
  `ResidentPair` is FAIL. Two live `/proc` pids that are not proven
  resident capsules (this process plus pid 1) are FAIL. Two other live
  pids without RA-6 host proof are BLOCKED. PASS needs two independent
  resident capsule instances inside one Runtime, each holding its own
  grant, sibling refused by the Runtime.
- **A12:** leftover census records the (dev, inode, ctime, full-content
  hash, file handle) set a run created. A rename to an unrelated name
  (`moved-away`), a leftover with no lab marker, a same-path
  delete+recreate that reuses an inode with the same bytes, and a
  65 KiB last-byte rewrite with mtime restored are found. The content
  hash covers the whole file and is sparse-aware (SEEK_HOLE map). An
  empty file handle is FileId NOT RUN. The snapshot is taken before
  the Runtime starts; if the Runtime already wrote under the watch or
  under `/tmp/elastos`, it fails. The run-window watch also covers
  `/tmp`, `/var/tmp`, `/dev/shm`, `$TMPDIR`, XDG
  cache/data/state/runtime dirs, and `~/Library/Caches` /
  `~/Library/Application Support`, plus inotify for create-then-delete.
  `ELASTOS_TMP_ROOT` is guarded after realpath: `/`, empty, `$HOME`, a
  `..` component, a symlink at or under isolation, a reachable live Home,
  and anything whose canonical path is not under the pack mktemp are
  refused. Writes re-check the root, then open with
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.
  `run.sh` / `mac-pack.sh` set `ELASTOS_TMP_ROOT` to a fresh
  `mktemp -d` folder and clean only that. A clean isolated root is PASS.
  `ThrowawayHome::new` + `census::cleanup` are called; on Linux that
  construction is NOT RUN.

## How to run

From the repository root:

```sh
./lab/a6-a12-evidence-fix/run.sh
```

`run.sh` always creates an isolated mktemp, exports `ELASTOS_TMP_ROOT`
and `ELASTOS_TMP_ISOLATION`, runs the lib tests, prints the Mac pack
commands with that same root, and removes only the mktemp folder.

On a Mac, `./lab/a6-a12-evidence-fix/mac-pack.sh` runs the three owner
journeys with the same isolated root.

`planted_bugs_are_caught` applies the plants under `plants/` and requires
each named test to print `FAILED`.

## NOT RUN on Linux

Resident instances and throwaway Homes need macOS. The commands set the
isolated temp root:

```sh
ELASTOS_TMP_ROOT="$ELASTOS_TMP_ROOT" ELASTOS_TMP_ISOLATION="$ELASTOS_TMP_ISOLATION" \
  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  two_instances_overlap_with_separate_grants -- --nocapture
ELASTOS_TMP_ROOT="$ELASTOS_TMP_ROOT" ELASTOS_TMP_ISOLATION="$ELASTOS_TMP_ISOLATION" \
  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  instance_grant_does_not_authorise_sibling -- --nocapture
ELASTOS_TMP_ROOT="$ELASTOS_TMP_ROOT" ELASTOS_TMP_ISOLATION="$ELASTOS_TMP_ISOLATION" \
  cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
  cleanup_census_refuses_each_leftover -- --nocapture
```

Those skips are not passes. A6 stays BLOCKED on RA-6. A12 owner census
of a real Runtime leftover after `run` is still the Mac remainder.
