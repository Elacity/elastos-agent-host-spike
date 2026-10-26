# A9 r2 fix (draft #290)

Lab only. Do not merge. Do not book A9.

```text
Slice:        A9 r2 fix (hard-link unlink, intermediate-dir TOCTOU, M-no-nofollow)
Branch / PR:  cursor/owned-storage-a9-9b7c  https://github.com/Elacity/elastos-agent-host-spike/pull/290
Parent:       2e5c37293279996fcb98ee2623381264f2d92e3f
```

The r2 review (draft #390) found two Store journeys that still let B see or receive A's bytes, and one surviving mutant. Those holes were in `lab/owned-storage`. Runtime store code was not patched. `lab/a9/RUNTIME-ASK.md` names the same class of hole in `LocalMutableStorage` for Anders.

## What changed

1. Hard-link then unlink A's name. The Store records `(st_dev, st_ino)` created through `write`. `read` / `write` refuse `st_nlink > 1` and refuse an inode owned by another agent. After `hard_link` + `unlink`, B's `read` and `write` return `Refuse::HardLink`. Journey: `agent_b_is_denied_a_hard_linked_inode_after_a_unlinks`. Plant: `F-A9-hardlink-unlink`.
2. Intermediate-directory TOCTOU. Every component is opened from the capsule root fd with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`, else per-component `openat` + `O_NOFOLLOW` (`O_DIRECTORY` on dirs) and `fstat`. No `create_dir_all` on a string path. 5000-iteration race: `intermediate_dir_swap_write_leaves_nothing_in_b`.
3. Last-component `O_NOFOLLOW`. `last_component_nofollow_is_required` fails when that flag is dropped. Plant: `F-A9-nofollow`. This is the old surviving mutant `M-no-nofollow`.

Runtime rows stay Blocked (`AC-006-STORAGE`, `executed=false`, `read_refusal=None`). Host same-uid walks stay `NEEDS CONFINEMENT/RUNTIME`.

## Tests

See the session message for exact command results (fmt, clippy, suite, plants, 8 r2 mutants, race counts).

## Principles

- 3 No ambient authority: Store IO stays on the grant's root fd.
- 11 Fail closed, then explain: a stolen inode and a symlink component stop with a reason.
- 12 Docs, code, tests agree: Runtime rows stay Blocked; RUNTIME-ASK is for Anders.
- 18 Isolated execution: lab directories are separate. The host process is not.

DeepSeek: none.
Runtime-ASK: yes, `lab/a9/RUNTIME-ASK.md`.
