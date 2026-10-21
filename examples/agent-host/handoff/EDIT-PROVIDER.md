# Edit provider: all-or-none multi-file write (design note only)

Written 21 Oct 2026. **Design only, no code.** It changes the Runtime's object provider, so it comes after 0.8.0,
and Anders decides whether and how to build it. It follows from OMP idea 1 (PR #24): the guest already builds the
request (`edit_request`) and records the reply (`note_change_wrote`).

## Decided (Sasha, 21 Oct)

- The edit provider lives **in the object provider**, not in its own capsule.
  - The object provider already owns revisions, so the revision rule stays in one place (PRINCIPLES 10).
  - A separate capsule would need write authority over every file it might edit, which is more authority (3, 5).
- From PR #24's questions: the third identical no-op edit is refused (`NOOP_EDIT_LIMIT = 2`), and a change touches
  at most 16 files (`CHANGE_FILES_LIMIT`). Raise the second only with evidence.

## The request the guest sends (from PR #24)

```json
{ "op": "edit", "all_or_none": true,
  "files": [ { "path": "localhost://Users/self/...", "if_revision": "<revision the guest read>",
               "first_line": 10, "line_count": 2, "old": "eleven", "new": "11" } ] }
```

- One request is one change.
- Every file has its own write grant. The Runtime checks each grant before the provider runs, as for any write.
- The reply names each file once, with its new revision: `{ "files": [ { "path": ..., "revision": ... } ] }`. This is
  the list `note_change_wrote` checks.

## What the code has today (at spike/agent-host f5396709c)

1. **Two revision formulas.**
   - Library objects: `rev:<sha256(plaintext)>` (`library.rs`, `library_object`).
   - Principal-root objects: `"<sha256(principal_id, 0, object_uri, 0, plaintext)>"`
     (`auth.rs`, `principal_root_object_revision`). The S3 journal bridge and viewer storage use this one.
   - One rule in one place means picking one. **Proposal:** the principal-root revision. It binds the principal and
     the object, and the S3 write path already checks it.
2. **Library's write checks `if_revision` outside the object lock.**
   - `write_library_file_bytes` calls `check_revision`, then `write_principal_root_object`. Each takes
     `principal_root_object_mutation_lock` separately.
   - A write that lands between the two is overwritten without a conflict.
   - The S3 path does both under one lock (`write_principal_root_object_if_revision`). The edit path must do the
     same. Whether Library's own write changes is a separate decision.
3. **One process-wide lock**, `principal_root_object_mutation_lock`. Reads (`read_principal_root_object`) take it too,
   so while a change holds it, no reader sees half a change.
4. **A tested pattern for many objects across a crash:** the protection migration (`auth.rs`, from
   `principal_root_migration_journal_path`).
   - It stages every object, writes a journal (Prepared, then Committing, then Committed) and keeps a backup.
   - Recovery rolls a Committing journal back from the backup before anything else runs.
   - Its tests inject a fault at every stage.

## Proposed algorithm (in the object provider)

Refuse before taking the lock:
- no files, more than 16 files, or a path twice;
- a path outside the caller's principal root;
- a path in `.AppData/Agents/` (journals only go through the bridge);
- a root without principal-root protection (`principal_root_protection_required`, as in S3).

Then, under `principal_root_object_mutation_lock`:

1. **Check every file first.**
   - Read and open the current object, and compute its revision. Any `if_revision` mismatch returns
     `revision_conflict` naming the file. Nothing is staged.
   - In memory, the lines `first_line .. first_line + line_count - 1` must hold `old` exactly once. Otherwise return
     `invalid_content` naming the file. Nothing is staged.
2. **Stage** the new encrypted bytes for every file in one stage directory, and fsync.
3. **Write an edit journal** (phase Prepared) listing each file, its old revision, the staged path, and a backup of
   the current bytes. Then set phase Committing.
4. **Commit:** rename each staged file over its target, and fsync the parent.
5. **Finish:** set phase Committed, return each file's new revision, then clean up.

Recovery, at start and before any read or write:
- a Prepared journal discards the stage;
- a Committing journal restores every backup (all old, none new);
- a Committed journal only cleans up.

So after any crash, either every file has its new revision or every file has its old one.

## Tests to write when it is built (each with a falsifier)

| Test | Falsifier |
| --- | --- |
| `a_stale_revision_on_any_file_writes_none` | check each file just before writing it |
| `old_text_outside_the_named_lines_writes_none` | search the whole file |
| `a_crash_at_every_stage_leaves_all_old_or_all_new` (faults as in the migration tests) | skip the restore |
| `a_change_naming_the_agents_area_is_refused` | drop the area check |
| `the_reply_names_each_file_once_with_its_new_revision` | reply with the old revision |
| `the_revision_check_and_the_write_hold_one_lock` | release the lock between them |

## Not decided (for Anders)

- Which revision formula wins (fact 1), and whether Library's own write moves the check inside the lock (fact 2).
- Whether the edit journal shares the migration journal's code or gets its own file.
- How the error codes reach the guest. PR #19 already maps `revision_conflict` and `invalid_content` to Invalid in
  `elastos-compute`.
